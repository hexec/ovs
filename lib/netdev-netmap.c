#include <config.h>

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/ioctl.h>

/* debug */
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
/* end debug */

#include "dpif.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "netmap.h"
#include "netdev-netmap.h"
#include "netmap-utils.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "packets.h"
#include "smap.h"

//#define DBG_THREAD
#define NMA_BLOCK_SIZE NETDEV_MAX_BURST * 2

VLOG_DEFINE_THIS_MODULE(netdev_netmap);

static struct vlog_rate_limit rl OVS_UNUSED = VLOG_RATE_LIMIT_INIT(5, 100);

struct netdev_netmap {
    struct netdev up;
    struct nm_desc *nmd;

    uint64_t timestamp;
    uint32_t rxsync_rate_usecs;

    struct ovs_mutex mutex OVS_ACQ_AFTER(netmap_mutex);
    struct netmap_spinlock tx_lock;

    struct netdev_stats stats;
    struct eth_addr hwaddr;
    enum netdev_flags flags;
    int mtu;

    int requested_mtu;

#ifdef DBG_THREAD /* debug info data */
    uint64_t nrx_calls, ntx_calls;
    uint64_t nrx_sync, ntx_sync;
    uint64_t nrx_packets, ntx_packets;
    pthread_t dbg_thread;
#endif
};

struct netdev_rxq_netmap {
    struct netdev_rxq up;
    struct nm_desc *nmd;
};

static struct ovs_mutex netmap_mutex = OVS_MUTEX_INITIALIZER;
static struct netmap_spinlock netmap_spinlock;

static void netdev_netmap_destruct(struct netdev *netdev);

static bool
is_netmap_class(const struct netdev_class *class)
{
    return class->destruct == netdev_netmap_destruct;
}

static struct netdev_netmap *
netdev_netmap_cast(const struct netdev *netdev)
{
    ovs_assert(is_netmap_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_netmap, up);
}

static struct netdev_rxq_netmap *
netdev_rxq_netmap_cast(const struct netdev_rxq *rx)
{
    ovs_assert(is_netmap_class(netdev_get_class(rx->netdev)));
    return CONTAINER_OF(rx, struct netdev_rxq_netmap, up);
}

static struct netdev *
netdev_netmap_alloc(void)
{
    struct netdev_netmap *dev;

    dev = (struct netdev_netmap *) xzalloc(sizeof *dev);
    if (dev) {
        return &dev->up;
    }

    return NULL;
}

struct nm_alloc_block {
    struct nm_alloc_block* next;           /* Blocks can be queued in a list. */
    struct dp_packet* packets[NMA_BLOCK_SIZE]; /* Block of dp_packet*. */
    uint16_t idx;                          /* Index of the buffer. */
};

struct nm_alloc_global {
    struct nm_alloc_block *block_heads[2];  /* Two lists for dp_packet* buffers
                                             one for empty and one for full. */
    void *mem;
    uint32_t memsize;
    uint16_t memid;
    uint32_t extrabufs;
    uint32_t count;
};

struct nm_alloc {
    struct nm_alloc_block *putb;      /* Buffer primarily used by rx to
                                         extract dp_packet*. */
    struct nm_alloc_block *getb;      /* Buffer primarily used by tx to
                                         insert dp_packet*. */
};

static struct nm_alloc_global nmg = { 0 };

DEFINE_STATIC_PER_THREAD_DATA(struct nm_alloc, nma, { 0 });
#define nma nma_get()

static inline struct nm_alloc_block*
nm_alloc_block_new_empty(void) {
    struct nm_alloc_block *block;

    block = xcalloc(1, sizeof(struct nm_alloc_block));

    return block;
}

static void
nm_alloc_block_free(struct nm_alloc_block* b) {
    if (b) {
        /* TODO clean extrabuffers */
        for (int i = 0; i < NMA_BLOCK_SIZE; i++) {
            if (b->packets[i]) {
                free(b->packets[i]);
            }
        }
        free(b);
    }
}

static inline void
nm_alloc_block_push(struct nm_alloc_block* b, bool is_full) {
    if (b) {
        b->next = nmg.block_heads[is_full];
        nmg.block_heads[is_full] = b;
    }
}

static inline struct nm_alloc_block*
nm_alloc_block_pop(bool want_full) {
    struct nm_alloc_block* b;

    b = nmg.block_heads[want_full];
    if (b) {
        nmg.block_heads[want_full] = b->next;
    }

    return b;
}

/* Swaps two dp_packets blocks from global and local allocator */
static inline void
nm_alloc_block_swap(bool want_full) {
    struct nm_alloc_block **bn = NULL;
    struct nm_alloc_block *bs = NULL, *tmp;

    netmap_spin_lock(&netmap_spinlock);

    bs = nm_alloc_block_pop(want_full);

    if (want_full) {
        bn = (nma->getb->idx)? &nma->getb : &nma->putb;
    } else if (!bs) {
        bn = &nma->putb;
        bs = nm_alloc_block_new_empty();
    }

    if (OVS_LIKELY(bs)) {
        tmp = *bn;
        *bn = bs;
        nm_alloc_block_push(tmp, !want_full);
    }

    netmap_spin_unlock(&netmap_spinlock);
}

static inline void
nm_alloc_block_exchange(void) {
    struct nm_alloc_block* block;

    if (nma->getb->idx < nma->putb->idx) {
        block = nma->getb;
        nma->getb = nma->putb;
        nma->putb = block;
    }
}

void
nm_init(int extrabufs) {
    VLOG_WARN("netmap_alloc: init global");
    netmap_calibrate_tsc();
    netmap_spin_create(&netmap_spinlock);
    nmg.extrabufs = extrabufs;
}

static int
nm_alloc_global_init(struct nm_desc *nmd) {
    struct nm_alloc_block *block = NULL;
    struct dp_packet* packet;

    netmap_spin_lock(&netmap_spinlock);

    VLOG_WARN("nm_alloc_global: init_port");

    if (nmg.count) {
        if (nmg.memid != nmd->req.nr_arg2) {
            VLOG_WARN("differnt memid: %x %x", nmg.memid, nmd->req.nr_arg2);
            netmap_spin_unlock(&netmap_spinlock);
            return 1;
        }
        VLOG_INFO("reusing previously mmapped netmap memory");
    } else {
        /* Opening the first port. we have to setup netmap memory */
        VLOG_INFO("allocating netmap memory");
        nmg.memid = nmd->req.nr_arg2;
        nmg.memsize = nmd->req.nr_memsize;
        nmg.mem = mmap(0, nmg.memsize, PROT_WRITE | PROT_READ,
                        MAP_SHARED, nmd->fd, 0);

        if (nmg.mem == MAP_FAILED) {
            VLOG_INFO("mmap failed!");
            netmap_spin_unlock(&netmap_spinlock);
            return 1;
        }
    }

    nmg.count++;
    nmd->memsize = nmg.memsize;
    nmd->mem = nmg.mem;

    struct netmap_if *nifp = NETMAP_IF(nmg.mem, nmd->req.nr_offset);
    struct netmap_ring *r = NETMAP_RXRING(nifp, nmd->first_rx_ring);
    if ((void *)r == (void *)nifp) {
        /* the descriptor is open for TX only */
        r = NETMAP_TXRING(nifp, nmd->first_tx_ring);
    }

    *(struct netmap_if **)(uintptr_t)&(nmd->nifp) = nifp;
    *(struct netmap_ring **)(uintptr_t)&nmd->some_ring = r;
    *(void **)(uintptr_t)&nmd->buf_start = NETMAP_BUF(r, 0);
    *(void **)(uintptr_t)&nmd->buf_end = (char *)nmd->mem + nmd->memsize;

    struct netmap_ring *ring = NETMAP_RXRING(nmd->nifp, 0);
    for (uint32_t idx = nmd->nifp->ni_bufs_head; idx ;
            idx = *(uint32_t *)NETMAP_BUF(ring, idx)) {
        if (!block) {
            block = nm_alloc_block_new_empty();
        }

        packet = dp_packet_new(0);
        packet->buf_idx = idx;
        block->packets[block->idx++] = packet;

        if (block->idx == NMA_BLOCK_SIZE) {
            nm_alloc_block_push(block, true);
            block = NULL;
        }
    }

    if (block != NULL) {
        nm_alloc_block_push(block, true);
    }

    nm_alloc_block_push(block, false);

    VLOG_WARN("nm_alloc_global: done");
    netmap_spin_unlock(&netmap_spinlock);

    return 0;
}

/* This function has to be called in the pmd thread */
void
nm_alloc_init(void) {
    netmap_spin_lock(&netmap_spinlock);
    nma->getb = nm_alloc_block_pop(true);
    if (!nma->getb) {
        nma->getb = nm_alloc_block_new_empty();
    }
    netmap_spin_unlock(&netmap_spinlock);
    nma->putb = nm_alloc_block_new_empty();

    VLOG_INFO("local allocator block getb:%d", nma->getb->idx);
    VLOG_INFO("local allocator block putb:%d", nma->putb->idx);
}

static void
nm_alloc_close(void) {
    bool done = false;

    netmap_spin_lock(&netmap_spinlock);

    if (!nmg.count && nmg.mem) {
        VLOG_INFO("unmapping netmap memory");
        munmap(nmg.mem, nmg.memsize);
        nmg.mem = NULL;
        nmg.memsize = 0;
    }

/*
    struct nm_alloc_block* b;
    while (nmg.block_heads[0]) {
        b = nm_alloc_block_pop(false);
        nmg.block_heads[0] = b->next;
        nm_alloc_block_free(b);
    }
    while (nmg.block_heads[1]) {
        b = nm_alloc_block_pop(true);
        nmg.block_heads[1] = b->next;
        nm_alloc_block_free(b);
    }
*/
    done = true;
    netmap_spin_unlock(&netmap_spinlock);
    /*if (done) {
        netmap_spin_destroy(&netmap_spinlock);
    }*/
}

void
nm_free_packet(struct dp_packet* packet) {
    struct nm_alloc_block* block = nma->putb;

    if (OVS_UNLIKELY(block->idx == (NMA_BLOCK_SIZE - 1))) {
        block = nma->getb;
        if (OVS_UNLIKELY(block->idx == (NMA_BLOCK_SIZE - 1))) {
            nm_alloc_block_swap(false);
            block = nma->putb;
        }
    }

    block->packets[block->idx++] = packet;
}

/*
static inline void
nm_free_packets(struct dp_packet_batch* b) {
    struct nm_alloc_block* block;
    size_t step, tot = 0, s, n = b->count;

    for (step = 0; step < 3; step++) {
        block = nma->putb;
        s = MIN(n, NMA_BLOCK_SIZE - block->idx);
        memcpy(&block->packets[block->idx], &b->packets[tot],
                s * sizeof(struct dp_packet*));
        block->idx += s;
        tot += s;
        n -= s;

        if (n == 0) {
            break;
        } else if (OVS_LIKELY(step == 0)) {
            nm_alloc_block_exchange();
        } else {
            nm_alloc_block_swap(false);
        }
    }

    dp_packet_batch_init(b);
}
*/

static inline int
nm_alloc_packets(struct dp_packet_batch* b, size_t n) {
    struct nm_alloc_block* block;
    size_t step, tot = 0, s;

    for (step = 0; step < 3; step++) {
        block = nma->getb;
        s = MIN(n, block->idx);
        memcpy(&b->packets[tot], &block->packets[block->idx - s],
                s * sizeof(struct dp_packet*));
        block->idx -= s;
        tot += s;
        n -= s;

        if (n == 0) {
            break;
        } else if (OVS_LIKELY(step == 0)) {
            nm_alloc_block_exchange();
        } else {
            nm_alloc_block_swap(true);
        }
    }

    return tot;
}

#ifdef DBG_THREAD
static void*
debug_thread(void *ptr)
{
    const struct netdev *netdev = (struct netdev *) ptr;
    const struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    struct timespec start, stop;
    bool running = true;
    FILE *ff;
    char fname[100], buffer[1024];
    int sleeptime = 5;
    useconds_t usleeptime = sleeptime * 1e6;
    clockid_t clkid = CLOCK_REALTIME;

    uint64_t nrx_calls, ntx_calls;
    uint64_t nrx_sync, ntx_sync;
    uint64_t nrx_packets, ntx_packets;

    uint64_t p_nrx_calls = 0, p_ntx_calls = 0;
    uint64_t p_nrx_sync = 0, p_ntx_sync = 0;
    uint64_t p_nrx_packets = 0, p_ntx_packets = 0;

    clock_gettime(clkid, &start);
    snprintf(fname, 100, "/tmp/%s-%s.log",
            netdev_get_type(netdev), netdev_get_name(netdev));
    ff = fopen(fname, "w");

    while (running) {
        double timediff, rx, tx, ntx, nrx, rxs = 0, txs = 0, txb = 0, rxb = 0;
        uint64_t dtxc, drxc, dtxs, drxs, dtxp, drxp;

        usleep(usleeptime);

        clock_gettime(clkid, &stop);
        timediff = (stop.tv_sec - start.tv_sec) +
                    (stop.tv_nsec - start.tv_nsec) / 1e9;
        if (timediff < 1)
            continue;

        /* snapshot */
        nrx_calls = dev->nrx_calls;
        ntx_calls = dev->ntx_calls;
        nrx_sync = dev->nrx_sync;
        ntx_sync = dev->ntx_sync;
        nrx_packets = dev->nrx_packets;
        ntx_packets = dev->ntx_packets;

        dtxp = ntx_packets - p_ntx_packets;
        drxp = nrx_packets - p_nrx_packets;
        dtxc = ntx_calls - p_ntx_calls;
        drxc = nrx_calls - p_nrx_calls;
        dtxs = ntx_sync - p_ntx_sync;
        drxs = nrx_sync - p_nrx_sync;

        rx = drxp / (1e6 * sleeptime);
        tx = dtxp / (1e6 * sleeptime);
        nrx = drxc / sleeptime;
        ntx = dtxc / sleeptime;

        if (dtxc) {
            txb = (double) dtxp / (double) dtxc;
            txs = (double) dtxs / (double) dtxc;
        }

        if (drxc) {
            rxb = (double) drxp / (double) drxc;
            rxs = (double) drxs / (double) drxc;
        }

        snprintf(buffer, 1024, "%s-%.1fs tid(%d) :\ntx[ %.1fMpps calls:%.2fM sync:%.1f%% batch:%.1f ]\nrx[ %.1fMpps calls:%.2fM sync:%.1f%% batch:%.1f ]\n",
                 netdev_get_name(netdev), timediff, (int) syscall(SYS_gettid),
                 tx, ntx / 1e6, txs * 100, txb,
                 rx, nrx / 1e6, rxs * 100, rxb);
        fwrite(buffer, strlen(buffer), sizeof(char), ff);

        fflush(ff);

        p_nrx_calls = nrx_calls;
        p_ntx_calls = ntx_calls;
        p_nrx_sync = nrx_sync;
        p_ntx_sync = ntx_sync;
        p_nrx_packets = nrx_packets;
        p_ntx_packets = ntx_packets;
    }

    fclose(ff);
    return NULL;
}
#endif

static int
netdev_netmap_construct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    const char *ifname = netdev_get_name(netdev);

    VLOG_INFO("construct: \"%s\"", ifname);

    struct nmreq req;
    memset(&req, 0 , sizeof(req));
    req.nr_arg3 = nmg.extrabufs;

    dev->nmd = nm_open(ifname, &req, NM_OPEN_NO_MMAP, NULL);

    if (!dev->nmd) {
        if (!errno) {
            VLOG_WARN("opening port \"%s\" failed: not a netmap port", ifname);
        } else {
            VLOG_WARN("opening port \"%s\" failed: %s", ifname,
                ovs_strerror(errno));
        }
        return EINVAL;
    } else {
        VLOG_INFO("opening port \"%s\"", ifname);
    }

    VLOG_WARN("\"%s\": requested %d extra buffers, got %d.",
            ifname, nmg.extrabufs, dev->nmd->req.nr_arg3);

    /* Check how many extra buffers we have got. */
    if (dev->nmd->req.nr_arg3 < NETDEV_MAX_BURST) {
        VLOG_WARN("not enough extra buffers, closing port");
        nm_close(dev->nmd);
        return EINVAL;
    }

    /* We will now lookup or build the netmap's global allocator.
     * Every dp-packet is associated with a netmap buffer that is not
     * currently contained in a TX/RX ring. */
    if (nm_alloc_global_init(dev->nmd)) {
        VLOG_WARN("could not allocate netmap memory");
        nm_close(dev->nmd);
        return EINVAL;
    }

    ovs_mutex_init(&dev->mutex);
    netmap_spin_create(&dev->tx_lock);
    eth_addr_random(&dev->hwaddr);
    dev->flags = NETDEV_UP | NETDEV_PROMISC;
    dev->timestamp = rdtsc();
    dev->rxsync_rate_usecs = 10;
    dev->requested_mtu = NETMAP_RXRING(dev->nmd->nifp, 0)->nr_buf_size;
    netdev_request_reconfigure(netdev);

#ifdef DBG_THREAD /* debug */
    dev->nrx_sync = dev->ntx_sync = 0;
    dev->nrx_calls = dev->ntx_calls = 0;
    dev->nrx_packets = dev->ntx_packets = 0;
    if (pthread_create(&(dev->dbg_thread), NULL, debug_thread, netdev)) {
        VLOG_DEBUG("error starting debug thread");
    }
#endif

    return 0;
}

static void
netdev_netmap_destruct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

#ifdef DBG_THREAD
    pthread_cancel(dev->dbg_thread);
#endif

    nm_close(dev->nmd);
}

static void
netdev_netmap_dealloc(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_destroy(&dev->mutex);
    netmap_spin_destroy(&dev->tx_lock);

    nm_alloc_close();

    free(dev);
}

static struct netdev_rxq *
netdev_netmap_rxq_alloc(void)
{
    struct netdev_rxq_netmap *rx = xzalloc(sizeof *rx);
    return &rx->up;
}

static int
netdev_netmap_rxq_construct(struct netdev_rxq *rxq)
{
    struct netdev_rxq_netmap *rx = netdev_rxq_netmap_cast(rxq);
    struct netdev *netdev = rx->up.netdev;
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);
    rx->nmd = dev->nmd;
    ovs_mutex_unlock(&dev->mutex);
    VLOG_INFO("netmap_rxq_construct : done");
    return err;
}

static void
netdev_netmap_rxq_destruct(struct netdev_rxq *rxq OVS_UNUSED)
{
    /* struct netdev_rxq_netmap *rx = netdev_rxq_netmap_cast(rxq); */
}

static void
netdev_netmap_rxq_dealloc(struct netdev_rxq *rxq)
{
    struct netdev_rxq_netmap *rx = netdev_rxq_netmap_cast(rxq);
    free(rx);
}

static int
netdev_netmap_class_init(void)
{
    /* Nothing to do for now, but we keep the same code structure
     * used by DPDK. */
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovsthread_once_done(&once);
    }

    return 0;
}

static int
netdev_netmap_reconfigure(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);

    if (dev->mtu == dev->requested_mtu) {
        /* Reconfiguration is unnecessary */
        goto out;
    }

    dev->mtu = dev->requested_mtu;
    netdev_change_seq_changed(netdev);

out:
    ovs_mutex_unlock(&dev->mutex);
    return err;
}

static int
netdev_netmap_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    smap_add_format(args, "mtu", "%d", dev->mtu);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_set_config(struct netdev *netdev, const struct smap *args,
                         char **errp OVS_UNUSED)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&netmap_mutex);
    ovs_mutex_lock(&dev->mutex);
    dev->rxsync_rate_usecs = smap_get_int(args, "rxsync-rate-usecs", 10);
    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&netmap_mutex);

    return 0;
}

static inline void
netmap_txsync(struct netdev_netmap *dev)
{
    ioctl(dev->nmd->fd, NIOCTXSYNC, NULL);
#ifdef DBG_THREAD
    dev->ntx_sync++;
#endif
}

static inline void
netmap_rxsync(struct netdev_netmap *dev)
{
    uint64_t now = rdtsc();
    unsigned int diff = TSC2US(now - dev->timestamp);

    /* rxsync rate is too high */
    if (diff < dev->rxsync_rate_usecs) {
        return;
    }

    ioctl(dev->nmd->fd, NIOCRXSYNC, NULL);

    /* update current timestamp */
    dev->timestamp = now;

#ifdef DBG_THREAD
    dev->nrx_sync++;
#endif
}

static inline void
netmap_swap_slot(struct dp_packet *packet, struct netmap_slot *s) {
    uint32_t idx;

    idx = s->buf_idx;
    s->buf_idx = packet->buf_idx;
    s->flags |= NS_BUF_CHANGED;
    packet->buf_idx = idx;
}

static int
netdev_netmap_send(struct netdev *netdev, int qid OVS_UNUSED,
                     struct dp_packet_batch *batch, bool concurrent_txq)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    struct nm_desc *nmd = dev->nmd;
    uint16_t r, nrings = dev->nmd->nifp->ni_tx_rings;
    uint32_t budget = batch->count, count = 0;
    bool again = false;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        dp_packet_delete_batch(batch, true);
        return 0;
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        netmap_spin_lock(&dev->tx_lock);
    }

try_again:
    for (r = 0; r < nrings; r++) {
        struct netmap_ring *ring;
        uint32_t head, space;

        ring = NETMAP_TXRING(nmd->nifp, nmd->cur_tx_ring);
        space = nm_ring_space(ring); /* Available slots in this ring. */
        head = ring->head;

        if (space > budget) {
            space = budget;
        }
        budget -= space;

        /* Transmit batch in this ring as much as possible. */
        while (space--) {
            struct netmap_slot *ts = &ring->slot[head];
            struct dp_packet *packet = batch->packets[count++];

            ts->len = dp_packet_get_send_len(packet);

            if (OVS_UNLIKELY(packet->source != DPBUF_NETMAP)) {
                /* send packet copying data to the netmap slot */
                memcpy(NETMAP_BUF(ring, ts->buf_idx),
                        dp_packet_data(packet), ts->len);
            } else {
                /* send packet using zerocopy */
                netmap_swap_slot(packet, ts);
            }

            head = nm_ring_next(ring, head);
        }

        ring->head = ring->cur = head;

        /* We may have exhausted the budget */
        if (OVS_LIKELY(!budget)) {
            break;
        }

        /* We still have packets to send, select next ring. */
        if (OVS_UNLIKELY(++dev->nmd->cur_tx_ring == nrings)) {
            nmd->cur_tx_ring = 0;
        }
    }

    netmap_txsync(dev);

    if (OVS_UNLIKELY(!count && !again)) {
        again = true;
        goto try_again;
    }

    dp_packet_delete_batch(batch, true);

#ifdef DBG_THREAD
        dev->ntx_calls++;
        dev->ntx_packets+=count;
#endif

    if (OVS_UNLIKELY(concurrent_txq)) {
        netmap_spin_unlock(&dev->tx_lock);
    }

    return 0;
}

static void
netdev_netmap_send_wait(struct netdev *netdev OVS_UNUSED, int qid OVS_UNUSED)
{
    poll_immediate_wake();
}

static int
netdev_netmap_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch)
{
    struct netdev_netmap *dev = netdev_netmap_cast(rxq->netdev);
    struct nm_desc *nmd = dev->nmd;
    uint16_t r, nrings = nmd->nifp->ni_rx_rings;
    uint32_t budget = 0;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        return EAGAIN;
    }

    for (r = nmd->first_rx_ring; r < nrings; r++) {
        budget += nm_ring_space(NETMAP_RXRING(nmd->nifp, r));
    }

    if (budget == 0) {
        netmap_rxsync(dev);
        return EAGAIN;
    }

    budget = nm_alloc_packets(batch, MIN(budget, NETDEV_MAX_BURST));

    for (r = 0; r < nrings; r++) {
        struct netmap_ring *ring;
        uint32_t head, space;

        ring = NETMAP_RXRING(nmd->nifp, nmd->cur_rx_ring);
        head = ring->head;
        space = nm_ring_space(ring);
        if (space > budget) {
            space = budget;
        }
        budget -= space;

        while (space--) {
            struct netmap_slot *rs = &ring->slot[head];
            struct dp_packet *packet = batch->packets[batch->count++];
            dp_packet_init_netmap(packet, NETMAP_BUF(ring, rs->buf_idx),
                                    rs->len);
            netmap_swap_slot(packet, rs);
            head = nm_ring_next(ring, head);
        }

        ring->cur = ring->head = head;

        if (!budget) {
            break;
        }

        if (OVS_UNLIKELY(++nmd->cur_rx_ring == nrings)) {
            nmd->cur_rx_ring = 0;
        }
    }

#ifdef DBG_THREAD
    dev->nrx_packets += batch->count;
    dev->nrx_calls++;
#endif

    dp_packet_batch_init_packet_fields(batch);

    return 0;
}

static void
netdev_netmap_rxq_wait(struct netdev_rxq *rxq)
{
    struct netdev_rxq_netmap *rx = netdev_rxq_netmap_cast(rxq);
    poll_fd_wait(rx->nmd->fd, POLLIN);
}

static int
netdev_netmap_get_ifindex(const struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    /* Calculate hash from the netdev name. Ensure that ifindex is a 24-bit
     * postive integer to meet RFC 2863 recommendations.
     */
    int ifindex = hash_string(netdev->name, 0) % 0xfffffe + 1;
    ovs_mutex_unlock(&dev->mutex);

    return ifindex;
}

static int
netdev_netmap_get_mtu(const struct netdev *netdev, int *mtu)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mtu = dev->mtu;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_set_mtu(struct netdev *netdev, int mtu)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    if (mtu > NETMAP_RXRING(dev->nmd->nifp, 0)->nr_buf_size
        || mtu < ETH_HEADER_LEN) {
        VLOG_WARN("%s: unsupported MTU %d\n", dev->up.name, mtu);
        return EINVAL;
    }

    ovs_mutex_lock(&dev->mutex);
    if (dev->requested_mtu != mtu) {
        dev->requested_mtu = mtu;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    dev->hwaddr = mac;
    netdev_change_seq_changed(netdev);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mac = dev->hwaddr;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_update_flags(struct netdev *netdev,
                          enum netdev_flags off, enum netdev_flags on,
                          enum netdev_flags *old_flagsp)
    OVS_REQUIRES(dev->mutex)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    /*if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }*/

    *old_flagsp = dev->flags;
    dev->flags |= on;
    dev->flags &= ~off;

    //netdev_change_seq_changed(&dev->up);

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_get_carrier(const struct netdev *netdev, bool *carrier)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *carrier = true;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    stats->tx_packets = dev->stats.tx_packets;
    stats->tx_bytes = dev->stats.tx_bytes;
    stats->rx_packets = dev->stats.rx_packets;
    stats->rx_bytes = dev->stats.rx_bytes;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_get_status(const struct netdev *netdev, struct smap *args)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    smap_add_format(args, "mtu", "%d", dev->mtu);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

#define NETDEV_NETMAP_CLASS(NAME, PMD, INIT, CONSTRUCT, DESTRUCT, SET_CONFIG, \
        SET_TX_MULTIQ, SEND, SEND_WAIT, GET_CARRIER, GET_STATS, GET_FEATURES, \
        GET_STATUS, RECONFIGURE, RXQ_RECV, RXQ_WAIT)        \
{                                                           \
    NAME,                                                   \
    PMD,                        /* is_pmd */                \
    INIT,                       /* init */                  \
    NULL,                       /* netdev_netmap_run */     \
    NULL,                       /* netdev_netmap_wait */    \
    netdev_netmap_alloc,                                    \
    CONSTRUCT,                                              \
    DESTRUCT,                                               \
    netdev_netmap_dealloc,                                  \
    netdev_netmap_get_config,                               \
    SET_CONFIG,                                             \
    NULL,                       /* get_tunnel_config */     \
    NULL,                       /* build header */          \
    NULL,                       /* push header */           \
    NULL,                       /* pop header */            \
    NULL,                       /* get numa id */           \
    SET_TX_MULTIQ,              /* tx multiq */             \
    SEND,                       /* send */                  \
    SEND_WAIT,                                              \
    netdev_netmap_set_etheraddr,                            \
    netdev_netmap_get_etheraddr,                            \
    netdev_netmap_get_mtu,                                  \
    netdev_netmap_set_mtu,                                  \
    netdev_netmap_get_ifindex,                              \
    GET_CARRIER,                                            \
    NULL,                       /* get_carrier_resets */    \
    NULL,                       /* get_miimon */            \
    GET_STATS,                                              \
    NULL,                       /* get_custom_stats */      \
                                                            \
    NULL,                       /* get_features */          \
    NULL,                       /* set_advertisements */    \
    NULL,                       /* get_pt_mode */           \
                                                            \
    NULL,                       /* set_policing */          \
    NULL,                       /* get_qos_types */         \
    NULL,                       /* get_qos_capabilities */  \
    NULL,                       /* get_qos */               \
    NULL,                       /* set_qos */               \
    NULL,                       /* get_queue */             \
    NULL,                       /* set_queue */             \
    NULL,                       /* delete_queue */          \
    NULL,                       /* get_queue_stats */       \
    NULL,                       /* queue_dump_start */      \
    NULL,                       /* queue_dump_next */       \
    NULL,                       /* queue_dump_done */       \
    NULL,                       /* dump_queue_stats */      \
                                                            \
    NULL,                       /* set_in4 */               \
    NULL,                       /* get_addr_list */         \
    NULL,                       /* add_router */            \
    NULL,                       /* get_next_hop */          \
    GET_STATUS,                                             \
    NULL,                       /* arp_lookup */            \
                                                            \
    netdev_netmap_update_flags,                             \
    RECONFIGURE,                                            \
                                                            \
    netdev_netmap_rxq_alloc,                                \
    netdev_netmap_rxq_construct,                            \
    netdev_netmap_rxq_destruct,                             \
    netdev_netmap_rxq_dealloc,                              \
    RXQ_RECV,                                               \
    RXQ_WAIT,                                               \
    NULL,                       /* rxq_drain */             \
    NO_OFFLOAD_API                                          \
}

static const struct netdev_class netmap_class =
    NETDEV_NETMAP_CLASS(
        "netmap",
        false,
        netdev_netmap_class_init,
        netdev_netmap_construct,
        netdev_netmap_destruct,
        netdev_netmap_set_config,
        NULL,
        netdev_netmap_send,
        netdev_netmap_send_wait,
        netdev_netmap_get_carrier,
        netdev_netmap_get_stats,
        NULL,
        netdev_netmap_get_status,
        netdev_netmap_reconfigure,
        netdev_netmap_rxq_recv,
        netdev_netmap_rxq_wait);

static const struct netdev_class netmap_class_pmd =
    NETDEV_NETMAP_CLASS(
        "netmap-pmd",
        true,
        netdev_netmap_class_init,
        netdev_netmap_construct,
        netdev_netmap_destruct,
        netdev_netmap_set_config,
        NULL,
        netdev_netmap_send,
        NULL,
        netdev_netmap_get_carrier,
        netdev_netmap_get_stats,
        NULL,
        netdev_netmap_get_status,
        netdev_netmap_reconfigure,
        netdev_netmap_rxq_recv,
        NULL);

void
netdev_netmap_register(void)
{
    netdev_register_provider(&netmap_class);
    netdev_register_provider(&netmap_class_pmd);
}
