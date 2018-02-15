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
#include "packets.h"
#include "smap.h"

#define DEBUGTHREAD
#define DEFAULT_RXQ_SIZE 2048
#define DEFAULT_TXQ_SIZE 2048
#define NR_QUEUE 1

#define NM_ALLOC_RING_SIZE 128
#define NM_ALLOC_RINGS_INIT 16

VLOG_DEFINE_THIS_MODULE(netdev_netmap);

static struct vlog_rate_limit rl OVS_UNUSED = VLOG_RATE_LIMIT_INIT(5, 100);

struct netdev_netmap {
    struct netdev up;
    struct nm_desc *nmd;
    struct nm_alloc_ring* nmr;
    struct nm_alloc_ring* nmr_b;
    struct nm_info nmi;

    uint32_t rxsync_rate_usecs;
    uint64_t timestamp;
    //uint32_t foundempty;

#ifdef DEBUGTHREAD /* debug info data */
    uint64_t nrx_calls, ntx_calls;
    uint64_t nrx_sync, ntx_sync;
    uint64_t nrx_packets, ntx_packets;
    pthread_t dbg_thread;
#endif

    struct ovs_mutex mutex OVS_ACQ_AFTER(netmap_mutex);

    int mtu;

    struct netdev_stats stats;
    struct eth_addr hwaddr;
    enum netdev_flags flags;

    int requested_mtu;
    /*
    int n_txq;
    int n_rxq;
    int rxq_size;
    int txq_size;

    int requested_n_txq;
    int requested_n_rxq;
    int requested_rxq_size;
    int requested_txq_size;
    */
    };

struct netdev_rxq_netmap {
    struct netdev_rxq up;
    struct nm_desc *nmd;
};

struct nm_alloc_ring {
    struct dp_packet* ring[NM_ALLOC_RING_SIZE];
    struct nm_alloc_ring* next;
    uint16_t head;
    uint16_t tail;
};

struct nm_alloc {
    struct nm_alloc_ring* rlist;
    struct nm_alloc_ring* rlist_b;
    uint16_t nrings;
    /* possible locks */
};

static struct nm_alloc nma = {
    NULL,
    NULL,
    0
};

static struct ovs_mutex netmap_mutex = OVS_MUTEX_INITIALIZER;

static struct netmap_spinlock_t spinlock;

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
    if (dev)
        return &dev->up;

    return NULL;
}

static struct nm_alloc_ring*
nm_alloc_ring_new(bool fill) {
    struct nm_alloc_ring* r;

    r = (struct nm_alloc_ring*)
       xmalloc(sizeof(struct nm_alloc_ring));
    nma.nrings++;

    if (fill) {
        r->head = 0;
        r->tail = NM_ALLOC_RING_SIZE - 1;
        r->next = NULL;

        for (int i = 0; i < NM_ALLOC_RING_SIZE - 1; i++)
            r->ring[i] = dp_packet_new(0);

        r->ring[NM_ALLOC_RING_SIZE - 1] = NULL;
    } else {
        memset(r, 0, sizeof(struct nm_alloc_ring));
    }

    return r;
}

static inline void
nm_alloc_ring_free(struct nm_alloc_ring* r) {
    if (r) {
        nma.nrings--;
        for (int i = 0; i < NM_ALLOC_RING_SIZE; i++) {
            if (r->ring[i])
                free(r->ring[i]);
        }
        free(r);
    }
}

static inline void
nm_alloc_ring_push(struct nm_alloc_ring* r) {
    if (r) {
        r->next = nma.rlist;
        nma.rlist = r;
    }
}

static struct nm_alloc_ring*
nm_alloc_ring_pop(void) {
    struct nm_alloc_ring* r = nma.rlist;

    if (r)
        nma.rlist = r->next;
    else
        r = nm_alloc_ring_new(true);

    return r;
}

/* Swaps two dp_packet rings from the global allocator */
static inline struct nm_alloc_ring*
nm_alloc_ring_swap(struct nm_alloc_ring* r) {
    if (r) {
        struct nm_alloc_ring* rnew;
        rnew = nm_alloc_ring_pop();
        nm_alloc_ring_push(r);
        return rnew;
    }
    return r;
}

/* Returns the number of dp_packets that you can pop out */
static inline uint16_t
nm_alloc_ring_available(struct nm_alloc_ring* nmr) {
    int16_t space = nmr->tail - nmr->head;

    if (space < 0)
        space += NM_ALLOC_RING_SIZE;

    return space;
}

/* Returns the number of dp_packets that you can push in */
static inline uint16_t
nm_alloc_ring_empty(struct nm_alloc_ring* nmr) {
    int16_t space = nmr->head - nmr->tail;

    if (space < 0)
        space += NM_ALLOC_RING_SIZE;

    return space;
}

static inline bool
nm_alloc_ring_is_empty(struct nm_alloc_ring* nmr) {
    return nm_alloc_ring_empty(nmr) == 0;
}

static inline bool
nm_alloc_ring_is_full(struct nm_alloc_ring* nmr) {
    return nm_alloc_ring_available(nmr) == NM_ALLOC_RING_SIZE;
}

static inline uint16_t
nm_alloc_ring_next(uint16_t i, uint16_t n) {
    uint16_t sum = i + n;

    if (OVS_UNLIKELY(sum >= NM_ALLOC_RING_SIZE))
        sum-=NM_ALLOC_RING_SIZE;

    return sum;
}

static void
nm_alloc_init(void) {
    struct nm_alloc_ring* r;
    uint16_t count = NM_ALLOC_RINGS_INIT;

    if (!nma.nrings)
        while (count--) {
            r = nm_alloc_ring_new(true);
            nm_alloc_ring_push(r);
        }
}

static void
nm_alloc_free_all(void) {
    struct nm_alloc_ring* r;

    while (nma.rlist) {
        r = nm_alloc_ring_pop();
        nma.rlist = r->next;
        nm_alloc_ring_free(r);
    }
}

void
nm_alloc_free(struct nm_alloc_ring* nmr, struct dp_packet* packet) {
    uint16_t space = nm_alloc_ring_empty(nmr);
    if (space) {
        nmr->ring[nmr->tail] = packet;
        nmr->tail = nm_alloc_ring_next(nmr->tail, 1);
    } else {
        /* push to backup ring, if full swap with empty one */
    }
    VLOG_INFO("nm_alloc_free: %x tail: %d", packet, nmr->tail);
}

/*
static inline int
nm_alloc_prepare_batch(struct nm_alloc_ring* nmr, struct dp_packet_batch* b, uint8_t n) {
    int16_t head;

    n = MIN(n, nm_alloc_ring_available(nmr));

    head = nmr->head;
    for (int i = 0; i < n; i++) {
        b->packets[b->count + i] = nmr->ring[head];
        head = OVS_LIKELY(head < (NM_ALLOC_RING_SIZE - 1))? head + 1 : 0;
    }
    nmr->head = head;

    return n;
}
*/

static inline int
nm_alloc_prepare_batch(struct nm_alloc_ring* nmr, struct dp_packet_batch* b, uint8_t n) {
    int16_t overflow;

    n = MIN(n, nm_alloc_ring_available(nmr));

    if (!n)
        return 0;

    overflow = nmr->head + n - NM_ALLOC_RING_SIZE + 1;

    if (overflow <= 0) {
        //VLOG_INFO("overflow:%d nb:%dB | n:%d", overflow, nb, n);
        memcpy(&b->packets[b->count], &nmr->ring[nmr->head], n * sizeof(struct dp_packet*));
    } else {
        int16_t cut = n - overflow;
        //VLOG_INFO("overflow:%dB nb:%dB -> (cut:%d) | n:%d", overflow, nb, cut, n);
        memcpy(&b->packets[b->count], &nmr->ring[nmr->head], cut * sizeof(struct dp_packet*));
        memcpy(&b->packets[b->count + cut], &nmr->ring[0], overflow * sizeof(struct dp_packet*));
    }

    nmr->head = nm_alloc_ring_next(nmr->head, n);

    return n;
}

#ifdef DEBUGTHREAD
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
    snprintf(fname, 100, "/tmp/%s-%s.log", netdev_get_type(netdev), netdev_get_name(netdev));
    ff = fopen(fname, "w");

    while (running) {
        double timediff, rx, tx, ntx, nrx, rxs = 0, txs = 0, txb = 0, rxb = 0;
        uint64_t dtxc, drxc, dtxs, drxs, dtxp, drxp;

        usleep(usleeptime);

        clock_gettime(clkid, &stop);
        timediff = (stop.tv_sec - start.tv_sec) + (stop.tv_nsec - start.tv_nsec) / 1e9;
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

    if (access("/dev/netmap", F_OK) == -1) {
        VLOG_WARN("/dev/netmap not found, module is not loaded.");
    }

    ovs_mutex_init(&dev->mutex);
    netmap_spin_create(&spinlock);

    eth_addr_random(&dev->hwaddr);

    dev->flags = NETDEV_UP | NETDEV_PROMISC;

    //netdev->n_rxq = 0;
    //netdev->n_txq = 0;
    //dev->requested_n_rxq = NR_QUEUE;
    //dev->requested_n_txq = NR_QUEUE;
    //dev->requested_rxq_size = DEFAULT_RXQ_SIZE;
    //dev->requested_txq_size = DEFAULT_TXQ_SIZE;

    VLOG_INFO("tsc ticks_per_second : %" PRIu64 "", ticks_per_second);
    dev->timestamp = rdtsc();
    dev->rxsync_rate_usecs = 10;
    /* dev->foundempty = 0; */

    //nm_alloc_init();
    dev->nmr = nm_alloc_ring_new(true); //pop();

    const char *ifname = netdev_get_name(netdev);
    dev->nmd = nm_open(ifname, NULL, 0, NULL);
    if (!dev->nmd) {
        if (!errno)
            VLOG_WARN("opening \"%s\" failed: not a netmap port", ifname);
        else
            VLOG_WARN("opening \"%s\" failed: %s", ifname,
                  ovs_strerror(errno));
        return EINVAL;
    } else
        VLOG_INFO("opening \"%s\"", ifname);

    dev->requested_mtu = NETMAP_RXRING(dev->nmd->nifp, 0)->nr_buf_size;

    dev->nmi.nmd = dev->nmd;
    dev->nmi.nmr = dev->nmr;

    netdev_request_reconfigure(netdev);

#ifdef DEBUGTHREAD /* debug */
    dev->nrx_sync = dev->ntx_sync = 0;
    dev->nrx_calls = dev->ntx_calls = 0;
    dev->nrx_packets = dev->ntx_packets = 0;
    if (pthread_create(&(dev->dbg_thread), NULL, debug_thread, netdev)) {
        VLOG_INFO("error starting debug thread");
    }
#endif

    VLOG_INFO("netmap_construct : done");
    return 0;
}

static void
netdev_netmap_destruct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    const char *ifname = netdev_get_name(netdev);

    VLOG_INFO("closing netmap port: \"%s\"", ifname);
    nm_close(dev->nmd);
#ifdef DEBUGTHREAD
    pthread_cancel(dev->dbg_thread);
#endif
    ovs_mutex_destroy(&dev->mutex);
    netmap_spin_destroy(&spinlock);
}

static void
netdev_netmap_dealloc(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    nm_alloc_ring_free(dev->nmr);
    nm_alloc_free_all();
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
//        && netdev->n_txq == dev->requested_n_txq
//        && netdev->n_rxq == dev->requested_n_rxq
//        && dev->rxq_size == dev->requested_rxq_size
//        && dev->txq_size == dev->requested_txq_size) {
        /* Reconfiguration is unnecessary */

        goto out;
    }

    dev->mtu = dev->requested_mtu;

//    netdev->n_txq = dev->requested_n_txq;
//    netdev->n_rxq = dev->requested_n_rxq;

//    dev->rxq_size = dev->requested_rxq_size;
//    dev->txq_size = dev->requested_txq_size;

//    dev->up.n_rxq = 1;
//    dev->up.n_txq = 1;

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

    //smap_add_format(args, "requested_rx_queues", "%d", dev->requested_n_rxq);
    //smap_add_format(args, "configured_rx_queues", "%d", netdev->n_rxq);
    //smap_add_format(args, "requested_tx_queues", "%d", dev->requested_n_txq);
    //smap_add_format(args, "configured_tx_queues", "%d", netdev->n_txq);
    smap_add_format(args, "mtu", "%d", dev->mtu);

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_set_config(struct netdev *netdev, const struct smap *args,
                         char **errp OVS_UNUSED)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    //VLOG_INFO("set_config");

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
#ifdef DEBUGTHREAD
    dev->ntx_sync++;
#endif
}

static inline void
netmap_rxsync(struct netdev_netmap *dev)
{
    uint64_t now = rdtsc();
    unsigned int diff = TSC2US(now - dev->timestamp);

    if (diff < dev->rxsync_rate_usecs) {
        /* rxsync rate is too high */
        return;
    }

    ioctl(dev->nmd->fd, NIOCRXSYNC, NULL);

    /* update current timestamp */
    dev->timestamp = now;

#ifdef DEBUGTHREAD
    dev->nrx_sync++;
#endif
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

    //VLOG_INFO("s_%s : qid:%d, c_txq:%d", (const char*) netdev_get_name(dev), qid, concurrent_txq);

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        dp_packet_delete_batch(batch, true);
        return 0;
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        netmap_spin_lock(&spinlock);
    }

try_again:
    for (r = 0; r < nrings; r++) {
        struct netmap_ring *ring;
        uint32_t head, space;

        ring = NETMAP_TXRING(nmd->nifp, nmd->cur_tx_ring);
        space = nm_ring_space(ring); /* Available slots in this ring. */
        head = ring->head;

        if (space > budget)
            space = budget;
        budget -= space;

        //VLOG_INFO("s_%s: %d slots on %d | %d/%d",
        //        netdev_get_name(dev), nm_ring_space(ring), nmd->cur_tx_ring, r, nrings-1);

        /* Transmit batch in this ring as much as possible. */
        while (space--) {
            struct netmap_slot *ts, *rs;
            struct dp_packet *packet;
            uint32_t idx;

            packet = batch->packets[count++];
            ts = &ring->slot[head];
            ts->len = dp_packet_get_send_len(packet);

            /*VLOG_INFO("s_%s: %d/%d head:%d len:%d",
                netdev_get_name(dev), count, space, head, ts->len);*/

            if (OVS_UNLIKELY(batch->packets[count]->source != DPBUF_NETMAP)) {
                /* send packet copying data to the netmap slot */
                memcpy(NETMAP_BUF(ring, ts->buf_idx),
                   dp_packet_data(packet), ts->len);
            } else {
                /* send packet using zerocopy */
                rs = &(NETMAP_RXRING(packet->nmi->nmd->nifp, packet->ring)->slot[packet->slot]);
                idx = ts->buf_idx;
                ts->buf_idx = rs->buf_idx;
                rs->buf_idx = idx;
                ts->flags |= NS_BUF_CHANGED;
                rs->flags |= NS_BUF_CHANGED;
            }

            head = nm_ring_next(ring, head);
        }

        ring->head = ring->cur = head;

        /* We may have exhausted the budget */
        if (OVS_LIKELY(!budget))
            break;

        /* We still have packets to send,
         * update ring head and select the next one. */
        if (OVS_UNLIKELY(++dev->nmd->cur_tx_ring == nrings))
            nmd->cur_tx_ring = 0;
    }

    netmap_txsync(dev);

    if (OVS_UNLIKELY(!count && !again)) {
        again = true;
        goto try_again;
    }

    /* it actually deletes the batch if contains non netmap packets,
     * it is used also to clean the batch. */
    dp_packet_delete_batch(batch, true);

#ifdef DEBUGTHREAD
    dev->ntx_calls++;
    dev->ntx_packets+=count;
#endif

    //VLOG_INFO("s_%d: %d packets sent", (int) syscall(SYS_gettid), count);

    if (OVS_UNLIKELY(concurrent_txq)) {
        netmap_spin_unlock(&spinlock);
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
    uint32_t budget = NETDEV_MAX_BURST, count = 0;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP)))
        return EAGAIN;

    for (r = nmd->first_rx_ring; r < nrings; r++)
        count += nm_ring_space(NETMAP_RXRING(nmd->nifp, r));

    if (!count)
        netmap_rxsync(dev);

    for (r = 0; r < nrings; r++) {
        struct netmap_ring *ring;
        uint32_t head, space;

        ring = NETMAP_RXRING(nmd->nifp, nmd->cur_rx_ring);
        head = ring->head;
        space = nm_ring_space(ring);
        if (space > budget)
            space = budget;
        budget -= space;

        //if (space)
        //VLOG_INFO_RL(&rl, "r_%s: %d slots on %d | %d/%d",
        //    netdev_get_name(dev), nm_ring_space(ring), nmd->cur_rx_ring, r, nrings-1);

        count = nm_alloc_prepare_batch(dev->nmr, batch, space);

        //if (count)
        //VLOG_INFO("r_%s: batch prepared: %d available",
        //    netdev_get_name(dev), count);

        while (count--) {
            struct dp_packet *packet = batch->packets[batch->count++];
            struct netmap_slot *slot = &ring->slot[head];
            void* buf = NETMAP_BUF(ring, slot->buf_idx);
            //VLOG_INFO("init_%d len:%d", batch->count, slot->len);
            dp_packet_init_netmap(packet, buf, slot->len,
                    &dev->nmi, nmd->cur_rx_ring, head);

            head = nm_ring_next(ring, head);
        }

        ring->cur = ring->head = head;

        if (!budget)
            break;

        if (OVS_UNLIKELY(++nmd->cur_rx_ring == nrings))
            nmd->cur_rx_ring = 0;
    }

#ifdef DEBUGTHREAD
    dev->nrx_packets += batch->count;
    dev->nrx_calls++;
#endif

    if (batch->count == 0)
        return EAGAIN;

    dp_packet_batch_init_packet_fields(batch);

    /*
    if (batch->count)
    VLOG_INFO("r_%d: %d", (int) syscall(SYS_gettid), batch->count);
    else
    VLOG_INFO_RL(&rl, "r_%d: %d", (int) syscall(SYS_gettid), batch->count);
    */
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
