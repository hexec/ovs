#include <config.h>

#include "netdev-netmap.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>

#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "byte-order.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "netdev.h"
#include "netdev-native-tnl.h"
#include "netdev-provider.h"
#include "openvswitch/dynamic-string.h"
#include "ovs-router.h"
#include "packets.h"
#include "poll-loop.h"
#include "route-table.h"
#include "smap.h"
#include "socket-util.h"
#include "unaligned.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "netdev-tc-offloads.h"

VLOG_DEFINE_THIS_MODULE(netdev_netmap);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define ETHER_ADDR_LEN   6
#define ETHER_TYPE_LEN   2
#define ETHER_CRC_LEN   4
#define ETHER_HDR_LEN   (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#define ETHER_MIN_LEN   64
#define ETHER_MAX_LEN   1518
#define ETHER_MTU   (ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define ETHER_MIN_MTU   68
#define MTU_TO_FRAME_LEN(mtu)       ((mtu) + ETHER_HDR_LEN + ETHER_CRC_LEN)
#define NETDEV_NETMAP_MAX_PKT_LEN     9728

#define DEFAULT_RXQ_SIZE 2048
#define DEFAULT_TXQ_SIZE 2048

#define NR_QUEUE 1

#define SOCKET0    0

struct netdev_netmap {
    struct netdev up;
    struct nm_desc *nmd;
    unsigned int nrx_sync;
    unsigned int ntx_sync;

    struct ovs_mutex mutex OVS_ACQ_AFTER(netmap_mutex);

    int mtu;

    struct netdev_stats stats;

    struct eth_addr hwaddr;
    enum netdev_flags flags;

    int n_txq;
    int n_rxq;
    int rxq_size;
    int txq_size;

    int requested_socket_id;
    int requested_mtu;
    int requested_n_txq;
    int requested_n_rxq;
    int requested_rxq_size;
    int requested_txq_size;

    // memory pool? delete
    int socket_id;
};

struct netdev_rxq_netmap {
    struct netdev_rxq up;
    struct nm_desc *nmd;
};

static struct ovs_mutex netmap_mutex = OVS_MUTEX_INITIALIZER;

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

static inline void netmap_txsync(struct netdev_netmap *dev)
{
    ioctl(dev->nmd->fd, NIOCTXSYNC, NULL);
    VLOG_INFO_RL(&rl, "txsync(%d)", dev->ntx_sync++);
}

static inline void netmap_rxsync(struct netdev_netmap *dev)
{
    ioctl(dev->nmd->fd, NIOCRXSYNC, NULL);
    VLOG_INFO_RL(&rl, "rxsync(%d)", dev->nrx_sync++);
}

int
netdev_netmap_construct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    const char *ifname = netdev_get_name(netdev);
    const char *type = netdev_get_type(netdev);

    if (access("/dev/netmap", F_OK) == -1) {
        VLOG_WARN("/dev/netmap not found, module is not loaded.");
    }

    ovs_mutex_init(&dev->mutex);
    dev->requested_mtu = ETHER_MTU;
    eth_addr_random(&dev->hwaddr);

    dev->socket_id = SOCKET0;
    dev->requested_socket_id = dev->socket_id;
    dev->flags = 0;

    netdev->n_rxq = 0;
    netdev->n_txq = 0;
    dev->requested_n_rxq = NR_QUEUE;
    dev->requested_n_txq = NR_QUEUE;
    dev->requested_rxq_size = DEFAULT_RXQ_SIZE;
    dev->requested_txq_size = DEFAULT_TXQ_SIZE;

    dev->flags = NETDEV_UP | NETDEV_PROMISC;

    dev->nmd = nm_open(ifname, NULL, 0, NULL);
    if (!dev->nmd) {
        if (!errno) {
            VLOG_WARN("opening \"%s\" failed: not a netmap port", ifname);
        } else {
            VLOG_WARN("opening \"%s\" failed: %s", ifname,
                  ovs_strerror(errno));
        }
        return EINVAL;
    } else {
        VLOG_INFO("opening \"%s\"", ifname);
    }
    dev->ntx_sync = dev->nrx_sync = 0;

    netmap_txsync(dev);
    netmap_rxsync(dev);

    netdev_request_reconfigure(netdev);

    return 0;
}

static void
netdev_netmap_destruct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    const char *ifname = netdev_get_name(netdev);

    VLOG_INFO("closing netmap port: \"%s\"", ifname);
    nm_close(dev->nmd);
    ovs_mutex_destroy(&dev->mutex);
}

static void
netdev_netmap_dealloc(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
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
    return err;
}

static void
netdev_netmap_rxq_destruct(struct netdev_rxq *rxq)
{
    struct netdev_rxq_netmap *rx = netdev_rxq_netmap_cast(rxq);
}

static void
netdev_netmap_rxq_dealloc(struct netdev_rxq *rxq)
{
    struct netdev_rxq_netmap *rx = netdev_rxq_netmap_cast(rxq);
    free(rx);
}

static int
netdev_netmap_set_tx_multiq(struct netdev *netdev, unsigned int n_txq)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    if (dev->requested_n_txq != n_txq) {
        dev->requested_n_txq = n_txq;
        netdev_request_reconfigure(netdev);
    }

    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

static int
netdev_netmap_class_init(void)
{
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

    if (netdev->n_txq == dev->requested_n_txq
        && netdev->n_rxq == dev->requested_n_rxq
        && dev->mtu == dev->requested_mtu
        && dev->rxq_size == dev->requested_rxq_size
        && dev->txq_size == dev->requested_txq_size
        && dev->socket_id == dev->requested_socket_id) {
        /* Reconfiguration is unnecessary */

        goto out;
    }

    dev->mtu = dev->requested_mtu;

    netdev->n_txq = dev->requested_n_txq;
    netdev->n_rxq = dev->requested_n_rxq;

    dev->rxq_size = dev->requested_rxq_size;
    dev->txq_size = dev->requested_txq_size;

    dev->up.n_rxq = 1;
    dev->up.n_txq = 1;

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

    smap_add_format(args, "requested_rx_queues", "%d", dev->requested_n_rxq);
    smap_add_format(args, "configured_rx_queues", "%d", netdev->n_rxq);
    smap_add_format(args, "requested_tx_queues", "%d", dev->requested_n_txq);
    smap_add_format(args, "configured_tx_queues", "%d", netdev->n_txq);
    smap_add_format(args, "mtu", "%d", dev->mtu);

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_set_config(const struct netdev *netdev, const struct smap *args,
                         char **errp)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    VLOG_INFO("set_config");

    ovs_mutex_lock(&netmap_mutex);
    ovs_mutex_lock(&dev->mutex);

    //netmap_set_rxq_config(dev, args);

    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&netmap_mutex);

    return 0;
}

static int
netdev_netmap_send(struct netdev *netdev, int qid,
                     struct dp_packet_batch *batch, bool may_steal,
                     bool concurrent_txq)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    int error = 0;

    VLOG_INFO_RL(&rl, "send : qid:%d, steal:%d, concurrent_txq:%d", qid, may_steal, concurrent_txq);

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        error = EAGAIN;
        goto free_batch;
    }

    struct netmap_ring *ring;
    uint16_t nr = 0, nrings = dev->nmd->nifp->ni_tx_rings;
    unsigned int ntx  = 0;
    bool sync = false;

    for (; nr < nrings; nr++) {
        unsigned int head;
        unsigned int space;

        ring = NETMAP_TXRING(dev->nmd->nifp, dev->nmd->cur_tx_ring);
        space = nm_ring_space(ring); /* Available slots in this ring. */
        head = ring->head;

        VLOG_INFO("send: %d free slots on %d ring | cycle %d/%d", space, dev->nmd->cur_tx_ring, nr, nrings-1);

        /* If the current ring has low space, call txsync in not already called */
        if (OVS_UNLIKELY(space < NETDEV_MAX_BURST)) {
            if (!sync) {
                netmap_txsync(dev);
                sync = true;
                continue;
            }
            if (space == 0) {
                dev->nmd->cur_tx_ring = (dev->nmd->cur_tx_ring + 1) % nrings;
                continue;
            }
        }

        /* Transmit batch in this ring as much as possible. */
        for (; space > 0; space--, ntx++) {
                struct netmap_slot *ts = &ring->slot[head];
                struct dp_packet *packet = batch->packets[ntx];
                ts->len = dp_packet_get_send_len(packet);
                memcpy(NETMAP_BUF(ring, ts->buf_idx),
                       dp_packet_data(packet),
                       ts->len);
                //nm_pkt_copy((void *) dp_packet_data(packet), (void *) buf, ts->len);
                head = nm_ring_next(ring, head);

                /* No more packets to send in this batch. */
                if (OVS_UNLIKELY((ntx+1) == batch->count)) {
                    ring->head = ring->cur = head;
                    goto free_batch;
                }
        }
        /* We still have packets to send,
         * update ring head and select the next one. */
        ring->head = ring->cur = head;
        dev->nmd->cur_tx_ring = (dev->nmd->cur_tx_ring + 1) % nrings;
    }

free_batch:
    dp_packet_delete_batch(batch, may_steal);
    VLOG_INFO("send batch: %d", ntx+1);
    return error;
}

static void
netdev_netmap_send_wait(struct netdev *netdev, int qid OVS_UNUSED)
{
    poll_immediate_wake();
}

static int
netdev_netmap_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch)
{
    struct netdev_rxq_netmap *rx = netdev_rxq_netmap_cast(rxq);
    struct netdev_netmap *dev = netdev_netmap_cast(rxq->netdev);
    //int qid = rxq->queue_id;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        VLOG_INFO_RL(&rl, "rxq_recv: device down");
        return EAGAIN;
    }

    uint16_t nr = 0, nrings = dev->nmd->nifp->ni_rx_rings;
    struct netmap_ring *ring;
    unsigned int nrx = 0;
    bool sync = false;

    for (; nr < nrings; nr++) {
        unsigned head, tail, space;

        ring = NETMAP_RXRING(dev->nmd->nifp, dev->nmd->cur_rx_ring);
        head = ring->head;
        tail = ring->tail;
        space = nm_ring_space(ring);

        VLOG_INFO_RL(&rl, "rxq_recv: %d free slots on %d ring | cycle %d/%d", space, dev->nmd->cur_rx_ring, nr, nrings-1);

        if (OVS_UNLIKELY(space < NETDEV_MAX_BURST)) {
            if (!sync) {
                netmap_rxsync(dev);
                sync = true;
                continue;
            }
            if (space == 0) {
                dev->nmd->cur_rx_ring = (dev->nmd->cur_rx_ring + 1) % nrings;
                continue;
            }
        }

        while (head != tail && nrx < NETDEV_MAX_BURST) {
            struct netmap_slot *slot = &ring->slot[head];
            struct dp_packet *packet = dp_packet_new(slot->len);
            memcpy(dp_packet_data(packet),
                   NETMAP_BUF(ring, slot->buf_idx),
                   slot->len);
            dp_packet_set_size(packet, slot->len);
            dp_packet_batch_add(batch, packet);
            head = nm_ring_next(ring, head);
            nrx++;
        }

        ring->cur = ring->head = head;
        if (nrx >= NETDEV_MAX_BURST)
            break;
        dev->nmd->cur_rx_ring = (dev->nmd->cur_rx_ring + 1) % nrings;
    }

    if (nrx == 0)
        return EAGAIN;

    VLOG_INFO("rxq_recv batch: %d", nrx);

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
netdev_netmap_rxq_drain(struct netdev_rxq *rxq_)
{
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

    if (MTU_TO_FRAME_LEN(mtu) > NETDEV_NETMAP_MAX_PKT_LEN
        || mtu < ETHER_MIN_MTU) {
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
    ovs_mutex_unlock(&dev->mutex);
    netdev_change_seq_changed(netdev);

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
netdev_netmap_update_flags(struct netdev *netdev OVS_UNUSED,
                          enum netdev_flags off,
                          enum netdev_flags on OVS_UNUSED,
                          enum netdev_flags *old_flagsp)
{
    if (off & (NETDEV_UP | NETDEV_PROMISC)) {
        return EOPNOTSUPP;
    }

    *old_flagsp = NETDEV_UP | NETDEV_PROMISC;
    return 0;
}

void
netdev_netmap_inc_rx(const struct netdev *netdev,
                    const struct dpif_flow_stats *stats)
{
    if (is_netmap_class(netdev_get_class(netdev))) {
        struct netdev_netmap *dev = netdev_netmap_cast(netdev);

        ovs_mutex_lock(&dev->mutex);
        dev->stats.rx_packets += stats->n_packets;
        dev->stats.rx_bytes += stats->n_bytes;
        ovs_mutex_unlock(&dev->mutex);
    }
}

void
netdev_netmap_inc_tx(const struct netdev *netdev,
                    const struct dpif_flow_stats *stats)
{
    if (is_netmap_class(netdev_get_class(netdev))) {
        struct netdev_netmap *dev = netdev_netmap_cast(netdev);

        ovs_mutex_lock(&dev->mutex);
        dev->stats.tx_packets += stats->n_packets;
        dev->stats.tx_bytes += stats->n_bytes;
        ovs_mutex_unlock(&dev->mutex);
    }
}

static int
netdev_netmap_get_carrier(const struct netdev *netdev, bool *carrier)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    //check_link_status(dev);
    //*carrier = dev->link.link_status;
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
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_get_numa_id(const struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    return dev->socket_id;
}

static void
netmap_set_rxq_config(struct netdev_netmap *dev, const struct smap *args)
    OVS_REQUIRES(dev->mutex)
{
    int new_n_rxq;

        new_n_rxq = 2; //MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq != dev->requested_n_rxq) {
        dev->requested_n_rxq = new_n_rxq;
        netdev_request_reconfigure(&dev->up);
    }
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
    netdev_netmap_get_numa_id,                              \
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
    netdev_netmap_rxq_drain,                                \
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
        netdev_netmap_set_tx_multiq,
        netdev_netmap_send,
        netdev_netmap_send_wait,
        netdev_netmap_get_carrier,
        netdev_netmap_get_stats,
        NULL, //netdev_netmap_get_features,
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
        netdev_netmap_set_tx_multiq,
        netdev_netmap_send,
        NULL,
        netdev_netmap_get_carrier,
        netdev_netmap_get_stats,
        NULL, //netdev_netmap_get_features,
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
