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

struct netdev_netmap {
    struct netdev up;
    struct nm_desc *netmap_desc;
    struct pollfd pfd[1];

    int max_packet_len;

    struct ovs_mutex mutex OVS_ACQ_AFTER(netmap_mutex);

    int mtu;
    struct netdev_stats stats;

    struct eth_addr hwaddr;
    enum netdev_flags flags;

    int requested_mtu;
    int requested_n_txq;
    int requested_n_rxq;
    int requested_rxq_size;
    int requested_txq_size;

    int rxq_size;
    int txq_size;
};

static void netdev_netmap_destruct(struct netdev *netdev);

static bool
is_netmap_class(const struct netdev_class *class)
{
    return class->destruct == netdev_netmap_destruct;
}

static struct netdev_netmap *
netdev_netmap_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_netmap, up);
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

int
netdev_netmap_construct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    const char *ifname = netdev_get_name(netdev);
    const char *type = netdev_get_type(netdev);

    VLOG_INFO("type -> %s", type);
    VLOG_INFO("ifname -> %s", ifname);

    if (access("/dev/netmap", F_OK) == -1) {
        VLOG_WARN("/dev/netmap not found.");
    }

    ovs_mutex_init(&dev->mutex);
    dev->requested_mtu = ETHER_MTU;
    eth_addr_random(&dev->hwaddr);

    dev->netmap_desc = nm_open(ifname, NULL, 0, NULL);
    if (!dev->netmap_desc) {
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

    dev->flags = NETDEV_UP | NETDEV_PROMISC;

    netdev_request_reconfigure(netdev);

    return 0;
}

static void
netdev_netmap_destruct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    const char *ifname = netdev_get_name(netdev);

    VLOG_INFO("closing netmap port: \"%s\"", ifname);
    nm_close(dev->netmap_desc);
    ovs_mutex_destroy(&dev->mutex);
}

static void
netdev_netmap_dealloc(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    free(dev);
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

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_netmap_set_config(const struct netdev *netdev, const struct smap *args,
                         char **errp)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static inline void
netdev_netmap_send__(struct netdev_netmap *dev, int qid,
                   struct dp_packet_batch *batch, bool may_steal,
                   bool concurrent_txq)
{
    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        dp_packet_delete_batch(batch, may_steal);
        return;
    }
}

static int
netdev_netmap_eth_send(struct netdev *netdev, int qid,
                     struct dp_packet_batch *batch, bool may_steal,
                     bool concurrent_txq)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    netdev_netmap_send__(dev, qid, batch, may_steal, concurrent_txq);
    return 0;
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

    /*if (!is_valid_port(dev->port_id)) {
        return ENODEV;
    }*/

    ovs_mutex_lock(&dev->mutex);
    //eth_dev_info_get(dev->port_id, &dev_info);
    ovs_mutex_unlock(&dev->mutex);

    //smap_add_format(args, "port_no", "%d", dev->port_id);

    return 0;
}

#define NETDEV_NETMAP_CLASS(NAME, INIT, CONSTRUCT, DESTRUCT, \
                          SET_CONFIG, SET_TX_MULTIQ, SEND,  \
                          GET_CARRIER, GET_STATS,           \
                          GET_FEATURES, GET_STATUS,         \
                          RECONFIGURE, RXQ_RECV)            \
{                                                           \
    NAME,                                                   \
    false,                      /* is_pmd */                \
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
    NULL,                       /* get_numa_id */           \
    NULL,                       /* tx multiq */             \
    SEND,                       /* send */                  \
    NULL,                       /* send_wait */             \
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
    NULL,                   /* rx_alloc */                  \
    NULL,                   /* rx_construct */              \
    NULL,                   /* rx_destruct */               \
    NULL,                   /* rx_dealloc */                \
    NULL,                   /* rx_recv */                   \
    NULL,                   /* rx_wait */                   \
    NULL,                   /* rx_drain */                  \
    NO_OFFLOAD_API                                          \
}


static const struct netdev_class netmap_class =
    NETDEV_NETMAP_CLASS(
        "netmap",
        netdev_netmap_class_init,
        netdev_netmap_construct,
        netdev_netmap_destruct,
        netdev_netmap_set_config,
        NULL, //netdev_netmap_set_tx_multiq,
        netdev_netmap_eth_send,
        netdev_netmap_get_carrier,
        netdev_netmap_get_stats,
        NULL, //netdev_netmap_get_features,
        netdev_netmap_get_status,
        netdev_netmap_reconfigure,
        netdev_netmap_rxq_recv);

void
netdev_netmap_register(void)
{
    netdev_register_provider(&netmap_class);
}
