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

struct netdev_netmap {
    struct netdev up;
    int max_packet_len;

    struct ovs_mutex mutex OVS_ACQ_AFTER(netmap_mutex);

    int mtu;
    int socket_id;
    int buf_size;
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

    dev = (struct netdev_netmap *) malloc(sizeof *dev);
    if (dev) {
        return &dev->up;
    }

    return NULL;
}

int
netdev_netmap_construct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);
    //const char *type = netdev_get_type(netdev);

    ovs_mutex_init(&dev->mutex);
    //eth_addr_random(&dev->etheraddr);

    return 0;
}

static void
netdev_netmap_destruct(struct netdev *netdev)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

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
netdev_netmap_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    //dev->etheraddr = mac;
    ovs_mutex_unlock(&dev->mutex);
    //netdev_change_seq_changed(netdev);

    return 0;
}

static int
netdev_netmap_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    //*mac = netdev->etheraddr;
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

/*
static void
netdev_netmap_run(const struct netdev_class *netdev_class OVS_UNUSED)
{
return;
}

static void
netdev_netmap_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{
    return;
}
*/

void
netdev_netmap_inc_rx(const struct netdev *netdev,
                    const struct dpif_flow_stats *stats)
{
    if (is_netmap_class(netdev_get_class(netdev))) {
        struct netdev_netmap *dev = netdev_netmap_cast(netdev);

        ovs_mutex_lock(&dev->mutex);
        //dev->stats.rx_packets += stats->n_packets;
        //dev->stats.rx_bytes += stats->n_bytes;
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
        //dev->stats.tx_packets += stats->n_packets;
        //dev->stats.tx_bytes += stats->n_bytes;
        ovs_mutex_unlock(&dev->mutex);
    }
}

static int
netdev_netmap_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_netmap *dev = netdev_netmap_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    //stats->tx_packets = dev->stats.tx_packets;
    //stats->tx_bytes = dev->stats.tx_bytes;
    //stats->rx_packets = dev->stats.rx_packets;
    //stats->rx_bytes = dev->stats.rx_bytes;
    ovs_mutex_unlock(&dev->mutex);

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
    NULL,                       /* get_mtu */               \
    NULL,                       /* set_mtu */               \
    NULL,                       /* get_ifindex */           \
    NULL,                       /* get_carrier */           \
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
    NULL,                       /* reconfigure */           \
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
        NULL, //netdev_netmap_set_config,
        NULL, //netdev_netmap_set_tx_multiq,
        netdev_netmap_eth_send,
        NULL, //netdev_netmap_get_carrier,
        netdev_netmap_get_stats,
        NULL, //netdev_netmap_get_features,
        NULL, //netdev_netmap_get_status,
        netdev_netmap_reconfigure,
        netdev_netmap_rxq_recv);

void
netdev_netmap_register(void)
{
    netdev_register_provider(&netmap_class);
}
