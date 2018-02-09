#ifndef NETDEV_NETMAP_H
#define NETDEV_NETMAP_H 1

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

struct netmap_dp_packet_info {
    struct dp_packet** recycled_list;
    struct dp_packet* next;
    struct nm_desc* nmd;
    unsigned int ring, slot;
};

void netdev_netmap_register(void);

#endif /* netdev-netmap.h */
