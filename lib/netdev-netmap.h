#ifndef NETDEV_NETMAP_H
#define NETDEV_NETMAP_H 1

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

struct netmap_info {
    struct nm_desc* nmd;
    struct dp_packet** recycled_list;
    unsigned int* recycled_count;
};

void netdev_netmap_register(void);

#endif /* netdev-netmap.h */
