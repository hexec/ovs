#ifndef NETDEV_NETMAP_H
#define NETDEV_NETMAP_H 1

struct nm_desc;
struct nm_alloc_ring;
struct dp_packet;

struct nm_info {
    struct nm_desc* nmd;
    struct nm_alloc_ring* nmr;
};

void nm_alloc_free(struct nm_alloc_ring*, struct dp_packet*);
void netdev_netmap_register(void);

#endif /* netdev-netmap.h */
