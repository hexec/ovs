#ifndef NETDEV_NETMAP_H
#define NETDEV_NETMAP_H 1

struct dp_packet;

void nm_alloc_init_global(void);
void nm_alloc_init_local(void);
void nm_alloc_free_slot(struct dp_packet*);
void netdev_netmap_register(void);

#endif /* netdev-netmap.h */
