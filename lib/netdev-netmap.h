#ifndef NETDEV_NETMAP_H
#define NETDEV_NETMAP_H 1

struct dp_packet;

void nm_init(int);
void nm_alloc_init(void);
void nm_free_packet(struct dp_packet *);
void netdev_netmap_register(void);

#endif /* netdev-netmap.h */
