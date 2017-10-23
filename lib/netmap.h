#ifndef NETMAP_H
#define NETMAP_H

/*
#ifdef NETMAP_NETDEV

#include <net/if.h>
#include <stdint.h>
#include <stddef.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

#endif  NETMAP_NETDEV */

struct smap;

void netmap_init(const struct smap *ovs_other_config);

#endif /* netmap.h */
