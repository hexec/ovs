#ifndef NETDEV_NETMAP_H
#define NETDEV_NETMAP_H 1

#include <stdbool.h>
#include <stddef.h>
#include "compiler.h"

struct netdev;
struct netdev_class;
struct netdev_stats;

void netdev_netmap_register(void);

#endif /* netdev-netmap.h */
