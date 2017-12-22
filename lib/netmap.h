#ifndef NETMAP_H
#define NETMAP_H

#include "netmap-utils.h" /* to calibrate rdtsc */

struct smap;
struct dp_packet;

struct dp_packet* netmap_pull_packet();
void netmap_push_batch(struct dp_packet_batch *batch);
void netmap_init(const struct smap *ovs_other_config);

#endif /* netmap.h */
