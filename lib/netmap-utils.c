#include <config.h>

#include <stdio.h>
#include <fcntl.h>
#include <sys/time.h>   /* timersub */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h> /* read() */

#include "netmap-utils.h"
#include "dp-packet.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netmap_utils);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 100);

/* initialize to avoid a division by 0 */
uint64_t ticks_per_second = 1000000000; /* set by calibrate_tsc */

/*
 * do an idle loop to compute the clock speed. We expect
 * a constant TSC rate and locked on all CPUs.
 * Returns ticks per second
 */
uint64_t
calibrate_tsc(void)
{
    struct timeval a, b;
    uint64_t ta_0, ta_1, tb_0, tb_1, dmax = ~0;
    uint64_t da, db, cy = 0;
    int i;
    for (i=0; i < 3; i++) {
    ta_0 = rdtsc();
    gettimeofday(&a, NULL);
    ta_1 = rdtsc();
    usleep(20000);
    tb_0 = rdtsc();
    gettimeofday(&b, NULL);
    tb_1 = rdtsc();
    da = ta_1 - ta_0;
    db = tb_1 - tb_0;
    if (da + db < dmax) {
        cy = (b.tv_sec - a.tv_sec)*1000000 + b.tv_usec - a.tv_usec;
        cy = (double)(tb_0 - ta_1)*1000000/(double)cy;
        dmax = da + db;
    }
    }
    //ND("dmax %llu, da %llu, db %llu, cy %llu", (_P64)dmax, (_P64)da,
    //                                           (_P64)db, (_P64)cy);
    ticks_per_second = cy;
    return cy;
}

struct ovs_mutex mutex_recycle;
struct dp_packet **recycled_packets;
int recycled_packets_num;

void
netmap_init_recycle()
{
    ovs_mutex_init(&mutex_recycle);
    recycled_packets_num = -1;
    recycled_packets = (struct dp_packet **) malloc( RECYCLED_MAX * sizeof (struct dp_packet *));
}

struct dp_packet*
netmap_pull_packet()
{
    struct dp_packet *packet = NULL;

    ovs_mutex_lock(&mutex_recycle);
    if (recycled_packets_num >= 0)
        packet = recycled_packets[recycled_packets_num--];
    VLOG_INFO_RL(&rl, "pull from recycle: %d", recycled_packets_num);
    ovs_mutex_unlock(&mutex_recycle);

    return packet;
}

void
netmap_push_batch(struct dp_packet_batch *batch)
{
    struct dp_packet *packet = NULL;

    ovs_mutex_lock(&mutex_recycle);
    DP_PACKET_BATCH_FOR_EACH (packet, batch) {
        if (recycled_packets_num < RECYCLED_MAX) {
            recycled_packets[++recycled_packets_num] = packet;
            VLOG_INFO_RL(&rl, "push to recycle: %d", recycled_packets_num);
        }
        else
            dp_packet_delete(packet);
    }
    dp_packet_batch_init(batch);
    ovs_mutex_unlock(&mutex_recycle);
}

