#include <config.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>   /* timersub */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h> /* read() */

#include "netmap-utils.h"
/*#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netmap_utils);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 100);
*/

/* initialize to avoid a division by 0 */
uint64_t ticks_per_second = 1000000000; /* set by calibrate_tsc */

/*
 * do an idle loop to compute the clock speed. We expect
 * a constant TSC rate and locked on all CPUs.
 * Returns ticks per second
 */
uint64_t
netmap_calibrate_tsc(void)
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
    ticks_per_second = cy;
    return cy;
}

int netmap_spin_create(struct netmap_spinlock_t* l) {
    return pthread_spin_init(&l->lock, PTHREAD_PROCESS_SHARED);
}

int netmap_spin_lock(struct netmap_spinlock_t* l) {
    return pthread_spin_lock(&l->lock);
}

int netmap_spin_unlock(struct netmap_spinlock_t* l) {
    return pthread_spin_unlock(&l->lock);
}

int netmap_spin_destroy(struct netmap_spinlock_t* l) {
    return pthread_spin_destroy(&l->lock);
}
