#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>	/* timersub */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>	/* read() */

#include "tsc.h"

struct timeval
D_tod(void)
{
	static struct timeval t0, t;
	gettimeofday(&t, NULL);
	if (t0.tv_sec == 0 && t0.tv_usec == 0) {
		t0 = t;
 	}
	timersub(&t, &t0, &t);
	return t;
}

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

/*
void
runon(const char *name, int i)
{
    static int NUM_CPUS = 0;
    cpuset_t cpumask;

    if (NUM_CPUS == 0) {
	NUM_CPUS = sysconf(_SC_NPROCESSORS_ONLN);
	D("system has %d cores", NUM_CPUS);
    }
    CPU_ZERO(&cpumask);
    if (i >= 0) {
        CPU_SET(i, &cpumask);
    } else {
        /* -1 means it can run on any CPU /
        int j;

        i = -1;
        for (j = 0; j < NUM_CPUS; j++) {
            CPU_SET(j, &cpumask);
        }
    }

    if ((errno = pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t), &cpumask)) != 0) {
	D("Unable to set affinity for %s on %d : %s", name, i, strerror(errno));
    }

    if (i >= 0) {
        D("thread %s on core %d", name, i);
    } else {
        D("thread %s on any core in 0..%d", name, NUM_CPUS - 1);
    }
}*/
