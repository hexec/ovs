#ifndef __SCHED_TSC__
#define __SCHED_TSC__

#include <stdint.h>

#ifndef ND /* debug macros, from netmap */
#include <sys/time.h>

struct timeval D_tod(void); /* XXX could be gettimeofday */
#define ND(_fmt, ...) do {} while(0)
#define D(_fmt, ...)						\
    do {							\
	struct timeval _t0 = D_tod();				\
	fprintf(stderr, "%03d.%06d %-10.10s [%d] " _fmt "\n",	\
	    (int)(_t0.tv_sec % 1000), (int)_t0.tv_usec,		\
	    __FUNCTION__, __LINE__, ##__VA_ARGS__);		\
    } while (0)

/* Rate limited version of "D", lps indicates how many per second */
#define RD(lps, format, ...)					\
    do {							\
	static __thread int __t0, __cnt;			\
	struct timeval __xxts = D_tod();			\
	if (__t0 != __xxts.tv_sec) {				\
	    __t0 = __xxts.tv_sec;				\
	    __cnt = 0;						\
	}							\
	if (__cnt++ < lps) {					\
	    D(format, ##__VA_ARGS__);				\
	}							\
    } while (0)
#endif

extern uint64_t ticks_per_second;
#define NS2TSC(x) ((x)*ticks_per_second/1000000000UL)
#define TSC2NS(x) ((x)*1000000000UL/ticks_per_second)
uint64_t calibrate_tsc(void);

#if 0 /* gcc intrinsic */
#include <x86intrin.h>
#define rdtsc __rdtsc
#else
static inline uint64_t
rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)lo | ((uint64_t)hi << 32);
}
#endif

#define barrier() asm volatile ("" ::: "memory")

static inline void
tsc_sleep_till(uint64_t when)
{
    while (rdtsc() < when)
        barrier();
}

void runon(const char *, int);

#endif /* __SCHED_TSC__ */
