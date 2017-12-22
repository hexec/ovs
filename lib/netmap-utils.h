#ifndef __NETMAP_UTILS__
#define __NETMAP_UTILS__

#include <stdint.h>

extern uint64_t ticks_per_second;
#define NS2TSC(x) ((x)*ticks_per_second/1000000000UL)
#define TSC2NS(x) ((x)*1000000000UL/ticks_per_second)
#define US2TSC(x) ((x)*ticks_per_second/1000000UL)
#define TSC2US(x) ((x)*1000000UL/ticks_per_second)
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

//#define barrier() asm volatile ("" ::: "memory")

/*static inline void
tsc_sleep_till(uint64_t when)
{
    while (rdtsc() < when)
        barrier();
}*/

#define RECYCLED_MAX 32

struct dp_packet;
struct dp_packet_batch;
extern struct ovs_mutex mutex_recycle;
extern struct dp_packet **recycled_packets;
extern int recycled_packets_num;

void netmap_init_recycle();
struct dp_packet* netmap_pull_packet();
void netmap_push_batch(struct dp_packet_batch *batch);

#endif /* __NETMAP_UTILS__ */
