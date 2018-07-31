//
// Created by wyjap on 2017/10/11.
//

#ifndef DPTEST_RING_H
#define DPTEST_RING_H


union RingData_U{
    struct RingData_S {
        volatile unsigned long long val:48;
        volatile unsigned long long ver:16;
    }data_s;
    unsigned long data_l;
};

struct rtp_perf_ring {
    volatile unsigned int Head;
    volatile unsigned int Tail;
    unsigned int size;
    unsigned int mask;
    void *Addrbase;
    union RingData_U *ring;
};

struct rtp_perf_ring *rtp_perf_ring_create(unsigned int size, void *objAddrbase);
int rtp_perf_ring_enqueue(struct rtp_perf_ring *ring, void *box);
int rtp_perf_ring_dequeue(struct rtp_perf_ring *, void **box);
int rtp_perf_ring_free(struct rtp_perf_ring *);

#endif //DPTEST_RING_H
