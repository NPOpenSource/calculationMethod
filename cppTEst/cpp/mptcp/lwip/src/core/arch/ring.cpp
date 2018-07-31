//
// Created by wyjap on 2017/10/11.
//
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <lwip/arch/ring.h>

struct rtp_perf_ring *rtp_perf_ring_create(unsigned int size, void *objAddrbase)
{
    unsigned int loop;
    struct rtp_perf_ring *pRing ;
    unsigned int alloc_size = sizeof(struct rtp_perf_ring) + size*sizeof(union RingData_U);

    pRing = (struct rtp_perf_ring *)memalign(alloc_size, 64);
    memset((void *)pRing,0x0,alloc_size);

    pRing->Head = 0;
    pRing->Tail = 0;
    pRing->size = size;
    pRing->mask = (size-1);
    pRing->Addrbase = objAddrbase;
    pRing->ring = (union RingData_U *)((char *)pRing+sizeof(struct rtp_perf_ring));
    for(loop=0;loop< size; loop++){
        pRing->ring[loop].data_s.ver = (loop-size);
        pRing->ring[loop].data_s.val = 0;
    }

    return pRing;
}

int rtp_perf_ring_enqueue(struct rtp_perf_ring *ring, void *box){
    union RingData_U expextPosVal,curVal;
    unsigned int CurHead,CurTail;
    unsigned int tmpHead,tmpTail;
    unsigned int size = ring->size;
    unsigned int mask = ring->mask;
    char *pAddrbase = (char *)ring->Addrbase;
    void *prmBox = box;


    CurHead = ring->Head;
    do {
        tmpTail = ring->Tail;
        if(tmpTail + size - CurHead == 0){
            if(ring->ring[tmpTail & mask].data_s.val == 0){
                __sync_bool_compare_and_swap(&ring->Tail, tmpTail, tmpTail+1);
            }
        }

        expextPosVal.data_l = (((unsigned long long)(CurHead - size))<<48);
        curVal.data_l = (((unsigned long long)CurHead)<<48)|((char *)prmBox - pAddrbase);

        if((ring->ring[CurHead & mask].data_s.ver == expextPosVal.data_s.ver)&&__sync_bool_compare_and_swap(&ring->ring[CurHead & mask].data_l,expextPosVal.data_l , curVal.data_l))
        {
            tmpHead = ring->Head;
            if(0==(CurHead & 0x1) && (CurHead -tmpHead < 0x80000000))
            {
                __sync_bool_compare_and_swap(&ring->Head,tmpHead,CurHead+1);
            }
            break;
        }
        tmpHead = ring->Head;
        CurHead = ((CurHead - tmpHead) < (mask-1))?(CurHead+1):tmpHead;
    }while(1);
    return 1;
}

int rtp_perf_ring_dequeue(struct rtp_perf_ring *ring, void **box){
    union RingData_U ExcpRingVal,curNullVal;
    unsigned int CurHead,CurTail;
    unsigned int tmpHead,tmpTail;
    unsigned int size = ring->size;
    unsigned int mask = ring->mask;
    char *pAddrbase = (char *)ring->Addrbase;
    void *prmBox = box;

    CurTail = ring->Tail;
    do{
        tmpHead = ring->Head;

        if(CurTail == tmpHead){
            if(!ring->ring[tmpHead & mask].data_s.val){
                __sync_bool_compare_and_swap(&ring->Head,tmpHead,tmpHead+1);
            }
            else{
                return 0;
            }
        }

        curNullVal.data_l = (((unsigned long long)(CurTail))<<48);
        ExcpRingVal = ring->ring[CurTail & mask];

        if((curNullVal.data_s.ver == ExcpRingVal.data_s.ver) &&(ExcpRingVal.data_s.val) && \
                  __sync_bool_compare_and_swap(&ring->ring[CurTail & mask].data_l,ExcpRingVal.data_l , curNullVal.data_l)){
            *box = (void *)(pAddrbase + ExcpRingVal.data_s.val);

            tmpTail = ring->Tail;
            if(0==(CurTail & 0x1) && (CurTail -tmpTail < 0x80000000))
            {
                __sync_bool_compare_and_swap(&ring->Tail,tmpTail,CurTail+1);
            }
            break;
        }

        tmpTail = ring->Tail;
        CurTail = ((CurTail - tmpTail) < (mask-1))?(CurTail+1):tmpTail;
    }while(1);

    return 0;
}

int rtp_perf_ring_free(struct rtp_perf_ring *ring){
    free((void *)ring);
    ring = NULL;
    return 0;
}
