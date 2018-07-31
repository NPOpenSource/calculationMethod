//
// Created by ts on 2017/9/22.
//
#include<unistd.h>
#include<malloc.h>
#include "../../tools/tools.h"
#include "nolock.h"
#include <string.h>

//typedef struct {
//    volatile uint64_t cnt;
//}atomic_64;

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_PROXY

#define LOCK_DEBUG 0
#if LINUX_PLATFORM
#ifndef uint64_t
#define uint64_t int64_t
#endif
#endif
extern  "C" struct queue *queueCreate(char *name, int iQueLen);
extern  "C" void* Deque(struct queue *pQue);
extern  "C" int Enque(struct queue *pQue,void *pNode);
extern  "C" void destoryQue(struct queue *pQue);
extern  "C" int isNone(struct queue* pQue);
//uint64_t __atomic64_add_return(uint64_t i, uint64_t *v)
//{
//    uint64_t *__v = v ;
//    uint64_t val;
//
//	asm volatile(
//	    "0:						\n"
//	    "	orcc		gr0,gr0,gr0,icc3	\n"
//	    "	ckeq		icc3,cc7		\n"
//	    "	ldd.p		%M0,%1			\n"
//	    "	orcr		cc7,cc7,cc3		\n"
//	    "   addcc		%L1,%L2,%L1,icc0	\n"
//	    "   addx		%1,1,%1,icc0		\n"
//	    "	cstd.p		%1,%M0		,cc3,#1	\n"
//	    "	corcc		gr29,gr29,gr0	,cc3,#1	\n"
//	    "	beq		icc3,#0,0b		\n"
//        : "+m"(*__v),"=&e"(val)
//        : "e"(i)
//	    : "memory", "cc7", "cc3", "icc0", "icc3"
//	    );
//
//	return val;
//}


/***
 * arm get CPU count
 * @return
 */
//inline uint64_t getCPUCounter(){
//    uint64_t counter;
//    asm volatile("msr %0, pmccntr_e10" : "=r"(counter));
//    return counter;
//}
/***
 *
 * @param v
 * @param inc
 * @return
 */
//static inline uint64_t
//atomic64_add_return(uint64_t v, uint64_t inc)
//{
//    return atomic_fetch_add(inc,&v);
//}
//#include<android/atomic.h>

//inline uint64_t atomic64_add_return(){
//
//}


/***
 * queueCreate
 * @param name
 * @param iQueLen  len must be 2^n
 * @return
 */
struct queue *queueCreate(char *name, int iQueLen)
{
    struct queue *pQue = NULL;
    if(iQueLen<=0)
        iQueLen = 1024;
    pQue = (struct queue*)malloc(sizeof(struct queue)+sizeof(void*)*iQueLen);
    memset(pQue,0,sizeof(struct queue)+sizeof(void*)*iQueLen);
    pQue->pNode = (void**)((char*)pQue + sizeof(struct queue));
    pQue->q_size = (int64_t)iQueLen;
    //pQue->q_head = pQue->q_tail = 0;
    atomic_init(&(pQue->q_head),0);
    atomic_init(&(pQue->q_tail),0);
    memcpy(pQue->name,name,8);
    sem_init(&pQue->hasData,0,0);
    pQue->flag = 0;
    return pQue;
}
/***
 * 入队
 * @param pQue
 * @param pNode
 * @return
 */
int Enque(struct queue *pQue,void *pNode){
    uint64_t index = 0;
    uint64_t tail,head;

    tail = atomic_load(&pQue->q_tail);
    head = atomic_load(&pQue->q_head);
    //LogE("enter equeu1 head:%ld tail:%ld",head,tail);
    if(tail <head  + pQue->q_size -128 ){
        //pQue->pNode[pQue->q_tail]
        //atomic_fetch_add(pQue->q_tail,1);
        index = tail;
        index &= (pQue->q_size - 1);
        pQue->pNode[index] = pNode;
        atomic_fetch_add(&pQue->q_tail,1);
		/*
		CurHead = ring->Head;
		tmpHead = pQue->q_head;
		__sync_bool_compare_and_swap(&pQue->q_head,tmpHead,CurHead+1);*/
#if LOCK_DEBUG
        LogE("%s:%d %s current tail:%ld,head:%ld, %p",__func__,__LINE__, pQue->name,atomic_load(&pQue->q_tail),head,pNode);
#endif
        if(pQue->flag==1){
            sem_post(&pQue->hasData);
            pQue->flag =0;
        }
        return 1;
    }
    //LogE("output equeu1 head:%ld tail:%ld",head,tail);
    return 0;
}
/**
 * 出队
 * @param pQue
 * @return
 */
void* Deque(struct queue *pQue){
    uint64_t index;
    void *pNode;
    uint64_t head = atomic_load(&pQue->q_head);
    uint64_t tail = atomic_load(&pQue->q_tail);
    //LogE("enter Deque1 head:%ld tail:%ld",head,tail);
    if( head != tail ){
        index = atomic_load(&pQue->q_head) & (pQue->q_size -1);
        pNode = pQue->pNode[index];
        pQue->pNode[index] = NULL;
        atomic_fetch_add(&pQue->q_head,1);
#if LOCK_DEBUG
        LogE("%s:%d: %s head:%ld,tail:%ld, %p",__func__,__LINE__, pQue->name,atomic_load(&pQue->q_head),tail,pNode);
#endif
        return pNode;
    }else{
        pQue->flag = 1;
        struct timespec ts;
        ts.tv_nsec = 0;
        ts.tv_sec = 1;
        sem_timedwait(&pQue->hasData,&ts);
    }
    //LogE("out Deque1 head:%ld tail:%ld",head,tail);
    return 0;
}

int isNone(struct queue* pQue){
    uint64_t head = atomic_load(&pQue->q_head);
    uint64_t tail = atomic_load(&pQue->q_tail);
#if LOCK_DEBUG
    LogE("%s:%d head:%ld,tail:%ld isNode:%s",__func__,__LINE__,head,tail,tail - head < 50?"true":"false");
#endif
    return tail - head < 50 ? 1: 0;
}
/**
 * destory
 * @param pQue
 */
void destoryQue(struct queue *pQue){
    if(pQue != NULL){
        sem_destroy(&pQue->hasData);
        free(pQue);
    }
}

#if LWIP_PACKET_QUEUE
struct packet_queue *packet_queue_init(char *name, int iQueLen, free_node_callback free_callback)
{
    struct packet_queue *pQue = NULL;
	int i;
	
    if(iQueLen<=0)
        iQueLen = 128;
    pQue = (struct packet_queue*)malloc(sizeof(struct packet_queue)+sizeof(void*)*iQueLen);
    memset(pQue,0,sizeof(struct packet_queue)+sizeof(void*)*iQueLen);
    pQue->pNode = (void**)((char*)pQue + sizeof(struct packet_queue));
    pQue->q_size = (uint64_t)iQueLen;
	pQue->free_node = free_callback;

	pQue->q_head = 0;
	pQue->q_tail = 0;

    memcpy(pQue->name,name,8);
    pQue->q_elem_num = 0;
	pthread_mutex_init(&pQue->q_lock,NULL);
    return pQue;
}

void packet_queue_free(struct packet_queue *pQue){
	 uint64_t i,index;
     if(pQue == NULL)
	 	return;

     if(pQue->free_node != NULL){
	     pthread_mutex_lock(&pQue->q_lock);
		 for(i=pQue->q_tail;i<pQue->q_head;i++)
		 {
		    index = pQue->q_tail & (pQue->q_size - 1);
	        if(pQue->pNode[index] != NULL)
	        {
	           pQue->free_node(pQue->pNode[index]);
	        }
		 }
		 pthread_mutex_unlock(&pQue->q_lock);
     }
	 free(pQue);
	 pQue = NULL;
	 return;
}

int packet_queue_enque(struct packet_queue *pQue,void *pNode){
    uint64_t index = 0;
	int iRet = 1;

    pthread_mutex_lock(&pQue->q_lock);
    if(pQue->q_tail < (pQue->q_head  + pQue->q_size) ){
        index = pQue->q_tail & (pQue->q_size - 1);
        pQue->pNode[index] = (void *)pNode;
        pQue->q_tail++;
		iRet = 0;
    }
	pthread_mutex_unlock(&pQue->q_lock);
	
    return iRet;
}

void *packet_queue_deque(struct packet_queue *pQue){
    uint64_t index;
    void *pNode = NULL;
	int try_times = 0;

    pthread_mutex_lock(&pQue->q_lock);
    if( pQue->q_head != pQue->q_tail ){
        index = pQue->q_head & (pQue->q_size -1);
        pNode = pQue->pNode[index];
        pQue->pNode[index] = NULL;
        pQue->q_head++;
    }
	pthread_mutex_unlock(&pQue->q_lock);
    
    return pNode;
}

int packet_queue_try_enque(struct packet_queue *pQue,void *pNode){
    uint64_t index = 0;
	int iRet = 1;
	int try_times = 0;

    Retry:
    if(pthread_mutex_trylock(&pQue->q_lock) == 0){
		if(try_times++ < 50 )
			goto Retry;
    }
	else{
	    if(pQue->q_tail < (pQue->q_head  + pQue->q_size) ){
	        index = pQue->q_tail & (pQue->q_size - 1);
	        pQue->pNode[index] = (void *)pNode;
	        pQue->q_tail++;
			iRet = 0;
	    }
		pthread_mutex_unlock(&pQue->q_lock);
	}

    return iRet;
}


void *packet_queue_try_deque(struct packet_queue *pQue){
    uint64_t index;
    void *pNode = NULL;
	int try_times = 0;

Retry:
    if(pthread_mutex_trylock(&pQue->q_lock) != 0){
		if(try_times++ <5)
			goto Retry;
    }
	else
    {
	    if( pQue->q_head != pQue->q_tail ){
	        index = pQue->q_head & (pQue->q_size -1);
	        pNode = pQue->pNode[index];
	        pQue->pNode[index] = NULL;
	        pQue->q_head++;
	    }
		pthread_mutex_unlock(&pQue->q_lock);
    }
    return pNode;
}

int packet_queue_try_deque_list(struct packet_queue *pQue, int nMaxDequeNum,void **pNodes){
    uint64_t index;
    void *pNode = NULL;
	int i = 0,try_times = 0;

Retry:
    if(pthread_mutex_trylock(&pQue->q_lock) != 0){
		if(try_times++ < 10)
			goto Retry;
    }
	else
    {
        for(i=0; i<nMaxDequeNum; i++){ 
		    if( pQue->q_head != pQue->q_tail ){
		        index = pQue->q_head & (pQue->q_size -1);
		        pNodes[i] = pQue->pNode[index];
		        pQue->pNode[index] = NULL;
		        pQue->q_head++;
		    }
			else{
				break;
			}
        }
		pthread_mutex_unlock(&pQue->q_lock);
    }
    return i;
}
#endif
