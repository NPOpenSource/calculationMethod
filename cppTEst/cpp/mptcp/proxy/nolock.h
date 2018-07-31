//
// Created by ts on 2017/9/22.
//

#ifndef MYAPPLICATION_NOLOCK_H
#define MYAPPLICATION_NOLOCK_H

#include <semaphore.h>
#include <pthread.h>
#include "lwip/lwipopts.h"
#if !LINUX_PLATFORM
#include <linux/types.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif
#if !LINUX_PLATFORM
#include <stdatomic.h>
#else
typedef struct  {
   volatile int64_t cnt;
}atomic_long;

static void atomic_init(atomic_long *v, int64_t i)   {
	v->cnt = i;
}
static int64_t atomic_load(atomic_long *v){
	return v->cnt;
}
static int64_t atomic_fetch_add( atomic_long *v, int64_t inc){
     int64_t prev = inc;

	  asm __volatile__(
	  	"lock \r\n"
	  	"xaddq %[prev], %[cnt]\r\n"
	  	: [prev] "+r" (prev),
	  	  [cnt]  "=m" (v->cnt)
	         : "m" (v->cnt)
	  	);
}
#endif
#define MAX_QUE_RX_SIZE 1024
#define DATA_PACKET_LEN 32000

#if LWIP_PACKET_QUEUE
typedef void (* free_node_callback)(void * pNode);

struct packet_queue {
    char name[8];
    uint64_t q_size;
	uint64_t q_head;
	uint64_t q_tail;
	uint64_t q_elem_num;
	void **pNode;
	free_node_callback free_node;
	pthread_mutex_t q_lock;
};
#endif

struct queue{
    char name[8];
    int64_t q_size;
    atomic_long q_head;
    atomic_long q_tail;
    void ** pNode;
    sem_t hasData;
    u_int8_t flag;
};
//uint64_t getCPUCounter();
struct queue *queueCreate(char *name, int iQueLen);
int Enque(struct queue *pQue,void *pNode);
void* Deque(struct queue *pQue);
void destoryQue(struct queue *pQue);
int isNone(struct queue* pQue);
int enque_try(struct queue *pQue,void *pNode);
void* deque_try(struct queue *pQue);
int enque_push(struct queue *pQue,void *pNode);
void* deque_push(struct queue *pQue);

#if LWIP_PACKET_QUEUE
struct packet_queue *packet_queue_init(char *name, int iQueLen, free_node_callback free_callback);
void packet_queue_free(struct packet_queue *pQue);
int packet_queue_enque(struct packet_queue *pQue,void *pNode);
void *packet_queue_deque(struct packet_queue *pQue);
void *packet_queue_try_deque(struct packet_queue *pQue);
int packet_queue_try_enque(struct packet_queue *pQue,void *pNode);
int packet_queue_try_deque_list(struct packet_queue *pQue, int nMaxDequeNum,void **pNodes);
#endif

#if __cplusplus
};
#endif
#endif //MYAPPLICATION_NOLOCK_H
