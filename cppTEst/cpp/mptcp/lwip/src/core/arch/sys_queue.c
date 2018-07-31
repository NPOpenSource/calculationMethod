//
// Created by ts on 2017/10/14.
//
#if 0
#include <lwip/arch/sys_queue.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <lwip/arch/rte_spinlock.h>
#include "../../../../../tools/common.h"

#define QUEUE_ALIGN_TYPE uint64_t
#define SOCKET_ID_ANY 0
/***
 * 队列
 */
struct __sys_queue{
    union {
        struct rte_ring* llring;
        QUEUE_ALIGN_TYPE llring_a;
    };
};
/***
 * 创建队列
 * @param name 名称
 * @param size 大小
 * @return
 */
sys_queue* sys_queue_create(char *name,uint size){
    sys_queue* q = NULL;
    q = (sys_queue*)malloc(sizeof(sys_queue));
    if(q == NULL){
        LogE("no rom for create sys queue");
        return NULL;
    }
    memset(q,0,sizeof(sys_queue));
    q->llring = rte_ring_create(name, size, SOCKET_ID_ANY, 0);
    return q;
}
/**
 * 入队操作
 * @param q  队列
 * @param msg 消息
 * @return 是否入队成功，成功返回1，失败返回0
 */
int sys_queue_push(sys_queue *q,void *msg){
    return sys_queue_push_internal(q,msg,0);
}
/**
 * 出队操作
 * @param q 队列
 * @return 出队成功返回入队元素，否则返回NULL
 */
void* sys_queue_pop(sys_queue *q) {
    int timeout = 1000;
    return sys_queue_pop_internal(q,(uint32_t*)&timeout,0);
}
/***
 * 入队的具体实现，内部操作
 * @param q 队列
 * @param msg 消息
 * @param tryPush 是否尝试
 * @return
 */
int sys_queue_push_internal(sys_queue *q,void *msg,int tryPush){
    int ret = 1;
    while(ret != 0){
        if(q == NULL){
            break;
        }
        ret = rte_ring_mp_enqueue(q->llring,msg);
        if(ret == 0){
            return 1;
        }else if(tryPush){
            return 0;
        }
    }
    return 0;
}

#define SYS_ARCH_TIMEOUT 0xffffffffUL
/***
 * 出队的具体实现，内部操作
 * @param q 队列
 * @param timeout 超时时间，单位s
 * @param tryPop 是否尝试
 * @return 出队成功返回元素，否则返回NULL
 */
void* sys_queue_pop_internal(sys_queue *q,uint32_t *timeout,int tryPop){
    int retVal;
    int ret = 1;
    struct timespec start,end;
    void *msg= NULL;
    uint32_t diff;
    if(timeout != NULL && *timeout) {
        retVal = clock_gettime(CLOCK_MONOTONIC, &start);
        if(retVal){
            LogE("%s:%d error msg:%s",__func__,__LINE__,strerror(errno));
            return NULL;
        }
    }
    while(ret != 0)
    {
        if(q == NULL){
            return NULL;
        }
        ret = rte_ring_mc_dequeue(q->llring,(void**)&msg);
        if(ret == 0){
            return msg;
        }else if(tryPop){
            if(timeout != NULL && *timeout){
                retVal = clock_gettime(CLOCK_MONOTONIC,&end);
                if(retVal){
                    *timeout = SYS_ARCH_TIMEOUT;
                    return NULL;
                }
                diff = end.tv_sec - start.tv_sec;
                if(diff > *timeout){
                    *timeout = SYS_ARCH_TIMEOUT;
                    return NULL;
                }
                usleep(1000);
                continue;
            }
            return NULL;
        }
    }
    return NULL;
}
/***
 * 销毁对应的元素
 * @param q 队列
 * @return 队列为空返回-1，否则正常销毁返回0
 */
int sys_queue_destory(sys_queue *q) {
    if(q == NULL)
        return -1;
    rte_ring_free(q->llring);
    free(q);
    return 0;
}

/***
 * 创建信号量
 * @return 信号量
 */
sys_sem_t_v3 * sys_sem_new_internal(int cnt){
    sys_sem_t_v3 *sem;
    sem = (sys_sem_t_v3 *)malloc(sizeof(sys_sem_t_v3));
    rte_spinlock_init(sem);
    return sem;
}
/***
 * 销毁信号量
 * @param sem 信号量
 * @return
 */
int sys_sem_free_internal(sys_sem_t_v3 *sem){
    if(sem != NULL){
        free(sem);
        return 1;
    }
    return 0;
}

void sys_sem_signal_internal(sys_sem_t_v3 *sem){
    return rte_spinlock_unlock(sem);
}

void sys_sem_wait_internal(sys_sem_t_v3 *sem){
    return rte_spinlock_lock(sem);
}

uint32_t sys_sem_wait_timeout_internal(sys_sem_t_v3 *sem,uint32_t *timeout){
    uint32_t need;
    int retVal = 1;
    int ret = 0;
    struct timespec start,end;
    if(timeout != NULL && *timeout)
    {
        retVal = clock_gettime(CLOCK_MONOTONIC,&start);
        if(retVal){
            LogE("%s:%d error msg:%s",__func__,__LINE__,strerror(errno));
            return 0;
        }
    }
    while(!ret){
        ret = rte_spinlock_trylock(sem);
        if(ret){
            goto END;
        } else
            while(sem->locked){
                rte_pause();
                if(timeout != NULL && *timeout != 0){
                    retVal = clock_gettime(CLOCK_MONOTONIC,&end);
                    need = end.tv_sec - start.tv_sec;
                    if(need > *timeout){
                        return SYS_ARCH_TIMEOUT;
                    }
                    usleep(1000);
                }
            }
    }

    END:
        return 0;
}
#endif