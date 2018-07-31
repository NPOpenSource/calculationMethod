//
// Created by ts on 2017/10/14.
//

#ifndef MYAPPLICATION_SYS_QUEUE_H
#define MYAPPLICATION_SYS_QUEUE_H

#include <stdint.h>
#include <sys/types.h>
#include <lwip/arch/rte_spinlock.h>

#ifdef __cplusplus
extern "C" {
#endif
struct __sys_queue;
typedef rte_spinlock_t sys_sem_t_v3;
typedef struct __sys_queue sys_queue;
sys_queue* sys_queue_create(char *name,uint size);
int sys_queue_push(sys_queue *q,void *msg);
void* sys_queue_pop(sys_queue *q);
int sys_queue_push_internal(sys_queue *q,void *msg,int tryPush);
void* sys_queue_pop_internal(sys_queue *q,uint32_t *timeout,int tryPop);
int sys_queue_destory(sys_queue *q);

sys_sem_t_v3 * sys_sem_new_internal(int cnt);
int sys_sem_free_internal(sys_sem_t_v3 *sem);
void sys_sem_signal_internal(sys_sem_t_v3 *sem);
void sys_sem_wait_internal(sys_sem_t_v3 *sem);
uint32_t sys_sem_wait_timeout_internal(sys_sem_t_v3 *sem,uint32_t *timeout);

#ifdef __cplusplus
};
#endif
#endif //MYAPPLICATION_SYS_QUEUE_H
