//
// Created by user on 4/15/17.
//

#include <lwip/sys.h>
#include <pthread.h>
#include "test_sem.h"

struct sys_sem* sem;

void* thread_one(void* arg)
{
    sys_sem_wait(&sem);

    //pthread_cond_wait(&cond, &mutex);

    TSLOG("TEST","GO",NULL);
    return NULL;
}

void* thread_two(void* arg)
{
    //sys_sem_signal(&sem);
    return NULL;
}

void test_sem()
{
    sys_sem_new(&sem, 0);

    sys_thread_new("1", thread_one, NULL, 1024, 0);

    sys_thread_new("2", thread_two, NULL, 1024, 0);
}