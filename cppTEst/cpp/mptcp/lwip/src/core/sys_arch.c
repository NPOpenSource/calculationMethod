/*
 * Copyright (c) 2014 Digital Sorcery, LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is *NOT* part of the lwIP TCP/IP stack.
 *
 * Author: Kory Herzinger <digisorcery@gmail.com>
 *
 */
#define SYS_ARCH_REPLACE 0
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#if SYS_ARCH_REPLACE
#include <lwip/arch/rte_spinlock.h>
#include <lwip/arch/sys_queue.h>

#endif
#include "lwip/sys.h"
#include "lwip/opt.h"
#include "lwip/stats.h"
#include "lwip/timeouts.h"

#define UMAX(a, b)      ((a) > (b) ? (a) : (b))
/*
static struct timeval starttime;
*/
static struct timeval g_starttime = {0, 0};

#if !NO_SYS
#if !SYS_ARCH_REPLACE
/*
static struct sys_thread *threads = NULL;
static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;
*/
struct sys_context {
	struct sys_thread *threads;
	pthread_mutex_t threads_mutex;
	struct timeval starttime;
#if SYS_LIGHTWEIGHT_PROT
    pthread_mutex_t lwprot_mutex;
    pthread_t lwprot_thread ;
    int lwprot_count ;
#endif
};
struct sys_context *get_sys_context(void);

/*
struct sys_context {
    int dumy;
};
*/


#else
static struct sys_thread *threads = NULL;
static rte_spinlock_t threads_mutex = RTE_SPINLOCK_INITIALIZER;
#endif
struct sys_mbox_msg {
    struct sys_mbox_msg *next;
    void *msg;
};

#define DEFAULT_SYS_MBOX_SIZE 128
#define MAX_SYS_MBOX_SIZE 8192

#if !SYS_ARCH_REPLACE
struct sys_mbox {
    unsigned long long first, last;   //to avoid overflow result of check sysbox full error
    void **msgs;
    struct sys_sem *not_empty;
    struct sys_sem *not_full;
    struct sys_sem *mutex;
    int wait_send;
    int size;
};

struct sys_sem {
    unsigned int c;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
};
#else
typedef sys_queue sys_mbox;
typedef sys_sem_t_v3 sys_sem;
#endif
/*struct sys_thread {
    struct sys_thread *next;
    pthread_t pthread;
};
*/
#if !SYS_ARCH_REPLACE
#if SYS_LIGHTWEIGHT_PROT
static pthread_mutex_t lwprot_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t lwprot_thread = (pthread_t)0xDEAD;
static int lwprot_count = 0;
#endif
/* SYS_LIGHTWEIGHT_PROT */
#else
static rte_spinlock_t lwprot_mutex = RTE_SPINLOCK_INITIALIZER;
static pthread_t lwprot_thread = (pthread_t)0xDEAD;
static int lwprot_count = 0;
#endif
#if !SYS_ARCH_REPLACE
static struct sys_sem *sys_sem_new_internal(u8_t count);
static void sys_sem_free_internal(struct sys_sem *sem);

static u32_t cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex,
                       u32_t timeout);
#else

#endif
/*-----------------------------------------------------------------------------------*/
static struct sys_thread *
introduce_thread(pthread_t id)
{
  struct sys_thread *thread;
  struct sys_context *pstSysContext = get_sys_context();

  thread = (struct sys_thread *)malloc(sizeof(struct sys_thread));

  if (thread != NULL)
  {
#if !SYS_ARCH_REPLACE
	if(pstSysContext != NULL) {
	    pthread_mutex_lock(&pstSysContext->threads_mutex);
	    thread->next = pstSysContext->threads;
	    thread->pthread = id;
	    pstSysContext->threads = thread;
	    pthread_mutex_unlock(&pstSysContext->threads_mutex);
	}
#else
	if(threads != NULL)) {
	    rte_spinlock_lock(&threads_mutex);
	    thread->next = threads;
	    thread->pthread = id;
	    threads = thread;
	    rte_spinlock_unlock(&threads_mutex);
	}
#endif
  }

  return thread;
}
/*-----------------------------------------------------------------------------------*/
sys_thread_t
sys_thread_new(void *instance, pthread_attr_t *pAttr,const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio)
{
  int code;
  pthread_t tmp;
  struct sys_thread *st = NULL;
  LWIP_UNUSED_ARG(name);
  LWIP_UNUSED_ARG(stacksize);
  LWIP_UNUSED_ARG(prio);

  code = pthread_create(&tmp,
                        NULL,
                        (void *(*)(void *))
                                function,
                        arg);

  if (0 == code) {
    st = introduce_thread(tmp);
  }

  if (NULL == st) {
    LWIP_DEBUGF(LWIP_DBG_ON, ("sys_thread_new: call pthread_create failed %d, st = 0x%lx error:%s",
            code, (unsigned long)st, strerror(errno)));
    return NULL;
  }
  st->instance = instance;
  return st;
}

#if SYS_THREAD_FREE_FUNC
void
sys_thread_free_self()
{
	  struct sys_thread *thread,*prev;
	  pthread_t id = pthread_self();
	  struct sys_context *pstSysContext = get_sys_context();
	
	  LWIP_DEBUGF(LWIP_DBG_ON, ("sys_thread_free_self: free id %u",id));
	  if (pstSysContext != NULL) {
#if !SYS_ARCH_REPLACE
			  pthread_mutex_lock(&pstSysContext->threads_mutex);
			  thread = pstSysContext->threads;
#else
			  rte_spinlock_lock(&threads_mutex);
			  thread = threads;
#endif
				prev = thread;
				while(thread)
				{
					if (thread->pthread == id)
					{
						if (prev != thread)
						{
							prev->next = thread->next;
						}else
						{
#if !SYS_ARCH_REPLACE
						  pstSysContext->threads = thread->next;
#else
						  threads = thread->next;
#endif
						}
						LWIP_DEBUGF(LWIP_DBG_ON, ("sys_thread_free_self: free id %u OK",id));
						free(thread);
						break;
					}
					prev = thread;
					thread = thread->next;
				}
	  
#if !SYS_ARCH_REPLACE
				  pthread_mutex_unlock(&pstSysContext->threads_mutex);
#else
				  rte_spinlock_unlock(&threads_mutex);
#endif
	
	  }
	
	  return ;

}

void
sys_thread_free_all()
{
  struct sys_thread *thread,*next;
  struct sys_context *pstSysContext = get_sys_context();

  if (pstSysContext != NULL){
#if !SYS_ARCH_REPLACE
		  pthread_mutex_lock(&pstSysContext->threads_mutex);
		  thread = pstSysContext->threads;
#else
		  rte_spinlock_lock(&threads_mutex);
		  thread = threads;
#endif

			while(thread)
			{
				next = thread->next;
				free(thread);
				thread = next;
			}
  
#if !SYS_ARCH_REPLACE
      pstSysContext->threads = NULL;
			  pthread_mutex_unlock(&pstSysContext->threads_mutex);
#else
      threads = NULL;
			  rte_spinlock_unlock(&threads_mutex);
#endif

  }

  return ;
}
#endif

#if !SYS_ARCH_REPLACE

/*-----------------------------------------------------------------------------------*/
err_t
sys_mbox_new(struct sys_mbox **mb, int size)
{
  struct sys_mbox *mbox;

  if(size <= 0)
    size = DEFAULT_SYS_MBOX_SIZE;
  mbox = (struct sys_mbox *)malloc(sizeof(struct sys_mbox));
  if (mbox == NULL) {
    return ERR_MEM;
  }
  mbox->size = size;
  mbox->msgs = (void **)malloc(sizeof(void *) * size);
  if(mbox->msgs == NULL){
    free(mbox);
    return ERR_MEM;
  }
  mbox->first = mbox->last = 0;
  mbox->not_empty = sys_sem_new_internal(0);
  if(mbox->not_empty == NULL){
      free(mbox);
      return ERR_MEM;
  }
  mbox->not_full = sys_sem_new_internal(0);
  if(mbox->not_full == NULL){
      free(mbox->not_empty);
      free(mbox);
      return ERR_MEM;
  }
  mbox->mutex = sys_sem_new_internal(1);
  if(mbox->not_full == NULL){
      free(mbox->not_empty);
      free(mbox->not_full);
      free(mbox);
      return ERR_MEM;
  }
  mbox->wait_send = 0;

  SYS_STATS_INC_USED(mbox);
  *mb = mbox;
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_free(struct sys_mbox **mb)
{
  if ((mb != NULL) && (*mb != SYS_MBOX_NULL)) {
    struct sys_mbox *mbox = *mb;
    SYS_STATS_DEC(mbox.used);
    sys_arch_sem_wait(&mbox->mutex, 0);

    sys_sem_free_internal(mbox->not_empty);
    sys_sem_free_internal(mbox->not_full);
    sys_sem_free_internal(mbox->mutex);
    mbox->not_empty = mbox->not_full = mbox->mutex = NULL;
    /*  LWIP_DEBUGF("sys_mbox_free: mbox 0x%lx\n", mbox); */
    free(mbox->msgs);
    free(mbox);
  }
}
/*-----------------------------------------------------------------------------------*/
err_t
sys_mbox_trypost(struct sys_mbox **mb, void *msg)
{
  u8_t first;
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  sys_arch_sem_wait(&mbox->mutex, 0);

  LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_trypost: mbox %p msg %p\n",
          (void *)mbox, (void *)msg));

  if ((mbox->last + 1) >= (mbox->first + mbox->size)) {
    int new_size = mbox->size * 2;
    void **new_msgs = NULL;
    if(new_size <= MAX_SYS_MBOX_SIZE)
      new_msgs = (void **)realloc(mbox->msgs, sizeof(void *) * new_size);
    if(new_msgs == NULL){
      sys_sem_signal(&mbox->mutex);
      return ERR_MEM;
    }else{
      if((mbox->last % mbox->size) < (mbox->first % mbox->size)){
        memcpy(&new_msgs[mbox->size], &new_msgs[0],
          sizeof(void *) * ((mbox->last % mbox->size)  + 1));
        mbox->last = (mbox->last % mbox->size) + mbox->size;
      }else
        mbox->last = mbox->last % mbox->size;
      mbox->first = mbox->first % mbox->size;
      mbox->msgs = new_msgs;
      mbox->size = new_size;
    }
  }

  mbox->msgs[mbox->last % mbox->size] = msg;

  if (mbox->last == mbox->first) {
    first = 1;
  } else {
    first = 0;
  }

  mbox->last++;

  if (first) {
    sys_sem_signal(&mbox->not_empty);
  }

  sys_sem_signal(&mbox->mutex);

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
void
sys_mbox_post(struct sys_mbox **mb, void *msg)
{
  u8_t first;
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  sys_arch_sem_wait(&mbox->mutex, 0);

  LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_post: mbox %p msg %p\n", (void *)mbox, (void *)msg));

  while ((mbox->last + 1) >= (mbox->first + mbox->size)) {
    mbox->wait_send++;
    sys_sem_signal(&mbox->mutex);
    sys_arch_sem_wait(&mbox->not_full, 0);
    sys_arch_sem_wait(&mbox->mutex, 0);
    mbox->wait_send--;
  }

  mbox->msgs[mbox->last % mbox->size] = msg;

  if (mbox->last == mbox->first) {
    first = 1;
  } else {
    first = 0;
  }

  mbox->last++;

  if (first) {
    sys_sem_signal(&mbox->not_empty);
  }

  sys_sem_signal(&mbox->mutex);
}
/*-----------------------------------------------------------------------------------*/
u32_t
sys_arch_mbox_tryfetch(struct sys_mbox **mb, void **msg)
{
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  sys_arch_sem_wait(&mbox->mutex, 0);

  if (mbox->first == mbox->last) {
    sys_sem_signal(&mbox->mutex);
    return SYS_MBOX_EMPTY;
  }

  if (msg != NULL) {
    LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_tryfetch: mbox %p msg %p\n", (void *)mbox, *msg));
    *msg = mbox->msgs[mbox->first % mbox->size];
  }
  else{
    LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_tryfetch: mbox %p, null msg\n", (void *)mbox));
  }

  mbox->first++;

  if (mbox->wait_send) {
    sys_sem_signal(&mbox->not_full);
  }

  sys_sem_signal(&mbox->mutex);

  return 0;
}
/*-----------------------------------------------------------------------------------*/
u32_t
sys_arch_mbox_fetch(struct sys_mbox **mb, void **msg, u32_t timeout)
{
  u32_t time_needed = 0;
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  /* The mutex lock is quick so we don't bother with the timeout
     stuff here. */
  sys_arch_sem_wait(&mbox->mutex, 0);

  while (mbox->first == mbox->last) {
    sys_sem_signal(&mbox->mutex);

    /* We block while waiting for a mail to arrive in the mailbox. We
       must be prepared to timeout. */
    if (timeout != 0) {
      time_needed = sys_arch_sem_wait(&mbox->not_empty, timeout);

      if (time_needed == SYS_ARCH_TIMEOUT) {
        return SYS_ARCH_TIMEOUT;
      }
    } else {
      sys_arch_sem_wait(&mbox->not_empty, 0);
    }

    sys_arch_sem_wait(&mbox->mutex, 0);
  }

  if (msg != NULL) {
    LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_fetch: mbox %p msg %p\n", (void *)mbox, *msg));
    *msg = mbox->msgs[mbox->first % mbox->size];
  }
  else{
    LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_fetch: mbox %p, null msg\n", (void *)mbox));
  }

  mbox->first++;

  if (mbox->wait_send) {
    sys_sem_signal(&mbox->not_full);
  }

  sys_sem_signal(&mbox->mutex);

  return time_needed;
}
/*-----------------------------------------------------------------------------------*/
static struct sys_sem *
sys_sem_new_internal(u8_t count)
{
  struct sys_sem *sem;

  sem = (struct sys_sem *)malloc(sizeof(struct sys_sem));
  if (sem != NULL) {
    sem->c = count;
    pthread_cond_init(&(sem->cond), NULL);
    pthread_mutex_init(&(sem->mutex), NULL);
  }
  return sem;
}
/*-----------------------------------------------------------------------------------*/
err_t
sys_sem_new(struct sys_sem **sem, u8_t count)
{
  SYS_STATS_INC_USED(sem);
  *sem = sys_sem_new_internal(count);
  if (*sem == NULL) {
    return ERR_MEM;
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
static u32_t
cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex, u32_t timeout)
{
  time_t tdiff;
  time_t sec, usec;
  struct timeval rtime1, rtime2;
  struct timespec ts;
  int retval;

  if (timeout > 0) {
    /* Get a timestamp and add the timeout value. */
    gettimeofday(&rtime1, NULL);
    sec = rtime1.tv_sec;
    usec = rtime1.tv_usec;
    usec += timeout % 1000 * 1000;
    sec += (int)(timeout / 1000) + (int)(usec / 1000000);
    usec = usec % 1000000;
    ts.tv_nsec = usec * 1000;
    ts.tv_sec = sec;

    retval = pthread_cond_timedwait(cond, mutex, &ts);

    if (retval == ETIMEDOUT) {
      return SYS_ARCH_TIMEOUT;
    } else {
      /* Calculate for how long we waited for the cond. */
      gettimeofday(&rtime2, NULL);
      tdiff = (rtime2.tv_sec - rtime1.tv_sec) * 1000 +
              (rtime2.tv_usec - rtime1.tv_usec) / 1000;

      if (tdiff <= 0) {
        return 0;
      }
      return (u32_t)tdiff;
    }
  } else {
    pthread_cond_wait(cond, mutex);
    return 0;
  }
}
/*-----------------------------------------------------------------------------------*/
u32_t
sys_arch_sem_wait(struct sys_sem **s, u32_t timeout)
{
  u32_t time_needed = 0;
  struct sys_sem *sem;
  LWIP_ASSERT("invalid sem", (s != NULL) && (*s != NULL));
  sem = *s;

  pthread_mutex_lock(&(sem->mutex));
  while (sem->c <= 0) {
    if (timeout > 0) {
      time_needed = cond_wait(&(sem->cond), &(sem->mutex), timeout);

      if (time_needed == SYS_ARCH_TIMEOUT) {
        pthread_mutex_unlock(&(sem->mutex));
        return SYS_ARCH_TIMEOUT;
      }
      /*      pthread_mutex_unlock(&(sem->mutex));
              return time_needed; */
    } else {
      cond_wait(&(sem->cond), &(sem->mutex), 0);
    }
  }
  sem->c--;
  pthread_mutex_unlock(&(sem->mutex));
  return (u32_t)time_needed;
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_signal(struct sys_sem **s)
{
  struct sys_sem *sem;
  LWIP_ASSERT("invalid sem", (s != NULL) && (*s != NULL));
  sem = *s;

  pthread_mutex_lock(&(sem->mutex));
  sem->c++;

  if (sem->c > 1) {
    sem->c = 1;
  }

  pthread_cond_broadcast(&(sem->cond));
  pthread_mutex_unlock(&(sem->mutex));
}
/*-----------------------------------------------------------------------------------*/
static void
sys_sem_free_internal(struct sys_sem *sem)
{
  pthread_cond_destroy(&(sem->cond));
  pthread_mutex_destroy(&(sem->mutex));
  free(sem);
}
/*-----------------------------------------------------------------------------------*/
void
sys_sem_free(struct sys_sem **sem)
{
  if ((sem != NULL) && (*sem != SYS_SEM_NULL)) {
    SYS_STATS_DEC(sem.used);
    sys_sem_free_internal(*sem);
  }
}
#else
void    sys_sem_free(struct sys_sem **sem){
    if(sem != NULL && *sem != NULL){
        sys_sem_free_internal(*sem);
        *sem = NULL;
    }
    return;
}

void    sys_sem_signal(struct sys_sem **s){
    if(s!= NULL && *s!= NULL){
        sys_sem_signal_internal(*s);
    }
}

u32_t   sys_arch_sem_wait(struct sys_sem **s, u32_t timeout){
    int ret = 0;
    if(s != NULL && *s!= NULL){
        ret = sys_sem_wait_timeout_internal(*s,&timeout);
        return ret;
    }
    return 0;
}

err_t   sys_sem_new(struct sys_sem **sem, u8_t count){
    if(sem != NULL){
        *sem = sys_sem_new_internal(count);
        if(*sem == NULL){
            return ERR_MEM;
        }
        if(!count){
            rte_spinlock_lock(*sem);
        }
        return ERR_OK;
    }
    return ERR_ARG;
}

u32_t   sys_arch_mbox_fetch(struct sys_mbox **mb, void **msg, u32_t timeout){
    if( mb != NULL && *mb != NULL) {
        *msg = sys_queue_pop_internal(*mb,&timeout,0);
        return 0;
    }
    return 1;
}

u32_t   sys_arch_mbox_tryfetch(struct sys_mbox **mb, void **msg){
    if( mb != NULL && *mb != NULL) {
        *msg = sys_queue_pop_internal(*mb,NULL,1);
        if(*msg == NULL){
            return SYS_ARCH_TIMEOUT;
        }
        else return ERR_OK;
    }
    return ERR_ARG;
}

void    sys_mbox_post(struct sys_mbox **mb, void *msg){
    int ret = 0;
    if( mb != NULL && *mb != NULL){
        while(ret == 0){
            if(mb != NULL && *mb != NULL){
                ret = sys_queue_push(*mb,msg);
            }
            else break;
        }
    }
}

err_t   sys_mbox_trypost(struct sys_mbox **mb, void *msg){
    int ret = 0;
    if( mb != NULL && *mb != NULL){
        ret = sys_queue_push_internal(*mb,msg,1);
        if(ret == 0){
            return ERR_GENERIC;//the queue is full
        }
        return ERR_OK;
    }
    return ERR_ARG;
}

void    sys_mbox_free(struct sys_mbox **mb){
    if(mb != NULL && *mb != NULL){
        sys_queue_destory(*mb);
        *mb = NULL;
    }
}

err_t   sys_mbox_new(struct sys_mbox **mb, int size){
    int tid = gettid();
    int pid = getpid();
    char name[8]="0,0";
    if(mb == NULL)
        return ERR_ARG;
    //sprintf(name,"%d:%d",tid,pid);
    *mb = sys_queue_create(name,size);
    if(*mb != NULL){
        return ERR_OK;
    }
    return ERR_MEM;
}
#endif
#endif /* !NO_SYS */
struct sys_context *get_sys_context(void)
{
    struct lwip_instance *instance = (struct lwip_instance *)global_get_thread_instance();
    struct module_conext *pSysModuleContext;
	struct sys_context *pstSysContext = NULL;

	if(instance != NULL)
	{
	    pSysModuleContext = &instance->module_conext[CONTEXT_SYS_TYPE];
		pstSysContext = (struct sys_context *)pSysModuleContext->pCcontext;
	}
	return pstSysContext;
}

u32_t sys_now_base(void *instance)
{
  struct timeval tv, start_time;
  long sec, usec, msec;
  struct lwip_instance *pLwipInstance = (struct lwip_instance *)instance;
  struct module_conext *pSysModuleContext;
  struct sys_context *pstSysContext = NULL;
  /*struct sys_context *pstSysContext = get_sys_context();*/

  if(instance != NULL)
  {
	  pSysModuleContext = &pLwipInstance->module_conext[CONTEXT_SYS_TYPE];
	  pstSysContext = (struct sys_context *)pSysModuleContext->pCcontext;
  }

  
  gettimeofday(&tv, NULL);
  if(pstSysContext != NULL)
  {
     sec = (tv.tv_sec - pstSysContext->starttime.tv_sec);
     usec = (tv.tv_usec - pstSysContext->starttime.tv_usec);
  }
  else
  {  
     sec = (tv.tv_sec - g_starttime.tv_sec);
     usec =(tv.tv_usec - g_starttime.tv_usec);
  }
  msec = sec * 1000 + usec / 1000;

  return (u32_t)msec;
}


/*-----------------------------------------------------------------------------------*/
u32_t sys_now(void *instance)
{
#if 0
  struct timeval tv, start_time;
  long sec, usec, msec;
  struct lwip_instance *pLwipInstance = (struct lwip_instance *)instance;
  struct module_conext *pSysModuleContext;
  struct sys_context *pstSysContext = NULL;
  /*struct sys_context *pstSysContext = get_sys_context();*/

  if(instance != NULL)
  {
	  pSysModuleContext = &pLwipInstance->module_conext[CONTEXT_SYS_TYPE];
	  pstSysContext = (struct sys_context *)pSysModuleContext->pCcontext;
  }

  
  gettimeofday(&tv, NULL);
  if(pstSysContext != NULL)
  {
     sec = (tv.tv_sec - pstSysContext->starttime.tv_sec);
     usec = (tv.tv_usec - pstSysContext->starttime.tv_usec);
  }
  else
  {  
     sec = (tv.tv_sec - g_starttime.tv_sec);
     usec =(tv.tv_usec - g_starttime.tv_usec);
  }
  msec = sec * 1000 + usec / 1000;

  return (u32_t)msec;
#else
  return tickGet(instance);
#endif
}

void sys_deinit(struct module_conext *pSysModuleContext)
{
#if SYS_THREAD_FREE_FUNC
    sys_thread_free_all();
#endif
    FREE(pSysModuleContext->pCcontext);
}

/*-----------------------------------------------------------------------------------*/
void
sys_init(struct module_conext *pSysModuleContext)
{
  struct sys_context *pstSysContext;
  /*pthread_mutexattr_t mutex = PTHREAD_MUTEX_INITIALIZER;*/
  struct timespec tv;

  pSysModuleContext->pCcontext = malloc(sizeof(struct sys_context));
  pSysModuleContext->callback = (context_deinit_callback_fn)sys_deinit;
  pSysModuleContext->pArg_deinit = (void *)pSysModuleContext;
  memset(pSysModuleContext->pCcontext, 0x0,sizeof(struct sys_context));
  pstSysContext = (struct sys_context *)pSysModuleContext->pCcontext;


  pstSysContext->threads = NULL;
  pthread_mutex_init(&pstSysContext->threads_mutex, NULL);

#if SYS_LIGHTWEIGHT_PROT
  pthread_mutex_init(&pstSysContext->lwprot_mutex,NULL);
  pstSysContext->lwprot_thread = (pthread_t)0xDEAD;
  pstSysContext->lwprot_count = 0;
#endif


  gettimeofday(&pstSysContext->starttime, NULL);
  if(g_starttime.tv_sec == 0 && g_starttime.tv_usec == 0)
  {
  	gettimeofday(&g_starttime, NULL);
  }

  LWIP_DEBUGF(TIMERS_DEBUG, ("sys_init gettimeofday sec=%d usec=%d\n",
		  pstSysContext->starttime.tv_sec,pstSysContext->starttime.tv_usec));

  clock_gettime(CLOCK_REALTIME, &tv);
  LWIP_DEBUGF(TIMERS_DEBUG, ("sys_init clock_gettime sec=%d\n",
		  tv.tv_sec));
}
/*-----------------------------------------------------------------------------------*/
#if SYS_LIGHTWEIGHT_PROT
/** sys_prot_t sys_arch_protect(void)

This optional function does a "fast" critical region protection and returns
the previous protection level. This function is only called during very short
critical regions. An embedded system which supports ISR-based drivers might
want to implement this function by disabling interrupts. Task-based systems
might want to implement this by using a mutex or disabling tasking. This
function should support recursive calls from the same task or interrupt. In
other words, sys_arch_protect() could be called while already protected. In
that case the return value indicates that it is already protected.

sys_arch_protect() is only required if your port is supporting an operating
system.
*/
sys_prot_t
sys_arch_protect(void)
{
	struct sys_context *pstSysContext = get_sys_context();

    if(pstSysContext == NULL) {
        return 1;
    }
    /* Note that for the UNIX port, we are using a lightweight mutex, and our
     * own counter (which is locked by the mutex). The return code is not actually
     * used. */
    if (pstSysContext->lwprot_thread != pthread_self())
    {
#if !SYS_ARCH_REPLACE
        /* We are locking the mutex where it has not been locked before *
        * or is being locked by another thread */
        pthread_mutex_lock(&pstSysContext->lwprot_mutex);
#else
        rte_spinlock_lock(&pstSysContext->lwprot_mutex);
#endif
        pstSysContext->lwprot_thread = pthread_self();
        pstSysContext->lwprot_count = 1;
    }
    else
        /* It is already locked by THIS thread */
        pstSysContext->lwprot_count++;
    return 0;
}
/*-----------------------------------------------------------------------------------*/
/** void sys_arch_unprotect(sys_prot_t pval)

This optional function does a "fast" set of critical region protection to the
value specified by pval. See the documentation for sys_arch_protect() for
more information. This function is only required if your port is supporting
an operating system.
*/
void
sys_arch_unprotect(sys_prot_t pval)
{
	struct sys_context *pstSysContext = get_sys_context();

    if(pstSysContext == NULL)
    {
        return;
    }


    LWIP_UNUSED_ARG(pval);
    if (pstSysContext->lwprot_thread == pthread_self())
    {
        if (--pstSysContext->lwprot_count == 0)
        {
            pstSysContext->lwprot_thread = (pthread_t) 0xDEAD;
#if !SYS_ARCH_REPLACE
            pthread_mutex_unlock(&pstSysContext->lwprot_mutex);
#else
            rte_spinlock_unlock(&pstSysContext->lwprot_mutex);
#endif
        }
    }
}
#endif /* SYS_LIGHTWEIGHT_PROT */

/*-----------------------------------------------------------------------------------*/

#ifndef MAX_JIFFY_OFFSET
#define MAX_JIFFY_OFFSET ((~0U >> 1)-1)
#endif

#ifndef HZ
#define HZ 100
#endif

u32_t
sys_jiffies(void)
{
  struct timeval tv,start_time;
  unsigned long sec;
  long usec;
  struct sys_context *pstSysContext = get_sys_context();

  gettimeofday(&tv,NULL);
  if(pstSysContext != NULL)
  {
      sec = tv.tv_sec - pstSysContext->starttime.tv_sec;
  }
  else
  {
      sec = tv.tv_sec - g_starttime.tv_sec;
  }
  usec = tv.tv_usec;

  if (sec >= (MAX_JIFFY_OFFSET / HZ))
    return MAX_JIFFY_OFFSET;
  usec += 1000000L / HZ - 1;
  usec /= 1000000L / HZ;
  return HZ * sec + usec;
}

#if PPP_DEBUG

#include <stdarg.h>

void ppp_trace(int level, const char *format, ...)
{
  va_list args;

  (void)level;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}
#endif
