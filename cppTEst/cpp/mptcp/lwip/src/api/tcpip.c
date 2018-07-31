/**
 * @file
 * Sequential API Main thread module
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#if !NO_SYS /* don't build if not configured for use in lwipopts.h */
#include <pthread.h>
#include "lwip/priv/tcpip_priv.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "netif/ethernet.h"
#if LWIP_MPTCP_SUPPORT
#include "lwip/mptcp_fin.h"
#endif
#include "lwip/tcp_common_context.h"
#include "lwip/module.h"
#include "../../../../tools/tools.h"

#define TCPIP_MSG_VAR_REF(name)     API_VAR_REF(name)
#define TCPIP_MSG_VAR_DECLARE(name) API_VAR_DECLARE(struct tcpip_msg, name)
#define TCPIP_MSG_VAR_ALLOC(name)   API_VAR_ALLOC(struct tcpip_msg, MEMP_TCPIP_MSG_API, name, ERR_MEM)
#define TCPIP_MSG_VAR_FREE(name)    API_VAR_FREE(MEMP_TCPIP_MSG_API, name)

/* global variables */
/*
static tcpip_init_done_fn tcpip_init_done;
static void *tcpip_init_done_arg;
static sys_mbox_t mbox;
*/
#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
extern u32_t  netpacketnumber;
extern u32_t  netinputlen;
extern u32_t  natpacketnumber;
extern u32_t  natinputlen;
extern unsigned  long nathandletime;
extern unsigned  long nethandletime;
extern u32_t msg_api_number;
extern unsigned  long msg_api_handletime;
extern unsigned  long lwipstack_worktime;
extern unsigned  long lwipstack_sleeptime;
#endif

#if LWIP_TCPIP_CORE_LOCKING
/** The global semaphore to lock the stack. */
/*sys_mutex_t lock_tcpip_core;*/
#endif /* LWIP_TCPIP_CORE_LOCKING */

#if LWIP_TIMERS
/* wait for a message, timeouts are processed while waiting */
#define TCPIP_MBOX_FETCH(timer_module,mbox, msg) sys_timeouts_mbox_fetch(timer_module, mbox, msg)
#else /* LWIP_TIMERS */
/* wait for a message with timers disabled (e.g. pass a timer-check trigger into tcpip_thread) */
#define TCPIP_MBOX_FETCH(timer_module,mbox, msg) sys_mbox_fetch(mbox, msg)
#endif /* LWIP_TIMERS */

static void tcpip_thread_handle_msg(void *instance,struct tcpip_msg *msg);

/**
 * The main lwIP thread. This thread has exclusive access to lwIP core functions
 * (unless access to them is not locked). Other threads communicate with this
 * thread using message boxes.
 *
 * It also starts all the timers to make sure they are running in the right
 * thread context.
 *
 * @param arg unused argument
 */
static void*
tcpip_thread(void *arg)
{
  struct tcpip_msg *msg;
  /*LWIP_UNUSED_ARG(arg);*/
  struct tcp_context *pTcpContext;
  struct module_conext *pTcpModuleContext = (struct module_conext *)arg;
  struct module_conext *timer_module;
  void *instance = (void *)get_instance_context(CONTEXT_TCP_TYPE,pTcpModuleContext);

  global_set_thread_instance(instance);
  pTcpContext = (struct tcp_context *)(pTcpModuleContext->pCcontext);
  if (pTcpContext->tcpip_init_done != NULL) {
    pTcpContext->tcpip_init_done(pTcpContext->tcpip_init_done_arg);
  }
  LOCK_TCPIP_CORE();
  timer_module = get_module_context(CONTEXT_TCP_TYPE,pTcpModuleContext,CONTEXT_TIMER_TYPE);
  char name[40]={0};
  sprintf(name,"tcpip_thread:%d",get_instance_logic_id(instance));
  setThreadName(name);
  while (pTcpContext->exitFlag) {                          /* MAIN Loop */
    UNLOCK_TCPIP_CORE();
    LWIP_TCPIP_THREAD_ALIVE();
#if LWIP_MPTCP_SUPPORT
    mptcp_fin_close_candidate_check(instance);
#endif
    /* wait for a message, timeouts are processed while waiting */
    TCPIP_MBOX_FETCH(timer_module,&pTcpContext->mbox, (void **)&msg);
    LOCK_TCPIP_CORE();
    if (msg == NULL) {
      LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: invalid message: NULL\n"));
      LWIP_ASSERT("tcpip_thread: invalid message", 0);
      continue;
    }
    tcpip_thread_handle_msg(instance,msg);
  }
#if SYS_THREAD_FREE_FUNC
  extern void sys_thread_free_self();
  sys_thread_free_self();
#endif
  pthread_detach(pthread_self());  //to avoid thread resource leak
  return NULL;
}

/* Handle a single tcpip_msg
 * This is in its own function for access by tests only.
 */
static void
tcpip_thread_handle_msg(void *instance,struct tcpip_msg *msg)
{
  switch (msg->type) {
#if !LWIP_TCPIP_CORE_LOCKING
  case TCPIP_MSG_API:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: API message %p\n", (void *)msg));
    msg->msg.api_msg.function(msg->msg.api_msg.msg);
#if LWIP_MPTCP_SUPPORT
    TCPIP_MSG_VAR_FREE(msg);
#endif
    break;
  case TCPIP_MSG_API_CALL:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: API CALL message %p\n", (void *)msg));
    msg->msg.api_call.arg->err = msg->msg.api_call.function(msg->msg.api_call.arg);
    sys_sem_signal(msg->msg.api_call.sem);
    break;
#endif /* !LWIP_TCPIP_CORE_LOCKING */

#if !LWIP_TCPIP_CORE_LOCKING_INPUT
  case TCPIP_MSG_INPKT:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: PACKET %p\n", (void *)msg));
    msg->msg.inp.input_fn(msg->msg.inp.p, msg->msg.inp.netif);
    memp_free(MEMP_TCPIP_MSG_INPKT, msg);
    break;
#endif /* !LWIP_TCPIP_CORE_LOCKING_INPUT */

#if LWIP_TCPIP_TIMEOUT && LWIP_TIMERS
  case TCPIP_MSG_TIMEOUT:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: TIMEOUT %p\n", (void *)msg));
    sys_timeout(msg->msg.tmo.instance, msg->msg.tmo.msecs, msg->msg.tmo.h, msg->msg.tmo.arg);
    memp_free(instance,MEMP_TCPIP_MSG_API, msg);
    break;
  case TCPIP_MSG_UNTIMEOUT:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: UNTIMEOUT %p\n", (void *)msg));
    sys_untimeout(msg->msg.tmo.instance, msg->msg.tmo.h, msg->msg.tmo.arg);
    memp_free(instance,MEMP_TCPIP_MSG_API, msg);
    break;
#endif /* LWIP_TCPIP_TIMEOUT && LWIP_TIMERS */

  case TCPIP_MSG_CALLBACK:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: CALLBACK %p\n", (void *)msg));
    msg->msg.cb.function(msg->msg.cb.ctx);
    memp_free(MEMP_TCPIP_MSG_API, msg);
    break;

  case TCPIP_MSG_CALLBACK_STATIC:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: CALLBACK_STATIC %p\n", (void *)msg));
    msg->msg.cb.function(msg->msg.cb.ctx);
    break;

  default:
    LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: invalid message: %d\n", msg->type));
    //LWIP_ASSERT("tcpip_thread: invalid message", 0);
    break;
  }
}

#ifdef TCPIP_THREAD_TEST
/** Work on queued items in single-threaded test mode */
int
tcpip_thread_poll_one(void)
{
  int ret = 0;
  struct tcpip_msg *msg;

  /* wait for a message, timeouts are processed while waiting */
  if (sys_arch_mbox_tryfetch(&mbox, (void **)&msg) != SYS_ARCH_TIMEOUT) {
    LOCK_TCPIP_CORE();
    if (msg != NULL) {
      tcpip_thread_handle_msg(msg);
      ret = 1;
    }
    UNLOCK_TCPIP_CORE();
  }
  return ret;
}
#endif

/**
 * Pass a received packet to tcpip_thread for input processing
 *
 * @param p the received packet
 * @param inp the network interface on which the packet was received
 * @param input_fn input function to call
 */
err_t
tcpip_inpkt(struct pbuf *p, struct netif *inp, netif_input_fn input_fn)
{
#if LWIP_TCPIP_CORE_LOCKING_INPUT
  err_t ret;
  LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_inpkt: PACKET %p/%p\n", (void *)p, (void *)inp));
  LOCK_TCPIP_CORE();
  ret = input_fn(p, inp);
  UNLOCK_TCPIP_CORE();
  return ret;
#else /* LWIP_TCPIP_CORE_LOCKING_INPUT */
  struct tcpip_msg *msg;
  struct tcp_context *pTcpContext;
  struct module_conext *pTcpModuleContext;
  struct lwip_instance *pLwipInstance = (struct lwip_instance *)inp->instance;

  pTcpModuleContext = &pLwipInstance->module_conext[CONTEXT_TCP_TYPE];
  pTcpContext = (struct tcp_context *)pTcpModuleContext->pCcontext;

  LWIP_ASSERT("Invalid mbox", sys_mbox_valid_val(pTcpContext->mbox));

  msg = (struct tcpip_msg *)memp_malloc(MEMP_TCPIP_MSG_INPKT);
  if (msg == NULL) {
    return ERR_MEM;
  }

  msg->type = TCPIP_MSG_INPKT;
  msg->msg.inp.p = p;
  msg->msg.inp.netif = inp;
  msg->msg.inp.input_fn = input_fn;
  
  if(p->len < 40) /*ip header + tcp header > 40*/
  { 
	  LWIP_ASSERT("Invalid pbuf packet", (p->len >= 40));
	  memp_free(MEMP_TCPIP_MSG_INPKT, msg);
	  return ERR_BUF;
  }
  
  if (sys_mbox_trypost(&pTcpContext->mbox, msg) != ERR_OK) {
    memp_free(MEMP_TCPIP_MSG_INPKT, msg);
    return ERR_MEM;
  }
  return ERR_OK;
#endif /* LWIP_TCPIP_CORE_LOCKING_INPUT */
}

/**
 * @ingroup lwip_os
 * Pass a received packet to tcpip_thread for input processing with
 * ethernet_input or ip_input. Don't call directly, pass to netif_add()
 * and call netif->input().
 *
 * @param p the received packet, p->payload pointing to the Ethernet header or
 *          to an IP header (if inp doesn't have NETIF_FLAG_ETHARP or
 *          NETIF_FLAG_ETHERNET flags)
 * @param inp the network interface on which the packet was received
 */
err_t
tcpip_input(struct pbuf *p, struct netif *inp)
{
#if LWIP_ETHERNET
  if (inp->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET)) {
    return tcpip_inpkt(p, inp, ethernet_input);
  } else
#endif /* LWIP_ETHERNET */
  return tcpip_inpkt(p, inp, ip_input);
}

/**
 * Call a specific function in the thread context of
 * tcpip_thread for easy access synchronization.
 * A function called in that way may access lwIP core code
 * without fearing concurrent access.
 *
 * @param function the function to call
 * @param ctx parameter passed to f
 * @param block 1 to block until the request is posted, 0 to non-blocking mode
 * @return ERR_OK if the function was called, another err_t if not
 */
err_t
tcpip_callback_with_block(struct lwip_instance *pLwipInstance, tcpip_callback_fn function, void *ctx, u8_t block)
{
  struct tcpip_msg *msg;
  struct module_conext *tcp_module_context = &pLwipInstance->module_conext[CONTEXT_TCP_TYPE];
  struct tcp_context *pTcpContext = (struct tcp_context *)tcp_module_context->pCcontext;
  
  LWIP_ASSERT("Invalid mbox", sys_mbox_valid_val(pTcpContext->mbox));

  msg = (struct tcpip_msg *)memp_malloc(MEMP_TCPIP_MSG_API);
  if (msg == NULL) {
    return ERR_MEM;
  }

  msg->type = TCPIP_MSG_CALLBACK;
  msg->msg.cb.function = function;
  msg->msg.cb.ctx = ctx;
  if (block) {
    sys_mbox_post(&pTcpContext->mbox, msg);
  } else {
    if (sys_mbox_trypost(&pTcpContext->mbox, msg) != ERR_OK) {
      memp_free(MEMP_TCPIP_MSG_API, msg);
      return ERR_MEM;
    }
  }
  return ERR_OK;
}

#if LWIP_TCPIP_TIMEOUT && LWIP_TIMERS
/**
 * call sys_timeout in tcpip_thread
 *
 * @param msecs time in milliseconds for timeout
 * @param h function to be called on timeout
 * @param arg argument to pass to timeout function h
 * @return ERR_MEM on memory error, ERR_OK otherwise
 */
err_t
tcpip_timeout(void *tcp_module_context, u32_t msecs, sys_timeout_handler h, void *arg)
{
  struct tcpip_msg *msg;
  struct tcp_context *pTcpContext = (struct tcp_context *)(((struct module_conext *)tcp_module_context)->pCcontext);

  LWIP_ASSERT("Invalid mbox", sys_mbox_valid_val(mbox));

  msg = (struct tcpip_msg *)memp_malloc(MEMP_TCPIP_MSG_API);
  if (msg == NULL) {
    return ERR_MEM;
  }

  msg->type = TCPIP_MSG_TIMEOUT;
  msg->msg.tmo.msecs = msecs;
  msg->msg.tmo.h = h;
  msg->msg.tmo.arg = arg;
  sys_mbox_post(&tcp_context->mbox, msg);
  return ERR_OK;
}

/**
 * call sys_untimeout in tcpip_thread
 *
 * @param h function to be called on timeout
 * @param arg argument to pass to timeout function h
 * @return ERR_MEM on memory error, ERR_OK otherwise
 */
err_t
tcpip_untimeout(void *tcp_module_context, sys_timeout_handler h, void *arg)
{
  struct tcpip_msg *msg;
  struct tcp_context *pTcpContext = (struct tcp_context *)(((struct module_conext *)tcp_module_context)->pCcontext);

  LWIP_ASSERT("Invalid mbox", sys_mbox_valid_val(mbox));

  msg = (struct tcpip_msg *)memp_malloc(MEMP_TCPIP_MSG_API);
  if (msg == NULL) {
    return ERR_MEM;
  }

  msg->type = TCPIP_MSG_UNTIMEOUT;
  msg->msg.tmo.h = h;
  msg->msg.tmo.arg = arg;
  sys_mbox_post(&pTcpContext->mbox, msg);
  return ERR_OK;
}
#endif /* LWIP_TCPIP_TIMEOUT && LWIP_TIMERS */


/**
 * Sends a message to TCPIP thread to call a function. Caller thread blocks on
 * on a provided semaphore, which ist NOT automatically signalled by TCPIP thread,
 * this has to be done by the user.
 * It is recommended to use LWIP_TCPIP_CORE_LOCKING since this is the way
 * with least runtime overhead.
 *
 * @param fn function to be called from TCPIP thread
 * @param apimsg argument to API function
 * @param sem semaphore to wait on
 * @return ERR_OK if the function was called, another err_t if not
 */
err_t
tcpip_send_msg_wait_sem(void *lwip_instance_context, tcpip_callback_fn fn, void *apimsg, sys_sem_t* sem)
{
   struct lwip_instance *pLwipInstance = (struct lwip_instance *)lwip_instance_context;
   struct module_conext *tcp_module_context = &pLwipInstance->module_conext[CONTEXT_TCP_TYPE];
   struct tcp_context *pTcpContext = (struct tcp_context *)tcp_module_context->pCcontext;

#if LWIP_TCPIP_CORE_LOCKING
  LWIP_UNUSED_ARG(sem);
  LOCK_TCPIP_CORE();
  fn(apimsg);
  UNLOCK_TCPIP_CORE();
  return ERR_OK;
#else /* LWIP_TCPIP_CORE_LOCKING */
  TCPIP_MSG_VAR_DECLARE(msg);

#if LWIP_PERFORMANCE_IMPROVE_RECV_NOWAIT
  if(sem != NULL)
#endif
  LWIP_ASSERT("semaphore not initialized", sys_sem_valid(sem));
  LWIP_ASSERT("Invalid mbox", sys_mbox_valid_val(pTcpContext->mbox));

  TCPIP_MSG_VAR_ALLOC(msg);
  TCPIP_MSG_VAR_REF(msg).type = TCPIP_MSG_API;
  TCPIP_MSG_VAR_REF(msg).msg.api_msg.function = fn;
  TCPIP_MSG_VAR_REF(msg).msg.api_msg.msg = apimsg;
  sys_mbox_post(&pTcpContext->mbox, &TCPIP_MSG_VAR_REF(msg));
#if LWIP_PERFORMANCE_IMPROVE_RECV_NOWAIT
  if(sem != NULL)
#endif
    sys_arch_sem_wait(sem, 0);
#if !LWIP_PERFORMANCE_IMPROVE_RECV_NOWAIT
  TCPIP_MSG_VAR_FREE(msg);
#endif
  return ERR_OK;
#endif /* LWIP_TCPIP_CORE_LOCKING */
}

/**
 * Synchronously calls function in TCPIP thread and waits for its completion.
 * It is recommended to use LWIP_TCPIP_CORE_LOCKING (preferred) or
 * LWIP_NETCONN_SEM_PER_THREAD. 
 * If not, a semaphore is created and destroyed on every call which is usually
 * an expensive/slow operation.
 * @param fn Function to call
 * @param call Call parameters
 * @return Return value from tcpip_api_call_fn
 */
err_t
tcpip_api_call(void *lwip_instance_context, tcpip_api_call_fn fn, struct tcpip_api_call_data *call)
{
  struct lwip_instance *pLwipInstance = (struct lwip_instance *)lwip_instance_context;
  struct module_conext *tcp_module_context = &pLwipInstance->module_conext[CONTEXT_TCP_TYPE];
  struct tcp_context *pTcpContext = (struct tcp_context *)tcp_module_context->pCcontext;

#if LWIP_TCPIP_CORE_LOCKING
  err_t err;
  LOCK_TCPIP_CORE();
  err = fn(call);
  UNLOCK_TCPIP_CORE();
  return err;
#else /* LWIP_TCPIP_CORE_LOCKING */
  TCPIP_MSG_VAR_DECLARE(msg);

#if !LWIP_NETCONN_SEM_PER_THREAD
  err_t err = sys_sem_new(&call->sem, 0);
  if (err != ERR_OK) {
    return err;
  }
#endif /* LWIP_NETCONN_SEM_PER_THREAD */

  LWIP_ASSERT("Invalid mbox", sys_mbox_valid_val(pTcpContext->mbox));

  TCPIP_MSG_VAR_ALLOC(msg);
  TCPIP_MSG_VAR_REF(msg).type = TCPIP_MSG_API_CALL;
  TCPIP_MSG_VAR_REF(msg).msg.api_call.arg = call;
  TCPIP_MSG_VAR_REF(msg).msg.api_call.function = fn;
#if LWIP_NETCONN_SEM_PER_THREAD
  TCPIP_MSG_VAR_REF(msg).msg.api_call.sem = LWIP_NETCONN_THREAD_SEM_GET();
#else /* LWIP_NETCONN_SEM_PER_THREAD */
  TCPIP_MSG_VAR_REF(msg).msg.api_call.sem = &call->sem;
#endif /* LWIP_NETCONN_SEM_PER_THREAD */
  sys_mbox_post(&pTcpContext->mbox, &TCPIP_MSG_VAR_REF(msg));
  sys_arch_sem_wait(TCPIP_MSG_VAR_REF(msg).msg.api_call.sem, 0);
  TCPIP_MSG_VAR_FREE(msg);

#if !LWIP_NETCONN_SEM_PER_THREAD
  sys_sem_free(&call->sem);
#endif /* LWIP_NETCONN_SEM_PER_THREAD */

  return call->err;
#endif /* LWIP_TCPIP_CORE_LOCKING */
}

/**
 * Allocate a structure for a static callback message and initialize it.
 * This is intended to be used to send "static" messages from interrupt context.
 *
 * @param function the function to call
 * @param ctx parameter passed to function
 * @return a struct pointer to pass to tcpip_trycallback().
 */
struct tcpip_callback_msg*
tcpip_callbackmsg_new(tcpip_callback_fn function, void *ctx)
{
  struct tcpip_msg *msg = (struct tcpip_msg *)memp_malloc(MEMP_TCPIP_MSG_API);
  if (msg == NULL) {
    return NULL;
  }
  msg->type = TCPIP_MSG_CALLBACK_STATIC;
  msg->msg.cb.function = function;
  msg->msg.cb.ctx = ctx;
  return (struct tcpip_callback_msg*)msg;
}

/**
 * Free a callback message allocated by tcpip_callbackmsg_new().
 *
 * @param msg the message to free
 */
void
tcpip_callbackmsg_delete(struct tcpip_callback_msg* msg)
{
  memp_free(MEMP_TCPIP_MSG_API, msg);
}

/**
 * Try to post a callback-message to the tcpip_thread mbox
 * This is intended to be used to send "static" messages from interrupt context.
 *
 * @param msg pointer to the message to post
 * @return sys_mbox_trypost() return code
 */
err_t
tcpip_trycallback(void *lwip_instance_context, struct tcpip_callback_msg* msg)
{	
  struct lwip_instance *pLwipInstance = (struct lwip_instance *)lwip_instance_context;
  struct module_conext *tcp_module_context = &pLwipInstance->module_conext[CONTEXT_TCP_TYPE];
  struct tcp_context *pTcpContext = (struct tcp_context *)tcp_module_context->pCcontext;

  LWIP_ASSERT("Invalid mbox", sys_mbox_valid_val(pTcpContext->mbox));
  return sys_mbox_trypost(&pTcpContext->mbox, msg);
}

/**
 * @ingroup lwip_os
 * Initialize this module:
 * - initialize all sub modules
 * - start the tcpip_thread
 *
 * @param initfunc a function to call when tcpip_thread is running and finished initializing
 * @param arg argument to pass to initfunc
 */
void
tcpip_init(struct lwip_instance *pstInstance,tcpip_init_done_fn initfunc, void *arg)
{
  struct module_conext *pTcpModuleContext = &pstInstance->module_conext[CONTEXT_TCP_TYPE];
  struct tcp_context *pTcpContext;
  char thread_name[32]= {0};

  
  lwip_init(pstInstance);

  pTcpContext = (struct tcp_context *)(pTcpModuleContext->pCcontext);
  pTcpContext->tcpip_init_done = initfunc;
  pTcpContext->tcpip_init_done_arg = arg;
  pTcpContext->exitFlag = 1;
  if (sys_mbox_new(&pTcpContext->mbox, TCPIP_MBOX_SIZE) != ERR_OK) {
    LWIP_ASSERT("failed to create tcpip_thread mbox", 0);
  }
#if LWIP_TCPIP_CORE_LOCKING
  if (sys_mutex_new(&pTcpContext->lock_tcpip_core) != ERR_OK) {
    LWIP_ASSERT("failed to create lock_tcpip_core", 0);
  }
#endif /* LWIP_TCPIP_CORE_LOCKING */

  sprintf(thread_name,"TCPIP_THREAD_NAME""-%p",pstInstance);
  sys_thread_t t = sys_thread_new((void *)pstInstance,NULL,thread_name, tcpip_thread, (void *)pTcpModuleContext, TCPIP_THREAD_STACKSIZE, TCPIP_THREAD_PRIO);
  upThreadPro(&t->pthread);
}

void tcpip_deinit(struct lwip_instance *pstInstance) {
    struct module_conext *pTcpModuleContext = &(pstInstance->module_conext[CONTEXT_TCP_TYPE]);
    struct tcp_context *pTcpContext = (struct tcp_context *)(pTcpModuleContext->pCcontext);
    /* Sleep 1s wait for all the proxy thread shut down.
     * It should be optimized later, sleep is not a good way.
     */
    //sys_msleep(1000);
    if(pTcpContext->mbox != NULL ) {
      struct tcpip_msg *msg;
      msg = (struct tcpip_msg *) memp_malloc(MEMP_TCPIP_MSG_API);
      if (msg != NULL) {
        msg->type = TCPIP_MSG_CALLBACK;
        msg->msg.cb.function = tcpip_exit;
        msg->msg.cb.ctx = (void *)pTcpModuleContext;
        sys_mbox_post(&pTcpContext->mbox, msg);
        //sys_msleep(100);
      }
    }
}

/**
 * This function only can be called in tcpip_thread_handle_message.
 */
void tcpip_exit(void *arg) {
    struct lwip_instance *pstInstance;
    struct module_conext* pTcpModuleContext = (struct module_conext*)arg;
    struct tcp_context *pTcpContext;

    if(pTcpModuleContext != NULL)
    {
        pstInstance = get_instance_context(CONTEXT_TCP_TYPE,pTcpModuleContext);
        pTcpContext = (struct tcp_context *)pTcpModuleContext->pCcontext;
        pTcpContext->exitFlag = 0;
#if LWIP_TCPIP_CORE_LOCKING
        sys_mutex_free(&pTcpContext->lock_tcpip_core);
#endif
        sys_mbox_free(&pTcpContext->mbox);
        lwip_deinit(pstInstance);
    }
    pthread_exit(0);
}

/**
 * Simple callback function used with tcpip_callback to free a pbuf
 * (pbuf_free has a wrong signature for tcpip_callback)
 *
 * @param p The pbuf (chain) to be dereferenced.
 */
static void
pbuf_free_int(void *p)
{
  struct pbuf *q = (struct pbuf *)p;
  pbuf_free(q);
}

/**
 * A simple wrapper function that allows you to free a pbuf from interrupt context.
 *
 * @param p The pbuf (chain) to be dereferenced.
 * @return ERR_OK if callback could be enqueued, an err_t if not
 */
err_t
pbuf_free_callback(void *lwip_instance_context, struct pbuf *p)
{
  return tcpip_callback_with_block((struct lwip_instance *)lwip_instance_context,pbuf_free_int, p, 0);
}

/**
 * A simple wrapper function that allows you to free heap memory from
 * interrupt context.
 *
 * @param m the heap memory to free
 * @return ERR_OK if callback could be enqueued, an err_t if not
 */
err_t
mem_free_callback(void *lwip_instance_context, void *m)
{
  return tcpip_callback_with_block((struct lwip_instance *)lwip_instance_context,mem_free, m, 0);
}

#endif /* !NO_SYS */
