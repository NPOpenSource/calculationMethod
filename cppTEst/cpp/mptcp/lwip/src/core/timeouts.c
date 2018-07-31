/**
 * @file
 * Stack-internal timers implementation.
 * This file includes timer callbacks for stack-internal timers as well as
 * functions to set up or stop timers and check for expired timers.
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
 *         Simon Goldschmidt
 *
 */

#include <unistd.h>
#include "lwip/opt.h"
#include "lwip/lwipopts.h"

#include "lwip/timeouts.h"
#include "lwip/priv/tcp_priv.h"

#include "lwip/priv/tcpip_priv.h"

#include "lwip/ip4_frag.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/igmp.h"
#include "lwip/nd6.h"
#include "lwip/ip6_frag.h"
#include "lwip/mld6.h"
#include "../../../../tools/tools.h"
#include <string.h>
#if LINUX_PLATFORM
#include "linux/linux_stub.h"
#endif


#if LWIP_DEBUG_TIMERNAMES
#define HANDLER(x) x, #x
#else /* LWIP_DEBUG_TIMERNAMES */
#define HANDLER(x) x
#endif /* LWIP_DEBUG_TIMERNAMES */

/** This array contains all stack-internal cyclic timers. To get the number of
 * timers, use LWIP_ARRAYSIZE() */
struct lwip_cyclic_timer lwip_cyclic_timers[] = {
#if LWIP_TCP
  /* The TCP timer is a special case: it does not have to run always and
     is triggered to start from TCP using tcp_timer_needed() */
  {TCP_TMR_INTERVAL, HANDLER(tcp_tmr), NULL},
#endif /* LWIP_TCP */
#if LWIP_IPV4
#if IP_REASSEMBLY
  {IP_TMR_INTERVAL, HANDLER(ip_reass_tmr), NULL},
#endif /* IP_REASSEMBLY */
#if LWIP_ARP
  {ARP_TMR_INTERVAL, HANDLER(etharp_tmr), NULL},
#endif /* LWIP_ARP */
#if LWIP_DHCP
  {DHCP_COARSE_TIMER_MSECS, HANDLER(dhcp_coarse_tmr), NULL},
  {DHCP_FINE_TIMER_MSECS, HANDLER(dhcp_fine_tmr), NULL},
#endif /* LWIP_DHCP */
#if LWIP_AUTOIP
  {AUTOIP_TMR_INTERVAL, HANDLER(autoip_tmr), NULL},
#endif /* LWIP_AUTOIP */
#if LWIP_IGMP
  {IGMP_TMR_INTERVAL, HANDLER(igmp_tmr), NULL},
#endif /* LWIP_IGMP */
#endif /* LWIP_IPV4 */
#if LWIP_DNS
  {DNS_TMR_INTERVAL, HANDLER(dns_tmr), NULL},
#endif /* LWIP_DNS */
#if LWIP_IPV6
  {ND6_TMR_INTERVAL, HANDLER(nd6_tmr), NULL},
#if LWIP_IPV6_REASS
  {IP6_REASS_TMR_INTERVAL, HANDLER(ip6_reass_tmr), NULL},
#endif /* LWIP_IPV6_REASS */
#if LWIP_IPV6_MLD
  {MLD6_TMR_INTERVAL, HANDLER(mld6_tmr), NULL},
#endif /* LWIP_IPV6_MLD */
#endif /* LWIP_IPV6 */
};

#if LWIP_TIMERS && !LWIP_TIMERS_CUSTOM

/** The one and only timeout list */
/*
static struct sys_timeo *next_timeout;
static u32_t timeouts_last_time;
*/
static int timer_run_flag = 1;
struct timer_context {
	struct sys_timeo *next_timeout;
	u32_t timeouts_last_time;
	u32_t ticks;
#if LWIP_TCP
	int tcpip_tcp_timer_active;
#endif
    unsigned int exitFlag;
};

#define LWIP_CYCLIC_TIMERS_NUM LWIP_ARRAYSIZE(lwip_cyclic_timers)
#define LWIP_TIMER_COST_TIMER  200

#if 1
/**
 * Timer callback function that calls mld6_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
cyclic_timer(void *arg)
{
  const struct lwip_cyclic_timer* cyclic = (const struct lwip_cyclic_timer*)arg;
#if LWIP_DEBUG_TIMERNAMES
  LWIP_DEBUGF(TIMERS_DEBUG, ("tcpip: %s()\n", cyclic->handler_name));
#endif
  cyclic->handler(cyclic->module_conext);
  sys_timeout((struct module_conext *)cyclic->module_conext,cyclic->interval_ms, cyclic_timer, arg);
}
#endif

struct timer_context *timer_get_context(struct lwip_instance  *instance)
{
    if(instance != NULL)
    {
	    return (struct timer_context *)instance->module_conext[CONTEXT_TIMER_TYPE].pCcontext;
    }
	return NULL;
}

void *timer_cyclic_thread(void *arg)
{
    struct lwip_instance *instance = (struct lwip_instance *)arg;
	struct timer_context *pTimerContext = timer_get_context((struct lwip_instance *)instance);
	struct lwip_cyclic_timer *pCyclic_timer;
	u32_t sys_now_time,diff,i,last_run_time;
	u32_t interval_ms_min;
	
	global_set_thread_instance(instance);
	last_run_time = sys_now(instance);
	interval_ms_min = lwip_cyclic_timers[0].interval_ms;
    do{
		sys_now_time = sys_now(instance);
		diff = sys_now_time - last_run_time;
		for(i=0; i<LWIP_CYCLIC_TIMERS_NUM;i++)
		{
		   pCyclic_timer = &lwip_cyclic_timers[i];
		   if( diff >= pCyclic_timer->interval_ms )
		   {
		       pCyclic_timer->handler((void *)instance);
		   }
		   
		   if(interval_ms_min > pCyclic_timer->interval_ms){
		   	  interval_ms_min = pCyclic_timer->interval_ms;
		   }
		}
		last_run_time = sys_now_time;
		if(interval_ms_min < 10){
			interval_ms_min = 10;
		}
		usleep(interval_ms_min * 1000 - LWIP_TIMER_COST_TIMER);
    }while(pTimerContext->exitFlag);
    return NULL;
}
/*
void *tickAnnounce(void *instance){
	struct timer_context *pTimerContext = timer_get_context((struct lwip_instance *)instance);
    char name[40]={ 0 };
    sprintf(name,"time:%d",get_instance_logic_id(instance));
    setThreadName(name);
	pTimerContext->ticks = sys_now_base(instance);
	while(pTimerContext->exitFlag)
	{
	    usleep(1000);
	    pTimerContext->ticks++;
	}
	return NULL;
}
*/
extern struct lwip_instance *gstInstance[MAX_INSTANCE_NUM*2];
void *tickAnnounce(void *instance){
    struct timer_context *pTimerContext = timer_get_context((struct lwip_instance*)instance);
    int id = -1;
    id = get_instance_logic_id((struct lwip_instance*)instance);
    char name[40]={ 0 };
    sprintf(name,"time:%d",id);
    setThreadName(name);
    pTimerContext->ticks = sys_now_base(instance);
    if(id != MAX_INSTANCE_NUM -1){
        return NULL;
    }
    while(timer_run_flag)
    {
        if(pTimerContext != NULL)
            pTimerContext->ticks++;
        for(int i = MAX_INSTANCE_NUM - 2;i >= 0;i--){
            instance = get_instance(i);
            struct timer_context *pTimerContext1 = timer_get_context((struct lwip_instance*)instance);
            if(pTimerContext1 != NULL)
                pTimerContext1->ticks++;
        }
        usleep(1000);
    }
#if SYS_THREAD_FREE_FUNC
	extern void sys_thread_free_self();
	sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
    return NULL;
}
	

u32_t tickGet(void *instance){
    struct timer_context *pTimerContext = timer_get_context((struct lwip_instance*)instance);

    if(pTimerContext != NULL)
        return pTimerContext->ticks;
    else
        return sys_now_base(instance);
}


/** Initialize this module */
void sys_timeouts_init(struct module_conext *pTimerModuleContext)
{
  size_t i;
  struct timer_context *pTimerContext;
  void *instance;
  
  pTimerModuleContext->pCcontext = malloc(sizeof(struct timer_context));
  memset(pTimerModuleContext->pCcontext, 0x0,sizeof(struct timer_context));
  pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;
  pTimerContext->exitFlag = 1;
  pTimerContext->ticks = 0;
  timer_run_flag = 1;


  instance = (void *)get_instance_context(CONTEXT_TIMER_TYPE,pTimerModuleContext);
#if 0

  sys_thread_new(instance,NULL,"timer_cyclic_thread", (lwip_thread_fn)timer_cyclic_thread, instance, 4096, 1);

#else
  
  sys_thread_new(instance,NULL,"timer_announce_thread", (lwip_thread_fn)tickAnnounce, instance, 1024, 1);
  /* tcp_tmr() at index 0 is started on demand */
  for (i = 1; i < LWIP_ARRAYSIZE(lwip_cyclic_timers); i++) {
    /* we have to cast via size_t to get rid of const warning
      (this is OK as cyclic_timer() casts back to const* */
    lwip_cyclic_timers[i].module_conext = (void *)instance;
    sys_timeout(pTimerModuleContext, lwip_cyclic_timers[i].interval_ms, cyclic_timer, LWIP_CONST_CAST(void*, &lwip_cyclic_timers[i]));
  }
#endif

  /* Initialise timestamp for sys_check_timeouts */
  pTimerContext->timeouts_last_time = sys_now(instance);
}

void sys_timeouts_deinit(struct module_conext *pTimerModuleContext)
{
    struct timer_context *pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;
    pTimerContext->exitFlag = 0;
    timer_run_flag = 0;
    usleep(200000); 
    FREE(pTimerModuleContext->pCcontext);
}

/**
 * Create a one-shot timer (aka timeout). Timeouts are processed in the
 * following cases:
 * - while waiting for a message using sys_timeouts_mbox_fetch()
 * - by calling sys_check_timeouts() (NO_SYS==1 only)
 *
 * @param msecs time in milliseconds after that the timer should expire
 * @param handler callback function to call when msecs have elapsed
 * @param arg argument to pass to the callback function
 */
#if LWIP_DEBUG_TIMERNAMES
void sys_timeout_debug(struct module_conext *pTimerModuleContext,u32_t msecs, sys_timeout_handler handler, void *arg, const char* handler_name)
#else 
void sys_timeout(struct module_conext *pTimerModuleContext,u32_t msecs, sys_timeout_handler handler, void *arg)
#endif 
/* LWIP_DEBUG_TIMERNAMES */
{
  struct sys_timeo *timeout, *t;
  u32_t now, diff;
  struct timer_context *pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;

  timeout = (struct sys_timeo *)memp_malloc(MEMP_SYS_TIMEOUT);
  if (timeout == NULL) {
    LWIP_ASSERT("sys_timeout: timeout != NULL, pool MEMP_SYS_TIMEOUT is empty", timeout != NULL);
    return;
  }
  
  if(pTimerContext == NULL)
  {
      memp_free(MEMP_SYS_TIMEOUT,(void *)timeout);
      return;
  }

  now = sys_now(get_instance_context(CONTEXT_TIMER_TYPE,pTimerModuleContext));
  if (pTimerContext->next_timeout == NULL) {
    diff = 0;
    pTimerContext->timeouts_last_time = now;
  } else {
    diff = now - pTimerContext->timeouts_last_time;
  }

  timeout->next = NULL;
  timeout->h = handler;
  timeout->arg = arg;
  timeout->time = msecs + diff;
#if LWIP_DEBUG_TIMERNAMES
  timeout->handler_name = handler_name;
  LWIP_DEBUGF(TIMERS_DEBUG, ("sys_timeout: %p msecs=%"U32_F" handler=%s arg=%p\n",
    (void *)timeout, msecs, handler_name, (void *)arg));
#endif /* LWIP_DEBUG_TIMERNAMES */

  if (pTimerContext->next_timeout == NULL) {
    pTimerContext->next_timeout = timeout;
    return;
  }

  if (pTimerContext->next_timeout->time > msecs) {
    pTimerContext->next_timeout->time -= msecs;
    timeout->next = pTimerContext->next_timeout;
    pTimerContext->next_timeout = timeout;
  } else {
    for (t = pTimerContext->next_timeout; t != NULL; t = t->next) {
      timeout->time -= t->time;
      if (t->next == NULL || t->next->time > timeout->time) {
        if (t->next != NULL) {
          t->next->time -= timeout->time;
        } else if (timeout->time > msecs) {
          /* If this is the case, 'timeouts_last_time' and 'now' differs too much.
             This can be due to sys_check_timeouts() not being called at the right
             times, but also when stopping in a breakpoint. Anyway, let's assume
             this is not wanted, so add the first timer's time instead of 'diff' */
          timeout->time = msecs + pTimerContext->next_timeout->time;
        }
        timeout->next = t->next;
        t->next = timeout;
        break;
      }
    }
  }
}

/**
 * Go through timeout list (for this task only) and remove the first matching
 * entry (subsequent entries remain untouched), even though the timeout has not
 * triggered yet.
 *
 * @param handler callback function that would be called by the timeout
 * @param arg callback argument that would be passed to handler
*/
void
sys_untimeout(struct module_conext *pTimerModuleContext, sys_timeout_handler handler, void *arg)
{
  struct sys_timeo *prev_t, *t;
  struct timer_context *pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;

  if (pTimerContext->next_timeout == NULL) {
    return;
  }

  for (t = pTimerContext->next_timeout, prev_t = NULL; t != NULL; prev_t = t, t = t->next) {
    if ((t->h == handler) && (t->arg == arg)) {
      /* We have a match */
      /* Unlink from previous in list */
      if (prev_t == NULL) {
        pTimerContext->next_timeout = t->next;
      } else {
        prev_t->next = t->next;
      }
      /* If not the last one, add time of this one back to next */
      if (t->next != NULL) {
        t->next->time += t->time;
      }
      memp_free(MEMP_SYS_TIMEOUT, t);
      return;
    }
  }
  return;
}

int printflag = 0;
/**
 * @ingroup lwip_nosys
 * Handle timeouts for NO_SYS==1 (i.e. without using
 * tcpip_thread/sys_timeouts_mbox_fetch(). Uses sys_now() to call timeout
 * handler functions when timeouts expire.
 *
 * Must be called periodically from your main loop.
 */
#if !NO_SYS && !defined __DOXYGEN__
static
#endif /* !NO_SYS */
void
sys_check_timeouts(struct module_conext *pTimerModuleContext)
{  
  struct timer_context *pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;

  if(pTimerContext == NULL){
  	return;
  }
  
  if (pTimerContext->next_timeout) {
    struct sys_timeo *tmptimeout;
    u32_t diff;
    sys_timeout_handler handler;
    void *arg;
    u8_t had_one;
    u32_t now;

    now = sys_now(get_instance_context(CONTEXT_TIMER_TYPE,pTimerModuleContext));
    /* this cares for wraparounds */
    diff = now - pTimerContext->timeouts_last_time;

    do {
      PBUF_CHECK_FREE_OOSEQ();
      had_one = 0;
      tmptimeout = pTimerContext->next_timeout;
      if (tmptimeout && (tmptimeout->time <= diff)) {
	  	
		LWIP_DEBUGF(TIMERS_DEBUG, ("timeouts_last_time =%d now=%d diff=%d\n",
            pTimerContext->timeouts_last_time, now, diff));
		
        /* timeout has expired */
        had_one = 1;
        pTimerContext->timeouts_last_time += tmptimeout->time;
        diff -= tmptimeout->time;
        pTimerContext->next_timeout = tmptimeout->next;
        handler = tmptimeout->h;
        arg = tmptimeout->arg;
#if LWIP_DEBUG_TIMERNAMES
        if (handler != NULL) {
          LWIP_DEBUGF(TIMERS_DEBUG, ("sct calling h=%s arg=%p\n",
            tmptimeout->handler_name, arg));
        }
#endif /* LWIP_DEBUG_TIMERNAMES */
        memp_free(MEMP_SYS_TIMEOUT, tmptimeout);
        if (handler != NULL) {
#if !NO_SYS
          /* For LWIP_TCPIP_CORE_LOCKING, lock the core before calling the
             timeout handler function. */
          LOCK_TCPIP_CORE();
#endif /* !NO_SYS */
          handler(arg);
#if !NO_SYS
          UNLOCK_TCPIP_CORE();
#endif /* !NO_SYS */
        }
        LWIP_TCPIP_THREAD_ALIVE();
      }
    /* repeat until all expired timers have been called */
    } while (had_one && pTimerContext->exitFlag);
  }
}

/** Set back the timestamp of the last call to sys_check_timeouts()
 * This is necessary if sys_check_timeouts() hasn't been called for a long
 * time (e.g. while saving energy) to prevent all timer functions of that
 * period being called.
 */
void
sys_restart_timeouts(struct module_conext *pTimerModuleContext)
{
  struct timer_context *pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;

  pTimerContext->timeouts_last_time = sys_now(get_instance_context(CONTEXT_TIMER_TYPE,pTimerModuleContext));
}

/** Return the time left before the next timeout is due. If no timeouts are
 * enqueued, returns 0xffffffff
 */
#if !NO_SYS
static
#endif /* !NO_SYS */
u32_t
sys_timeouts_sleeptime(struct module_conext *pTimerModuleContext)
{
  u32_t diff;
  struct timer_context *pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;

  if (pTimerContext->next_timeout == NULL) {
    return 0xffffffff;
  }
  diff = sys_now(get_instance_context(CONTEXT_TIMER_TYPE,pTimerModuleContext)) - pTimerContext->timeouts_last_time;
  if (diff > pTimerContext->next_timeout->time) {
    return 0;
  } else {
    return pTimerContext->next_timeout->time - diff;
  }
}

#if !NO_SYS

/**
 * Wait (forever) for a message to arrive in an mbox.
 * While waiting, timeouts are processed.
 *
 * @param mbox the mbox to fetch the message from
 * @param msg the place to store the message
 */
void
sys_timeouts_mbox_fetch(struct module_conext *pTimerModuleContext, sys_mbox_t *mbox, void **msg)
{
  u32_t sleeptime;
  struct timer_context *pTimerContext = (struct timer_context *)pTimerModuleContext->pCcontext;

again:
  if(pTimerContext->exitFlag == 0)
  {
      return;
  }
  if (!pTimerContext->next_timeout) {
    sys_arch_mbox_fetch(mbox, msg, 0);
    return;
  }

  sleeptime = sys_timeouts_sleeptime(pTimerModuleContext);
  if (sleeptime == 0 || sys_arch_mbox_fetch(mbox, msg, sleeptime) == SYS_ARCH_TIMEOUT) {
    /* If a SYS_ARCH_TIMEOUT value is returned, a timeout occurred
       before a message could be fetched. */
    sys_check_timeouts(pTimerModuleContext);
    /* We try again to fetch a message from the mbox. */
    goto again;
  }
}

#endif /* NO_SYS */

#else /* LWIP_TIMERS && !LWIP_TIMERS_CUSTOM */
/* Satisfy the TCP code which calls this function */
void
tcp_timer_needed(void *lwip_thread_instance)
{
}
#endif /* LWIP_TIMERS && !LWIP_TIMERS_CUSTOM */
