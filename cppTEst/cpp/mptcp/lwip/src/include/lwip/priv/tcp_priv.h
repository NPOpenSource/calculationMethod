/**
 * @file
 * TCP internal implementations (do not use in application code)
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
#ifndef LWIP_HDR_TCP_PRIV_H
#define LWIP_HDR_TCP_PRIV_H

#include "lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/tcp.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/err.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/prot/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif
#if LWIP_MPTCP_SUPPORT
#include "lwip/mptcp/mptcp.h"
#endif
/* Functions for interfacing with TCP: */

/* Lower layer interface to TCP: */
void             tcp_init    (struct module_conext *tcp_module_context);  /* Initialize this module. */
void             tcp_deinit  (struct module_conext *tcp_module_context);  /* Uninitialize this module. */
void             tcp_tmr     (void *pTcpContext);  /* Must be called every
                                         TCP_TMR_INTERVAL
                                         ms. (Typically 250 ms). */
/* It is also possible to call these two functions at the right
   intervals (instead of calling tcp_tmr()). */
void             tcp_slowtmr (void *pTcpContext);
void             tcp_fasttmr (void *pTcpContext);

/* Call this from a netif driver (watch out for threading issues!) that has
   returned a memory error on transmit and now has free buffers to send more.
   This iterates all active pcbs that had an error and tries to call
   tcp_output, so use this with care as it might slow down the system. */
void             tcp_txnow   (void *pTcpContext);

/* Only used by IP to pass a TCP segment to TCP: */
void             tcp_input   (struct pbuf *p, struct netif *inp);
/* Used within the TCP code only: */
struct tcp_pcb * tcp_alloc   (void *instance,u8_t prio);
void             tcp_abandon (struct tcp_pcb *pcb, int reset);
err_t            tcp_send_empty_ack(struct tcp_pcb *pcb);
void             tcp_rexmit  (struct tcp_pcb *pcb);
void             tcp_rexmit_rto  (struct tcp_pcb *pcb);
void             tcp_rexmit_fast (struct tcp_pcb *pcb);
u32_t            tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb);
err_t            tcp_process_refused_data(struct tcp_pcb *pcb);

/**
 * This is the Nagle algorithm: try to combine user data to send as few TCP
 * segments as possible. Only send if
 * - no previously transmitted data on the connection remains unacknowledged or
 * - the TF_NODELAY flag is set (nagle algorithm turned off for this pcb) or
 * - the only unsent segment is at least pcb->mss bytes long (or there is more
 *   than one unsent segment - with lwIP, this can happen although unsent->len < mss)
 * - or if we are in fast-retransmit (TF_INFR)
 */
#define tcp_do_output_nagle(tpcb) ((((tpcb)->unacked == NULL) || \
                            ((tpcb)->flags & (TF_NODELAY | TF_INFR)) || \
                            (((tpcb)->unsent != NULL) && (((tpcb)->unsent->next != NULL) || \
                              ((tpcb)->unsent->len >= (tpcb)->mss))) || \
                            ((tcp_sndbuf(tpcb) == 0) || (tcp_sndqueuelen(tpcb) >= TCP_SND_QUEUELEN)) \
                            ) ? 1 : 0)
#define tcp_output_nagle(tpcb) (tcp_do_output_nagle(tpcb) ? tcp_output(tpcb) : ERR_OK)


#define TCP_SEQ_LT(a,b)     ((s32_t)((u32_t)(a) - (u32_t)(b)) < 0)
#define TCP_SEQ_LEQ(a,b)    ((s32_t)((u32_t)(a) - (u32_t)(b)) <= 0)
#define TCP_SEQ_GT(a,b)     ((s32_t)((u32_t)(a) - (u32_t)(b)) > 0)
#define TCP_SEQ_GEQ(a,b)    ((s32_t)((u32_t)(a) - (u32_t)(b)) >= 0)
/* is b<=a<=c? */
#if 0 /* see bug #10548 */
#define TCP_SEQ_BETWEEN(a,b,c) ((c)-(b) >= (a)-(b))
#endif
#define TCP_SEQ_BETWEEN(a,b,c) (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))

#ifndef TCP_TMR_INTERVAL
#if LWIP_PERFORMANCE_IMPROVE
#define TCP_TMR_INTERVAL       150  /* The TCP timer interval in milliseconds. */
#else
#define TCP_TMR_INTERVAL       250  /* The TCP timer interval in milliseconds. */
#endif
#endif /* TCP_TMR_INTERVAL */

#ifndef TCP_FAST_INTERVAL
#define TCP_FAST_INTERVAL      TCP_TMR_INTERVAL /* the fine grained timeout in milliseconds */
#endif /* TCP_FAST_INTERVAL */

#ifndef TCP_SLOW_INTERVAL
#define TCP_SLOW_INTERVAL      (2*TCP_TMR_INTERVAL)  /* the coarse grained timeout in milliseconds */
#endif /* TCP_SLOW_INTERVAL */

#define TCP_FIN_WAIT_TIMEOUT 20000 /* milliseconds */
#define TCP_SYN_RCVD_TIMEOUT 20000 /* milliseconds */

#define TCP_OOSEQ_TIMEOUT        6U /* x RTO */

#ifndef TCP_MSL
#define TCP_MSL 60000UL /* The maximum segment lifetime in milliseconds */
#endif

/* Keepalive values, compliant with RFC 1122. Don't change this unless you know what you're doing */
#ifndef  TCP_KEEPIDLE_DEFAULT
#define  TCP_KEEPIDLE_DEFAULT     7200000UL /* Default KEEPALIVE timer in milliseconds */
#endif

#ifndef  TCP_KEEPINTVL_DEFAULT
#define  TCP_KEEPINTVL_DEFAULT    75000UL   /* Default Time between KEEPALIVE probes in milliseconds */
#endif

#ifndef  TCP_KEEPCNT_DEFAULT
#define  TCP_KEEPCNT_DEFAULT      9U        /* Default Counter for KEEPALIVE probes */
#endif

#define  TCP_MAXIDLE              TCP_KEEPCNT_DEFAULT * TCP_KEEPINTVL_DEFAULT  /* Maximum KEEPALIVE probe time */

#define TCP_TCPLEN(seg) ((seg)->len + (((TCPH_FLAGS((seg)->tcphdr) & (TCP_FIN | TCP_SYN)) != 0) ? 1U : 0U))

/** Flags used on input processing, not on pcb->flags
*/
#define TF_RESET     (u8_t)0x08U   /* Connection was reset. */
#define TF_CLOSED    (u8_t)0x10U   /* Connection was successfully closed. */
#define TF_GOT_FIN   (u8_t)0x20U   /* Connection was closed by the remote end. */


#if LWIP_EVENT_API

#define TCP_EVENT_ACCEPT(lpcb,pcb,arg,err,ret) ret = lwip_tcp_event(arg, (pcb),\
                LWIP_EVENT_ACCEPT, NULL, 0, err)
#define TCP_EVENT_SENT(pcb,space,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                   LWIP_EVENT_SENT, NULL, space, ERR_OK)
#define TCP_EVENT_RECV(pcb,p,err,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                LWIP_EVENT_RECV, (p), 0, (err))
#define TCP_EVENT_CLOSED(pcb,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                LWIP_EVENT_RECV, NULL, 0, ERR_OK)
#define TCP_EVENT_CONNECTED(pcb,err,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                LWIP_EVENT_CONNECTED, NULL, 0, (err))
#define TCP_EVENT_POLL(pcb,ret)       do { if ((pcb)->state != SYN_RCVD) {                          \
                ret = lwip_tcp_event((pcb)->callback_arg, (pcb), LWIP_EVENT_POLL, NULL, 0, ERR_OK); \
                } else {                                                                            \
                ret = ERR_ARG; } } while(0)
#define TCP_EVENT_ERR(last_state,errf,arg,err)  do { if (last_state != SYN_RCVD) {                \
                lwip_tcp_event((arg), NULL, LWIP_EVENT_ERR, NULL, 0, (err)); } } while(0)

#else /* LWIP_EVENT_API */

#define TCP_EVENT_ACCEPT(lpcb,pcb,arg,err,ret)                 \
  do {                                                         \
    if((lpcb)->accept != NULL)                                 \
      (ret) = (lpcb)->accept((arg),(pcb),(err));               \
    else (ret) = ERR_ARG;                                      \
  } while (0)

#define TCP_EVENT_SENT(pcb,space,ret)                          \
  do {                                                         \
    if((pcb)->sent != NULL)                                    \
      (ret) = (pcb)->sent((pcb)->callback_arg,(pcb),(space));  \
    else (ret) = ERR_OK;                                       \
  } while (0)

#define TCP_EVENT_RECV(pcb,p,err,ret)                          \
  do {                                                         \
    if((pcb)->recv != NULL) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),(p),(err));\
    } else {                                                   \
      (ret) = tcp_recv_null(NULL, (pcb), (p), (err));          \
    }                                                          \
  } while (0)

#define TCP_EVENT_CLOSED(pcb,ret)                                \
  do {                                                           \
    if(((pcb)->recv != NULL)) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),NULL,ERR_OK);\
    } else {                                                     \
      (ret) = ERR_OK;                                            \
    }                                                            \
  } while (0)

#define TCP_EVENT_CONNECTED(pcb,err,ret)                         \
  do {                                                           \
    if((pcb)->connected != NULL)                                 \
      (ret) = (pcb)->connected((pcb)->callback_arg,(pcb),(err)); \
    else (ret) = ERR_OK;                                         \
  } while (0)

#define TCP_EVENT_POLL(pcb,ret)                                \
  do {                                                         \
    if((pcb)->poll != NULL)                                    \
      (ret) = (pcb)->poll((pcb)->callback_arg,(pcb));          \
    else (ret) = ERR_OK;                                       \
  } while (0)

#define TCP_EVENT_ERR(last_state,errf,arg,err)                 \
  do {                                                         \
    LWIP_UNUSED_ARG(last_state);                               \
    if((errf) != NULL)                                         \
      (errf)((arg),(err));                                     \
  } while (0)

#endif /* LWIP_EVENT_API */

/** Enabled extra-check for TCP_OVERSIZE if LWIP_DEBUG is enabled */
#if TCP_OVERSIZE && defined(LWIP_DEBUG)
#define TCP_OVERSIZE_DBGCHECK 1
#else
#define TCP_OVERSIZE_DBGCHECK 0
#endif

/** Don't generate checksum on copy if CHECKSUM_GEN_TCP is disabled */
#define TCP_CHECKSUM_ON_COPY  (LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_TCP)

#define LWIP_TCP_OPT_EOL        0
#define LWIP_TCP_OPT_NOP        1
#define LWIP_TCP_OPT_MSS        2
#define LWIP_TCP_OPT_WS         3
#ifdef SACK_FOR_MPTCP_SUPPORT
#define LWIP_TCP_OPT_SACK_PERM  4
#define LWIP_TCP_OPT_SACK       5
#endif
#define LWIP_TCP_OPT_TS         8
#define LWIP_TCP_OPT_MPTCP 30

#define LWIP_TCP_OPT_LEN_MSS    4
#if LWIP_TCP_TIMESTAMPS
#define LWIP_TCP_OPT_LEN_TS     10
#define LWIP_TCP_OPT_LEN_TS_OUT 12 /* aligned for output (includes NOP padding) */
#else
#define LWIP_TCP_OPT_LEN_TS_OUT 0
#endif
#if LWIP_WND_SCALE
#define LWIP_TCP_OPT_LEN_WS     3
#define LWIP_TCP_OPT_LEN_WS_OUT 4 /* aligned for output (includes NOP padding) */
#else
#define LWIP_TCP_OPT_LEN_WS_OUT 0
#endif

#ifdef SACK_FOR_MPTCP_SUPPORT
#define LWIP_TCP_OPT_LEN_SACK_PERM 2
#define LWIP_TCP_OPT_LEN_SACK 12
#endif

#if LWIP_MPTCP_SUPPORT
#define LWIP_TCP_OPT_LENGTH(flags) \
  (flags & (u16_t)TF_SEG_OPTS_MSS       ? (u8_t)LWIP_TCP_OPT_LEN_MSS    : (u8_t)0) + \
  (flags & (u16_t)TF_SEG_OPTS_TS        ? (u8_t)LWIP_TCP_OPT_LEN_TS_OUT : (u8_t)0) + \
  (flags & (u16_t)TF_SEG_OPTS_WND_SCALE ? (u8_t)LWIP_TCP_OPT_LEN_WS_OUT : (u8_t)0) +\
  (flags & (u16_t)TF_SEG_OPTS_MP_CAPABLE_SYN ? (u8_t)MPTCP_SUB_LEN_CAPABLE_SYN + (u8_t)MPTCP_SUB_LEN_SER_ADDR4 : (u8_t)0) + \
  (flags & (u16_t)TF_SEG_OPTS_MP_CAPABLE_ACK ?  (u8_t)MPTCP_SUB_LEN_CAPABLE_ACK + (u8_t)MPTCP_SUB_LEN_ACK_DSS : (u8_t)0) + \
  (flags & (u16_t)TF_SEG_OPTS_MP_JOIN_SYN ?  (u8_t)MPTCP_SUB_LEN_JOIN_SYN : (u8_t)0) + \
  (flags & (u16_t)TF_SEG_OPTS_MP_JOIN_ACK ?  (u8_t)MPTCP_SUB_LEN_JOIN_ACK : (u8_t)0) + \
  (flags & (u16_t)TF_SEG_OPTS_MP_FAST_CLOSE ?  (u8_t)MPTCP_SUB_LEN_FCLOSE_ALIGN: (u8_t)0) + \
  (flags & (u16_t)TF_SEG_OPTS_MP_DSS ? (u8_t)MPTCP_SUB_LEN_DSM_ALIGN : (u8_t)0)
#else
#define LWIP_TCP_OPT_LENGTH(flags) \
  (flags & (u8_t)TF_SEG_OPTS_MSS       ? (u8_t)LWIP_TCP_OPT_LEN_MSS    : (u8_t)0) + \
  (flags & (u8_t)TF_SEG_OPTS_TS        ? (u8_t)LWIP_TCP_OPT_LEN_TS_OUT : (u8_t)0) + \
  (flags & (u8_t)TF_SEG_OPTS_WND_SCALE ? (u8_t)LWIP_TCP_OPT_LEN_WS_OUT : (u8_t)0)
#endif

/** This returns a TCP header option for MSS in an u32_t */
#define TCP_BUILD_MSS_OPTION(mss) lwip_htonl(0x02040000 | ((mss) & 0xFFFF))

#if LWIP_WND_SCALE
#define TCPWNDSIZE_F       U32_F
#define TCPWND_MAX         0xFFFFFFFFU
#define TCPWND_CHECK16(x)  LWIP_ASSERT("window size > 0xFFFF", (x) <= 0xFFFF)
#define TCPWND_MIN16(x)    ((u16_t)LWIP_MIN((x), 0xFFFF))
#else /* LWIP_WND_SCALE */
#define TCPWNDSIZE_F       U16_F
#define TCPWND_MAX         0xFFFFU
#define TCPWND_CHECK16(x)
#define TCPWND_MIN16(x)    x
#endif /* LWIP_WND_SCALE */

/* Global variables: */
/*
extern struct tcp_pcb *tcp_input_pcb;
extern u32_t tcp_ticks;
extern u8_t tcp_active_pcbs_changed;
*/


/*extern struct tcp_pcb *tcp_bound_pcbs;*/
/*extern union tcp_listen_pcbs_t tcp_listen_pcbs;*/
/*extern struct tcp_pcb *tcp_active_pcbs;*/  /* List of all TCP PCBs that are in a
              state in which they accept or send
              data. */
/*extern struct tcp_pcb *tcp_tw_pcbs;*/      /* List of all TCP PCBs in TIME-WAIT. */

#define NUM_TCP_PCB_LISTS_NO_TIME_WAIT  3
#define NUM_TCP_PCB_LISTS               4

/*
extern struct tcp_pcb ** const tcp_pcb_lists[NUM_TCP_PCB_LISTS];
*/
	/* The TCP PCB lists. */
union tcp_listen_pcbs_t { /* List of all TCP PCBs in LISTEN state. */
	  struct tcp_pcb_listen *listen_pcbs;
	  struct tcp_pcb *pcbs;
};
	
#if LWIP_MPTCP_SUPPORT
typedef struct mptcp_recv_info_t{
		u32_t recv_data_seq;
		u32_t recv_sub_data_seq;
		u16_t recv_data_len;
		u16_t recv_csum;
		u32_t sfl_data_seq;
		u16_t sfl_data_len;
		u16_t sfl_data_csum;
		u8_t recv_fin_valid:1,
			 recv_csum_valid:1,
			 mptcp_info_valid:1,
			 sfl_fin_valid:1;
}mptcp_recv_info, *p_mptcp_recv_info;
#endif
	
	/* This structure represents a TCP segment on the unsent, unacked and ooseq queues */
struct tcp_seg {
	  struct tcp_seg *next;    /* used when putting segments on a queue */
	  struct pbuf *p;		   /* buffer containing data + TCP header */
	  u16_t len;			   /* the TCP length of this segment */
#if TCP_OVERSIZE_DBGCHECK
	  u16_t oversize_left;	   /* Extra bytes available at the end of the last
								  pbuf in unsent (used for asserting vs.
								  tcp_pcb.unsent_oversize only) */
#endif /* TCP_OVERSIZE_DBGCHECK */
#if TCP_CHECKSUM_ON_COPY
	  u16_t chksum;
	  u8_t	chksum_swapped;
#endif /* TCP_CHECKSUM_ON_COPY */
	  u16_t  flags;
#define TF_SEG_OPTS_MSS         (u16_t)0x01U /* Include MSS option. */
#define TF_SEG_OPTS_TS          (u16_t)0x02U /* Include timestamp option. */
#define TF_SEG_DATA_CHECKSUMMED (u16_t)0x04U /* ALL data (not the header) is
												   checksummed into 'chksum' */
#define TF_SEG_OPTS_WND_SCALE   (u16_t)0x08U /* Include WND SCALE option */
#ifdef SACK_FOR_MPTCP_SUPPORT
#define TF_SEG_OPTS_SACK_FOR_MPTCP (u16_t)0x400U
#endif
	
#if LWIP_MPTCP_SUPPORT
	  u32_t meta_seq;
	  p_mptcp_recv_info recv_info;
	  u16_t mptcp_data_chksum;
	  u8_t rexmit;
#define TF_SEG_OPTS_MP_CAPABLE_SYN (u16_t)0x10U /* Include MP_CAPABLE SYN option */
#define TF_SEG_OPTS_MP_CAPABLE_ACK (u16_t)0x20U /* Include MP_CAPABLE ACK option */
#define TF_SEG_OPTS_MP_JOIN_SYN (u16_t)0x40U /* Include MP_JOIN SYN option */
#define TF_SEG_OPTS_MP_JOIN_ACK (u16_t)0x80U /* Include MP_JOIN ACK option */
#define TF_SEG_OPTS_MP_DSS (u16_t)0x100U /* Include MP_DSS option */
#define TF_SEG_OPTS_MP_FAST_CLOSE (u16_t)0x200U /* Include MP_FAST_CLOSE option */
	
#endif
	  struct tcp_hdr *tcphdr;  /* the TCP header */
      void *instance;
};

/* Axioms about the above lists:
   1) Every TCP PCB that is not CLOSED is in one of the lists.
   2) A PCB is only in one of the lists.
   3) All PCBs in the tcp_listen_pcbs list is in LISTEN state.
   4) All PCBs in the tcp_tw_pcbs list is in TIME-WAIT state.
*/
/* Define two macros, TCP_REG and TCP_RMV that registers a TCP PCB
   with a PCB list or removes a PCB from a list, respectively. */
#ifndef TCP_DEBUG_PCB_LISTS
#define TCP_DEBUG_PCB_LISTS 0
#endif
#if TCP_DEBUG_PCB_LISTS
#define TCP_REG(pcbs, npcb) do {\
                            struct tcp_pcb *tcp_tmp_pcb; \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_REG %p local port %d\n", (npcb), (npcb)->local_port)); \
                            for (tcp_tmp_pcb = *(pcbs); \
          tcp_tmp_pcb != NULL; \
        tcp_tmp_pcb = tcp_tmp_pcb->next) { \
                                LWIP_ASSERT("TCP_REG: already registered\n", tcp_tmp_pcb != (npcb)); \
                            } \
                            LWIP_ASSERT("TCP_REG: pcb->state != CLOSED", ((pcbs) == &tcp_bound_pcbs) || ((npcb)->state != CLOSED)); \
                            (npcb)->next = *(pcbs); \
                            LWIP_ASSERT("TCP_REG: npcb->next != npcb", (npcb)->next != (npcb)); \
                            *(pcbs) = (npcb); \
                            LWIP_ASSERT("TCP_RMV: tcp_pcbs sane", tcp_pcbs_sane()); \
              tcp_timer_needed(npcb->instance); \
                            } while(0)
#define TCP_RMV(pcbs, npcb) do { \
                            struct tcp_pcb *tcp_tmp_pcb; \
                            LWIP_ASSERT("TCP_RMV: pcbs != NULL", *(pcbs) != NULL); \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_RMV: removing %p from %p\n", (npcb), *(pcbs))); \
                            if(*(pcbs) == (npcb)) { \
                               *(pcbs) = (*pcbs)->next; \
                            } else for (tcp_tmp_pcb = *(pcbs); tcp_tmp_pcb != NULL; tcp_tmp_pcb = tcp_tmp_pcb->next) { \
                               if(tcp_tmp_pcb->next == (npcb)) { \
                                  tcp_tmp_pcb->next = (npcb)->next; \
                                  break; \
                               } \
                            } \
                            (npcb)->next = NULL; \
                            LWIP_ASSERT("TCP_RMV: tcp_pcbs sane", tcp_pcbs_sane()); \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_RMV: removed %p from %p\n", (npcb), *(pcbs))); \
                            } while(0)

#else /* LWIP_DEBUG */

#define TCP_REG(pcbs, npcb)                        \
  do {                                             \
    (npcb)->next = *pcbs;                          \
    *(pcbs) = (npcb);                              \
    tcp_timer_needed(npcb->instance);                            \
  } while (0)

#define TCP_RMV(pcbs, npcb)                        \
  do {                                             \
    if(*(pcbs) == (npcb)) {                        \
      (*(pcbs)) = (*pcbs)->next;                   \
    }                                              \
    else {                                         \
      struct tcp_pcb *tcp_tmp_pcb;                 \
      for (tcp_tmp_pcb = *pcbs;                    \
          tcp_tmp_pcb != NULL;                     \
          tcp_tmp_pcb = tcp_tmp_pcb->next) {       \
        if(tcp_tmp_pcb->next == (npcb)) {          \
          tcp_tmp_pcb->next = (npcb)->next;        \
          break;                                   \
        }                                          \
      }                                            \
    }                                              \
    (npcb)->next = NULL;                           \
  } while(0)

#endif /* LWIP_DEBUG */

#define TCP_REG_ACTIVE(npcb)                       \
  do {                                             \
    TCP_REG(&pTcpContext->tcp_active_pcbs, npcb);               \
	tcp_port_set_to_list(npcb->local_port,npcb);    \
    pTcpContext->tcp_active_pcbs_changed = 1;                   \
  } while (0)

#define TCP_RMV_ACTIVE(npcb)                       \
  do {                                             \
	tcp_port_set_to_list(npcb->local_port,npcb);		\
    TCP_RMV(&pTcpContext->tcp_active_pcbs, npcb);               \
    pTcpContext->tcp_active_pcbs_changed = 1;                   \
  } while (0)

#define TCP_PCB_REMOVE_ACTIVE(pcb)                 \
  do {                                             \
	tcp_port_set_to_list(pcb->local_port,pcb);		  \
    tcp_pcb_remove(&pTcpContext->tcp_active_pcbs, pcb);         \
    pTcpContext->tcp_active_pcbs_changed = 1;                   \
  } while (0)


/* Internal functions: */
struct tcp_pcb *tcp_pcb_copy(struct tcp_pcb *pcb);
void tcp_pcb_purge(struct tcp_pcb *pcb);
void tcp_pcb_remove(struct tcp_pcb **pcblist, struct tcp_pcb *pcb);

void tcp_segs_free(struct tcp_seg *seg);
void tcp_seg_free(struct tcp_seg *seg);
struct tcp_seg *tcp_seg_copy(void *instance,struct tcp_seg *seg);

#if LWIP_PERFORMANCE_ENABLE_DELAY_ACK
#define tcp_ack(pcb)                               \
  do {                                             \
    if((pcb)->flags & TF_ACK_DELAY) {              \
      if((++((pcb)->ack_delay_num)) > (pcb)->ack_delay_cnt) {         \
      (pcb)->flags &= ~TF_ACK_DELAY;               \
      (pcb)->flags |= TF_ACK_NOW;                  \
      (pcb)->ack_delay_num = 0;                    \
      }                                            \
    }                                              \
    else {                                         \
      (pcb)->flags |= TF_ACK_DELAY;                \
      (pcb)->ack_delay_num = 1;                    \
    }                                              \
  } while (0)
#define tcp_ack_now(pcb)                           \
  do {                                             \
    (pcb)->ack_delay_num = 0;                      \
    (pcb)->flags |= TF_ACK_NOW;                    \
  } while (0)
#else
#define tcp_ack(pcb)                               \
  do {                                             \
    if((pcb)->flags & TF_ACK_DELAY) {              \
      (pcb)->flags &= ~TF_ACK_DELAY;               \
      (pcb)->flags |= TF_ACK_NOW;                  \
    }                                              \
    else {                                         \
      (pcb)->flags |= TF_ACK_DELAY;                \
    }                                              \
  } while (0)

#define tcp_ack_now(pcb)                           \
  do {                                             \
    (pcb)->flags |= TF_ACK_NOW;                    \
  } while (0)
#endif

err_t tcp_send_fin(struct tcp_pcb *pcb);
err_t tcp_enqueue_flags(struct tcp_pcb *pcb, u8_t flags);

void tcp_rexmit_seg(struct tcp_pcb *pcb, struct tcp_seg *seg);

void tcp_rst(void *instance,u32_t seqno, u32_t ackno,
       const ip_addr_t *local_ip, const ip_addr_t *remote_ip,
       u16_t local_port, u16_t remote_port);

u32_t tcp_next_iss(struct tcp_pcb *pcb, void *pTcpContext);

err_t tcp_keepalive(struct tcp_pcb *pcb);
err_t tcp_zero_window_probe(struct tcp_pcb *pcb);
void  tcp_trigger_input_pcb_close(void *pTcpContext);

#if TCP_CALCULATE_EFF_SEND_MSS
u16_t tcp_eff_send_mss_netif(void *instance,u16_t sendmss, struct netif *outif,
                             const ip_addr_t *dest);
#define tcp_eff_send_mss(instance, sendmss, src, dest) \
    tcp_eff_send_mss_netif(instance, sendmss, ip_route(instance,src, dest), dest)
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

#if LWIP_CALLBACK_API
err_t tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
#endif /* LWIP_CALLBACK_API */

#if TCP_DEBUG || TCP_INPUT_DEBUG || TCP_OUTPUT_DEBUG
void tcp_debug_print(struct tcp_hdr *tcphdr);
void tcp_debug_print_flags(u8_t flags);
void tcp_debug_print_state(enum tcp_state s);
void tcp_debug_print_pcbs(void *instance);
s16_t tcp_pcbs_sane(void* instance);
#else
#  define tcp_debug_print(tcphdr)
#  define tcp_debug_print_flags(flags)
#  define tcp_debug_print_state(s)
#  define tcp_debug_print_pcbs()
#  define tcp_pcbs_sane(instance) 1
#endif /* TCP_DEBUG */

/** External function (implemented in timers.c), called when TCP detects
 * that a timer is needed (i.e. active- or time-wait-pcb found). */
void tcp_timer_needed(void *lwip_thread_instance);

void tcp_netif_ip_addr_changed(void *instance,const ip_addr_t* old_addr, const ip_addr_t* new_addr);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_TCP */

#endif /* LWIP_HDR_TCP_PRIV_H */
