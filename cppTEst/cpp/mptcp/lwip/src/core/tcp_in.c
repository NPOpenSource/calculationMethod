/**
 * @file
 * Transmission Control Protocol, incoming traffic
 *
 * The input processing functions of the TCP layer.
 *
 * These functions are generally called in the order (ip_input() ->)
 * tcp_input() -> * tcp_process() -> tcp_receive() (-> application).
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

#include <lwip/mptcp/mptcp_session.h>
#include <sys/time.h>
#include <lwip/tcpip.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/tcp_common_context.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/priv/tcp_priv.h"
#include "lwip/inet_chksum.h"
#include "lwip/mptcp_fin.h"

#undef printf
#define printf(x)

#if LWIP_ND6_TCP_REACHABILITY_HINTS
#include "lwip/nd6.h"
#endif /* LWIP_ND6_TCP_REACHABILITY_HINTS */

#if LWIP_MPTCP_SUPPORT
#include "lwip/mptcp/mptcp_input_output.h"
#include "lwip/mptcp/mptcp_state.h"
#endif
#include "lwip/module.h"
#include "lwip/tcp_common_context.h"
#include "lwip/tcp_common_context.h"
#include "../../../../mccp/mccp.h"


/** Initial CWND calculation as defined RFC 2581 */
#define LWIP_TCP_CALC_INITIAL_CWND(mss) LWIP_MIN((4U * (mss)), LWIP_MAX((2U * (mss)), 4380U));

/* These variables are global to all functions involved in the input
   processing of TCP segments. They are set by the tcp_input()
   function. */

/*
static struct tcp_seg inseg;
static struct tcp_hdr *tcphdr;
static u16_t tcphdr_optlen;
static u16_t tcphdr_opt1len;
static u8_t* tcphdr_opt2;
static u16_t tcp_optidx;
static u32_t seqno, ackno;
static tcpwnd_size_t recv_acked;
static u16_t tcplen;
static u8_t flags;

static u8_t recv_flags;
static struct pbuf *recv_data;
#if LWIP_MPTCP_SUPPORT
struct tcp_seg *mptcp_recv_data;
static u16_t tcp_data_csum;
#endif

struct tcp_pcb *tcp_input_pcb;
struct tcp_pcb *last_input_pcb = NULL;
*/

/* Forward declarations. */
static err_t tcp_process(struct tcp_pcb *pcb, struct tcp_context *pTcpContext);
static void tcp_receive(struct tcp_pcb *pcb, struct tcp_context *pTcpContext);
static void tcp_parseopt(struct tcp_pcb *pcb, struct tcp_context *pTcpContext);

static void tcp_listen_input(struct tcp_pcb_listen *pcb, struct tcp_context *pTcpContext);
static void tcp_timewait_input(struct tcp_pcb *pcb, struct tcp_context *pTcpContext);
#if SACK_FOR_MPTCP_SUPPORT
static inline int sack_before(u32_t seq1,u32_t seq2);
#endif
#if LWIP_MPTCP_SUPPORT
void tcp_in_init(struct module_conext *tcp_module_context){
    struct tcp_context *pTcpContext = (struct tcp_context *)tcp_module_context->pCcontext;
	struct tcp_seg *pTcpSeg;
	mptcp_recv_info *pMptcpRecvInfo;

	pTcpSeg = (struct tcp_seg *)malloc(sizeof(struct tcp_seg));
	memset((void *)pTcpSeg ,0x0, sizeof(struct tcp_seg));
    /*pTcpSeg->recv_info = NULL;*/
	pTcpContext->inseg = (void *)pTcpSeg;
	pTcpContext->sackOption = (struct sack_option *)malloc(sizeof(struct sack_option));
	memset((void *)pTcpContext->sackOption, 0x0, sizeof(struct sack_option));
	pTcpContext->sackOption->pairs = (struct sack_pair *)malloc(sizeof(struct sack_pair)*32);
	memset((void *)pTcpContext->sackOption->pairs, 0x0, sizeof(struct sack_pair)*32);
}
#endif

/**
 * The initial input processing of TCP. It verifies the TCP header, demultiplexes
 * the segment between the PCBs and passes it on to tcp_process(), which implements
 * the TCP finite state machine. This function is called by the IP layer (in
 * ip_input()).
 *
 * @param p received TCP segment to process (p->payload pointing to the TCP header)
 * @param inp network interface on which this segment was received
 */
void
tcp_input(struct pbuf *p, struct netif *inp)
{
  struct tcp_pcb *pcb = NULL, *prev;
  struct tcp_pcb_listen *lpcb = NULL;
#if SO_REUSE
  struct tcp_pcb *lpcb_prev = NULL;
  struct tcp_pcb_listen *lpcb_any = NULL;
#endif /* SO_REUSE */
  u8_t hdrlen_bytes;
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
  u8_t sch_lstn = 0;
#endif
#if TCP_FIND
  u8_t isFind = 0;
#endif
  err_t err;
  struct lwip_instance *pLwipInstance = (struct lwip_instance *)inp->instance;
  struct module_conext *netif_module_context = &pLwipInstance->module_conext[CONTEXT_NETIF_TYPE];
  struct module_conext *tcp_module_context = &pLwipInstance->module_conext[CONTEXT_TCP_TYPE];
  struct tcp_context *pTcpContext;
  struct tcp_seg *pTcpSeg;
/*
#if !LWIP_MPTCP_SUPPORT
  LWIP_UNUSED_ARG(inp);
#endif
*/
  if( tcp_module_context == NULL)
  {
      goto dropped;
  }
  pTcpContext = (struct tcp_context *)tcp_module_context->pCcontext;
  if( pTcpContext == NULL)
  {
      goto dropped;
  }
  pTcpSeg = ((struct tcp_seg *)(pTcpContext->inseg));

  PERF_START;

  TCP_STATS_INC(tcp.recv);
  MIB2_STATS_INC(mib2.tcpinsegs);

  pTcpContext->tcphdr = (struct tcp_hdr *)p->payload;

#if TCP_INPUT_DEBUG
  tcp_debug_print(pTcpContext->tcphdr);
#endif

  /* Check that TCP header fits in payload */
  if (p->len < TCP_HLEN) {
    /* drop short packets */
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: short packet (%"U16_F" bytes) discarded\n", p->tot_len));
    TCP_STATS_INC(tcp.lenerr);
    goto dropped;
  }

  /* Don't even process incoming broadcasts/multicasts. */
  if (ip_addr_isbroadcast(ip_current_dest_addr(inp->instance), ip_current_netif(inp->instance)) ||
      ip_addr_ismulticast(ip_current_dest_addr(inp->instance))) {
    TCP_STATS_INC(tcp.proterr);
    goto dropped;
  }

#if !LWIP_MPTCP_SUPPORT
#if CHECKSUM_CHECK_TCP
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP) {
    /* Verify TCP checksum. */
    u16_t chksum = ip_chksum_pseudo(p, IP_PROTO_TCP, p->tot_len,
                               ip_current_src_addr(inp->instance), ip_current_dest_addr(inp->instance));
    if (chksum != 0) {
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packet discarded due to failing checksum 0x%04"X16_F"\n",
          chksum));
      tcp_debug_print(pTcpContext->tcphdr);
      TCP_STATS_INC(tcp.chkerr);
      goto dropped;
    }
  }
#endif /* CHECKSUM_CHECK_TCP */
#endif

  /* sanity-check header length */
  hdrlen_bytes = TCPH_HDRLEN(pTcpContext->tcphdr) * 4;
  if ((hdrlen_bytes < TCP_HLEN) || (hdrlen_bytes > p->tot_len)) {
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: invalid header length (%"U16_F")\n", (u16_t)hdrlen_bytes));
    TCP_STATS_INC(tcp.lenerr);
    goto dropped;
  }

#if LWIP_MPTCP_SUPPORT
#if CHECKSUM_CHECK_TCP
#if 0
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP) {
    /* Verify TCP checksum. */
    /* assume all stuff is in one pbuf, and header length is even */
    u16_t chksum, tcp_hdr_csum;
    if(!inp->is_nat_if && p->tot_len - hdrlen_bytes > 0){
      tcp_hdr_csum = lwip_standard_chksum(p->payload, hdrlen_bytes);
      pTcpContext->tcp_data_csum = lwip_standard_chksum((void *)(((u8_t *)p->payload) +
        hdrlen_bytes), p->tot_len - hdrlen_bytes);
      chksum = tcp_chksum(tcp_hdr_csum, pTcpContext->tcp_data_csum, IP_PROTO_TCP,
        p->tot_len, ip_current_src_addr(inp->instance), ip_current_dest_addr(inp->instance));
    }else{
      chksum = ip_chksum_pseudo(p, IP_PROTO_TCP, p->tot_len,
                               ip_current_src_addr(inp->instance), ip_current_dest_addr(inp->instance));
    }
    if (chksum != 0) {
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packet discarded due to failing checksum 0x%04"X16_F"\n",
          chksum));
      tcp_debug_print(pTcpContext->tcphdr);
      TCP_STATS_INC(tcp.chkerr);
      goto dropped;
    }
  }
#endif
#endif /* CHECKSUM_CHECK_TCP */
#endif

  /* Move the payload pointer in the pbuf so that it points to the
     TCP data instead of the TCP header. */
  pTcpContext->tcphdr_optlen = hdrlen_bytes - TCP_HLEN;
  pTcpContext->tcphdr_opt2 = NULL;
  if (p->len >= hdrlen_bytes) {
    /* all options are in the first pbuf */
    pTcpContext->tcphdr_opt1len = pTcpContext->tcphdr_optlen;
    pbuf_header(p, -(s16_t)hdrlen_bytes); /* cannot fail */
  } else {
    u16_t opt2len;
    /* TCP header fits into first pbuf, options don't - data is in the next pbuf */
    /* there must be a next pbuf, due to hdrlen_bytes sanity check above */
    LWIP_ASSERT("p->next != NULL", p->next != NULL);

    /* advance over the TCP header (cannot fail) */
    pbuf_header(p, -TCP_HLEN);

    /* determine how long the first and second parts of the options are */
    pTcpContext->tcphdr_opt1len = p->len;
    opt2len = pTcpContext->tcphdr_optlen - pTcpContext->tcphdr_opt1len;

    /* options continue in the next pbuf: set p to zero length and hide the
        options in the next pbuf (adjusting p->tot_len) */
    pbuf_header(p, -(s16_t)pTcpContext->tcphdr_opt1len);

    /* check that the options fit in the second pbuf */
    if (opt2len > p->next->len) {
      /* drop short packets */
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: options overflow second pbuf (%"U16_F" bytes)\n", p->next->len));
      TCP_STATS_INC(tcp.lenerr);
      goto dropped;
    }

    /* remember the pointer to the second part of the options */
    pTcpContext->tcphdr_opt2 = (u8_t*)p->next->payload;

    /* advance p->next to point after the options, and manually
        adjust p->tot_len to keep it consistent with the changed p->next */
    pbuf_header(p->next, -(s16_t)opt2len);
    p->tot_len -= opt2len;

    LWIP_ASSERT("p->len == 0", p->len == 0);
    LWIP_ASSERT("p->tot_len == p->next->tot_len", p->tot_len == p->next->tot_len);
  }

  /* Convert fields in TCP header to host byte order. */
  pTcpContext->tcphdr->src = lwip_ntohs(pTcpContext->tcphdr->src);
  pTcpContext->tcphdr->dest = lwip_ntohs(pTcpContext->tcphdr->dest);
  pTcpContext->seqno = pTcpContext->tcphdr->seqno = lwip_ntohl(pTcpContext->tcphdr->seqno);
  pTcpContext->ackno = pTcpContext->tcphdr->ackno = lwip_ntohl(pTcpContext->tcphdr->ackno);
  pTcpContext->tcphdr->wnd = lwip_ntohs(pTcpContext->tcphdr->wnd);

  pTcpContext->flags = TCPH_FLAGS(pTcpContext->tcphdr);
  pTcpContext->tcplen = p->tot_len + ((pTcpContext->flags & (TCP_FIN | TCP_SYN)) ? 1 : 0);

#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
  if((pTcpContext->flags & TCP_SYN) && !(pTcpContext->flags & TCP_ACK))
    sch_lstn = 1;
#endif

  /* Demultiplex an incoming segment. First, we check if it is destined
     for an active connection. */
  prev = NULL;
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
  if (!sch_lstn) {
#endif
#if TCP_FIND
  if(inp->is_nat_if != 0){
      pcb = pTcpContext->mptcp_list[pTcpContext->tcphdr->dest];
      LWIP_DEBUGF(TCP_DEBUG,("find TCP Context:%p",pcb));
      if(pcb && (!is_meta_pcb(pcb)) && (pcb->state == ESTABLISHED) )  //针对数传优化
      {
	  	isFind = 1;
      }else
      {
      	pcb = NULL;	
      }
  }
  if(!isFind){
#endif
  for (pcb = pTcpContext->tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_ASSERT("tcp_input: active pcb->state != CLOSED", pcb->state != CLOSED);
    LWIP_ASSERT("tcp_input: active pcb->state != TIME-WAIT", pcb->state != TIME_WAIT);
    LWIP_ASSERT("tcp_input: active pcb->state != LISTEN", pcb->state != LISTEN);
#if LWIP_MPTCP_SUPPORT
    /* Skip meta pcb. Is it correct? */
    if(pcb->mptcp_enabled && is_meta_pcb(pcb) && pcb->delay_conn_evt != 1)
    {
        continue;
    }
#endif
    if (pcb->remote_port == pTcpContext->tcphdr->src &&
        pcb->local_port == pTcpContext->tcphdr->dest &&
        ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr(inp->instance)) &&
        ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr(inp->instance))) {
      /* Move this PCB to the front of the list so that subsequent
         lookups will be faster (we exploit locality in TCP segment
         arrivals). */
      LWIP_ASSERT("tcp_input: pcb->next != pcb (before cache)", pcb->next != pcb);
      if (prev != NULL) {
        prev->next = pcb->next;
        pcb->next = pTcpContext->tcp_active_pcbs;
        pTcpContext->tcp_active_pcbs = pcb;
      } else {
        TCP_STATS_INC(tcp.cachehit);
      }
 
	  if((pTcpContext->flags & TCP_ACK) && (pTcpContext->flags & TCP_PSH))
	  {
	      if(pcb->is_meta_pcb && pcb->mptcp_state == MPTCP_MP_ESTABLISHED)
		  	continue;
	  }
	 
      LWIP_ASSERT("tcp_input: pcb->next != pcb (after cache)", pcb->next != pcb);
      break;
    }
    prev = pcb;
  }
#if TCP_FIND
  }
#endif
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
  }
#endif
  if (pcb == NULL) {
    /* If it did not go to an active connection, we check the connections
       in the TIME-WAIT state. */
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
     if (!sch_lstn) {
#endif
    for (pcb = pTcpContext->tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
      LWIP_ASSERT("tcp_input: TIME-WAIT pcb->state == TIME-WAIT", pcb->state == TIME_WAIT);
      if (pcb->remote_port == pTcpContext->tcphdr->src &&
          pcb->local_port == pTcpContext->tcphdr->dest &&
          ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr(inp->instance)) &&
          ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr(inp->instance))) {
        /* We don't really care enough to move this PCB to the front
           of the list since we are not very likely to receive that
           many segments for connections in TIME-WAIT. */
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for TIME_WAITing connection.\n"));
        tcp_timewait_input(pcb, pTcpContext);
        pbuf_free(p);
        return;
      }
    }
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
    }
#endif
    /* Finally, if we still did not get a match, we check all PCBs that
       are LISTENing for incoming connections. */
    prev = NULL;
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
      if(sch_lstn) {
          lpcb = pTcpContext->tcp_listen_pcbs.listen_pcbs;
      }
#else
    for (lpcb = pTcpContext->tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
      if (lpcb->local_port == pTcpContext->tcphdr->dest) {
        if (IP_IS_ANY_TYPE_VAL(lpcb->local_ip)) {
          /* found an ANY TYPE (IPv4/IPv6) match */
#if SO_REUSE
          lpcb_any = lpcb;
          lpcb_prev = prev;
#else /* SO_REUSE */
          break;
#endif /* SO_REUSE */
        } else if (IP_ADDR_PCB_VERSION_MATCH_EXACT(lpcb, ip_current_dest_addr(inp->instance))) {
          if (ip_addr_cmp(&lpcb->local_ip, ip_current_dest_addr(inp->instance))) {
            /* found an exact match */
            break;
          } else if (ip_addr_isany(&lpcb->local_ip)) {
            /* found an ANY-match */
#if SO_REUSE
            lpcb_any = lpcb;
            lpcb_prev = prev;
#else /* SO_REUSE */
            break;
 #endif /* SO_REUSE */
          }
        }
      }
      prev = (struct tcp_pcb *)lpcb;
    }
#if SO_REUSE
    /* first try specific local IP */
    if (lpcb == NULL) {
      /* only pass to ANY if no specific local IP has been found */
      lpcb = lpcb_any;
      prev = lpcb_prev;
    }
#endif /* SO_REUSE */
#endif /* LWIP_MPTCP_SUPPORT */
    if (lpcb != NULL) {
      /* Move this PCB to the front of the list so that subsequent
         lookups will be faster (we exploit locality in TCP segment
         arrivals). */
#if !LWIP_MPTCP_SUPPORT || !LWIP_PERFORMANCE_IMPROVE
      if (prev != NULL) {
        ((struct tcp_pcb_listen *)prev)->next = lpcb->next;
              /* our successor is the remainder of the listening list */
        lpcb->next = pTcpContext->tcp_listen_pcbs.listen_pcbs;
              /* put this listening pcb at the head of the listening list */
        pTcpContext->tcp_listen_pcbs.listen_pcbs = lpcb;
      } else
#endif
      {
        TCP_STATS_INC(tcp.cachehit);
      }

      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for LISTENing connection.\n"));
      tcp_listen_input(lpcb, pTcpContext);
      pbuf_free(p);
      return;
    }
  }

#if TCP_INPUT_DEBUG
  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("+-+-+-+-+-+-+-+-+-+-+-+-+-+- tcp_input: flags "));
  tcp_debug_print_flags(TCPH_FLAGS(pTcpContext->tcphdr));
  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"));
#endif /* TCP_INPUT_DEBUG */


  if (pcb != NULL) {
    /* The incoming segment belongs to a connection. */
#if TCP_INPUT_DEBUG
    tcp_debug_print_state(pcb->state);
#endif /* TCP_INPUT_DEBUG */

    /* Set up a tcp_seg structure. */
    pTcpSeg->next = NULL;
    pTcpSeg->len = p->tot_len;
    pTcpSeg->p = p;
    pTcpSeg->tcphdr = pTcpContext->tcphdr;

    pTcpContext->recv_data = NULL;
    pTcpContext->recv_flags = 0;
    pTcpContext->recv_acked = 0;
#if LWIP_MPTCP_SUPPORT
    pTcpContext->mptcp_recv_data = NULL;
#endif

    if (pTcpContext->flags & TCP_PSH) {
      p->flags |= PBUF_FLAG_PUSH;
    }

    /* If there is data which was previously "refused" by upper layer */
    if (pcb->refused_data != NULL) {
      if ((tcp_process_refused_data(pcb) == ERR_ABRT) ||
        ((pcb->refused_data != NULL) && (pTcpContext->tcplen > 0))) {
        /* pcb has been aborted or refused data is still refused and the new
           segment contains data */
        if (pcb->rcv_ann_wnd == 0) {
          /* this is a zero-window probe, we respond to it with current RCV.NXT
          and drop the data segment */
          tcp_send_empty_ack(pcb);
        }
        TCP_STATS_INC(tcp.drop);
        MIB2_STATS_INC(mib2.tcpinerrs);
        goto aborted;
      }
    }
    pTcpContext->tcp_input_pcb = pcb;
#if LWIP_MPTCP_SUPPORT
    mptcp_invalidate_recv_info(pcb->instance);
#endif
#if SACK_FOR_MPTCP_SUPPORT
   if(sack_before(pTcpContext->ackno,pcb->sack_hight_recv)== 1 || pcb->sack_hight_recv == 0){
		/* update the pcb->hight_rcv */
		pcb->sack_hight_recv = pTcpContext->ackno;
	}
#endif
    err = tcp_process(pcb, pTcpContext);
    /* A return value of ERR_ABRT means that tcp_abort() was called
       and that the pcb has been freed. If so, we don't do anything. */
    if (err != ERR_ABRT) {
      if (pTcpContext->recv_flags & TF_RESET) {
        /* TF_RESET means that the connection was reset by the other
           end. We then call the error callback to inform the
           application that the connection is dead before we
           deallocate the PCB. */
#if LWIP_MPTCP_SUPPORT
        if(is_sfl_pcb(pcb)) {
            err = mptcp_fin_sfl_recved_rst(pcb);
            if (err == ERR_ABRT) {
                goto aborted;
            }
        }
#endif
        TCP_EVENT_ERR(pcb->state, pcb->errf, pcb->callback_arg, ERR_RST);

#if TCP_FIND
        tcp_port_remove_from_list(pcb->local_port,pcb);
#endif
        tcp_pcb_remove(&pTcpContext->tcp_active_pcbs, pcb);
        memp_free(MEMP_TCP_PCB, pcb);
      } else {
        err = ERR_OK;
        /* If the application has registered a "sent" function to be
           called when new send buffer space is available, we call it
           now. */
        if (pTcpContext->recv_acked > 0) {
          u16_t acked16;
#if LWIP_WND_SCALE
          /* recv_acked is u32_t but the sent callback only takes a u16_t,
             so we might have to call it multiple times. */
          u32_t acked = pTcpContext->recv_acked;
          while (acked > 0) {
            acked16 = (u16_t)LWIP_MIN(acked, 0xffffu);
            acked -= acked16;
#else
          {
            acked16 = pTcpContext->recv_acked;
#endif
#if LWIP_MPTCP_SUPPORT
            if(pcb->mp_conn_cb == NULL)
#endif
              TCP_EVENT_SENT(pcb, (u16_t)acked16, err);
#if LWIP_MPTCP_SUPPORT
            else
              err = ERR_OK;
#endif
            if (err == ERR_ABRT) {
              goto aborted;
            }
          }
          pTcpContext->recv_acked = 0;
        }
        if (pTcpContext->recv_flags & TF_CLOSED) {
          /* The connection has been closed and we will deallocate the
             PCB. */
          if (!(pcb->flags & TF_RXCLOSED)) {
            /* Connection closed although the application has only shut down the
               tx side: call the PCB's err callback and indicate the closure to
               ensure the application doesn't continue using the PCB. */
            TCP_EVENT_ERR(pcb->state, pcb->errf, pcb->callback_arg, ERR_CLSD);
          }

#if TCP_FIND
	  tcp_port_remove_from_list(pcb->local_port,pcb);
#endif
          tcp_pcb_remove(&pTcpContext->tcp_active_pcbs, pcb);
          memp_free(MEMP_TCP_PCB, pcb);
          goto aborted;
        }
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
        while (pTcpContext->recv_data != NULL) {
          struct pbuf *rest = NULL;
          pbuf_split_64k(pTcpContext->recv_data, &rest);
#else /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
        if (pTcpContext->recv_data != NULL) {
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

          LWIP_ASSERT("pcb->refused_data == NULL", pcb->refused_data == NULL);
          if (pcb->flags & TF_RXCLOSED) {
            /* received data although already closed -> abort (send RST) to
               notify the remote host that not all data has been processed */
            pbuf_free(pTcpContext->recv_data);
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            if (rest != NULL) {
              pbuf_free(rest);
            }
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
            tcp_abort(pcb);
            goto aborted;
          }

          /* Notify application that data has been received. */
#if LWIP_MPTCP_SUPPORT
          if(is_sfl_pcb(pcb)) /* This should not happen */
            err = ERR_OK;
          else
#endif
          TCP_EVENT_RECV(pcb, pTcpContext->recv_data, ERR_OK, err);
          if (err == ERR_ABRT) {
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            if (rest != NULL) {
              pbuf_free(rest);
            }
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
            goto aborted;
          }

          /* If the upper layer can't receive this data, store it */
          if (err != ERR_OK) {
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            if (rest != NULL) {
              pbuf_cat(pTcpContext->recv_data, rest);
            }
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
            pcb->refused_data = pTcpContext->recv_data;
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: keep incoming packet, because pcb is \"full\"\n"));
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            break;
          } else {
            /* Upper layer received the data, go on with the rest if > 64K */
            pTcpContext->recv_data = rest;
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
          }
        }

#if LWIP_MPTCP_SUPPORT
        if(pTcpContext->mptcp_recv_data != NULL){
          struct tcp_seg *mseg = pTcpContext->mptcp_recv_data, *nseg;
          while(mseg != NULL){
            /* data length may change in segment reordering */
            mseg->recv_info->sfl_data_seq = mseg->tcphdr->seqno;
            mseg->recv_info->sfl_data_len = TCP_TCPLEN(mseg);
            mseg->recv_info->sfl_fin_valid =
              (TCPH_FLAGS(mseg->tcphdr) & TCP_FIN) ? 1 : 0;
            LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: call mptcp_input(), pcb=%p",
                __FUNCTION__, __LINE__, pcb));
            mptcp_input(pcb, mseg->p, mseg->recv_info);
            nseg = mseg->next;
            mseg->p = NULL;
            tcp_seg_free(mseg);
            mseg = nseg;
          }
          pTcpContext->mptcp_recv_data = NULL;
        }
#endif
        /* If a FIN segment was received, we call the callback
           function with a NULL buffer to indicate EOF. */
        if (pTcpContext->recv_flags & TF_GOT_FIN) {
          if (pcb->refused_data != NULL) {
            /* Delay this if we have refused data. */
            pcb->refused_data->flags |= PBUF_FLAG_TCP_FIN;
          } else {
            /* correct rcv_wnd as the application won't call tcp_recved()
               for the FIN's seqno */
            if (pcb->rcv_wnd != TCP_WND_MAX(pcb)) {
              pcb->rcv_wnd++;
            }
#if LWIP_MPTCP_SUPPORT
            if(is_sfl_pcb(pcb)){
              /*for subflow,the all data has copy to meta pcb, we reset the rcv_wnd when rec fin*/
              pcb->rcv_wnd = TCP_WND_MAX(pcb);
              err = mptcp_fin_sfl_recved_fin(pcb);
              if (err == ERR_ABRT) {
                goto aborted;
              }
              /*In tcp_close_shutdown of tcp.c, we maybe sent a rst to network. and remove the pcb
               * from tcp_active_pcbs. If we do not free the pcb, it will caused memery leak*/
              if((err == ERR_OK) && (pcb->flags & TF_RXCLOSED) && (pTcpContext->recv_flags & TF_CLOSED)) {
#if TCP_FIND
                tcp_port_remove_from_list(pcb->local_port,pcb);
#endif
                memp_free(MEMP_TCP_PCB, pcb);
                goto aborted;
              }
            }else
#endif
            TCP_EVENT_CLOSED(pcb, err);
            if (err == ERR_ABRT) {
              goto aborted;
            }
          }
        }
#if LWIP_PERFORMANCE_ENABLE_DELAY_ACK
          pcb->pkt_recv_cnt ++;
          u32_t t_current = sys_now(pcb->instance);
          u32_t interval = t_current - pcb->t_last_time;
          if(interval >= 128000 ) {
            pcb->t_last_time = t_current;
            pcb->ack_delay_cnt = (u8_t)(pcb->pkt_recv_cnt*pcb->rto >> 7 >> 1);
            pcb->pkt_recv_cnt = 0;
          }
#endif
        pTcpContext->tcp_input_pcb = NULL;
        /* Try to send something out. */
        tcp_output(pcb);
#if LWIP_MPTCP_SUPPORT
        if(is_sfl_pcb(pcb) && pcb->meta_send_pending)
            mptcp_output(pcb->meta_pcb);
#endif
#if TCP_INPUT_DEBUG
#if TCP_DEBUG
        tcp_debug_print_state(pcb->state);
#endif /* TCP_DEBUG */
#endif /* TCP_INPUT_DEBUG */
      }
    }
    /* Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
       Below this line, 'pcb' may not be dereferenced! */
aborted:
    pTcpContext->tcp_input_pcb = NULL;
    pTcpContext->recv_data = NULL;

    /* give up our reference to inseg.p */
    if (pTcpSeg->p != NULL)
    {
      pbuf_free(pTcpSeg->p);
      pTcpSeg->p = NULL;
    }
  } else {

    /* If no matching PCB was found, send a TCP RST (reset) to the
       sender. */
    LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_input: no PCB match found, resetting.\n"));
    if (!(TCPH_FLAGS(pTcpContext->tcphdr) & TCP_RST)) {
      TCP_STATS_INC(tcp.proterr);
      TCP_STATS_INC(tcp.drop);
      tcp_rst(pLwipInstance,pTcpContext->ackno, pTcpContext->seqno + pTcpContext->tcplen, ip_current_dest_addr(inp->instance),
        ip_current_src_addr(inp->instance), pTcpContext->tcphdr->dest, pTcpContext->tcphdr->src);
    }
    pbuf_free(p);
  }

  LWIP_ASSERT("tcp_input: tcp_pcbs_sane()", tcp_pcbs_sane(pLwipInstance));
  PERF_STOP("tcp_input");
  return;
dropped:
  TCP_STATS_INC(tcp.drop);
  MIB2_STATS_INC(mib2.tcpinerrs);
  pbuf_free(p);
}

/**
 * Called by tcp_input() when a segment arrives for a listening
 * connection (from tcp_input()).
 *
 * @param pcb the tcp_pcb_listen for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static void
tcp_listen_input(struct tcp_pcb_listen *pcb, struct tcp_context *pTcpContext)
{
  struct tcp_pcb *npcb;
  u32_t iss;
  err_t rc;

  if (pTcpContext->flags & TCP_RST) {
    /* An incoming RST should be ignored. Return. */
    return;
  }

  /* In the LISTEN state, we check for incoming SYN segments,
     creates a new PCB, and responds with a SYN|ACK. */
  if (pTcpContext->flags & TCP_ACK) {
    /* For incoming segments with the ACK flag set, respond with a
       RST. */
    LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_listen_input: ACK in LISTEN, sending reset\n"));
    tcp_rst(pcb->instance,pTcpContext->ackno, pTcpContext->seqno + pTcpContext->tcplen, ip_current_dest_addr(pcb->instance),
      ip_current_src_addr(pcb->instance), pTcpContext->tcphdr->dest, pTcpContext->tcphdr->src);
  } else if (pTcpContext->flags & TCP_SYN) {
    LWIP_DEBUGF(TCP_DEBUG, ("TCP connection request %"U16_F" -> %"U16_F".\n", pTcpContext->tcphdr->src, pTcpContext->tcphdr->dest));
#if TCP_LISTEN_BACKLOG
    if (pcb->accepts_pending >= pcb->backlog) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_listen_input: listen backlog exceeded for port %"U16_F"\n", pTcpContext->tcphdr->dest));
      return;
    }
#endif /* TCP_LISTEN_BACKLOG */
    npcb = tcp_alloc(pcb->instance, pcb->prio);
    /* If a new PCB could not be created (probably due to lack of memory),
       we don't do anything, but rely on the sender will retransmit the
       SYN at a time when we have more memory available. */
    if (npcb == NULL) {
      err_t err;
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_listen_input: could not allocate PCB\n"));
      TCP_STATS_INC(tcp.memerr);
      TCP_EVENT_ACCEPT(pcb, NULL, pcb->callback_arg, ERR_MEM, err);
      LWIP_UNUSED_ARG(err); /* err not useful here */
      return;
    }
	npcb->instance = pcb->instance;
	npcb->mptcp_is_support = pcb->mptcp_is_support;
#if TCP_LISTEN_BACKLOG
    pcb->accepts_pending++;
    npcb->flags |= TF_BACKLOGPEND;
#endif /* TCP_LISTEN_BACKLOG */
    /* Set up the new PCB. */
    ip_addr_copy(npcb->local_ip, *ip_current_dest_addr(pcb->instance));
    ip_addr_copy(npcb->remote_ip, *ip_current_src_addr(pcb->instance));
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
    npcb->local_port = pTcpContext->tcphdr->dest;
#else
    npcb->local_port = pcb->local_port;
#endif
    npcb->remote_port = pTcpContext->tcphdr->src;
    npcb->state = SYN_RCVD;
    npcb->rcv_nxt = pTcpContext->seqno + 1;
    npcb->rcv_ann_right_edge = npcb->rcv_nxt;
    iss = tcp_next_iss(npcb, pTcpContext);
    npcb->snd_wl2 = iss;
    npcb->snd_nxt = iss;
    npcb->lastack = iss;
    npcb->snd_lbb = iss;
    npcb->snd_wl1 = pTcpContext->seqno - 1;/* initialise to seqno-1 to force window update */
    npcb->callback_arg = pcb->callback_arg;
#if LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG
    npcb->listener = pcb;
#endif /* LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG */
    /* inherit socket options */
    npcb->so_options = pcb->so_options & SOF_INHERITED;
#if LWIP_MPTCP_SUPPORT
    npcb->is_accept_pcb = 1;
#endif
#if LWIP_PERFORMANCE_IMPROVE
      npcb->is_nat_pcb = 1;
#endif
    /* Register the new PCB so that we can begin receiving segments
       for it. */
    TCP_REG_ACTIVE(npcb);

    /* Parse any options in the SYN. */
    tcp_parseopt(npcb,pTcpContext);
    
    npcb->snd_wnd = pTcpContext->tcphdr->wnd;
    npcb->snd_wnd_max = npcb->snd_wnd;

#if TCP_CALCULATE_EFF_SEND_MSS
    npcb->mss = tcp_eff_send_mss(npcb->instance,npcb->mss, &npcb->local_ip, &npcb->remote_ip);
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

    MIB2_STATS_INC(mib2.tcppassiveopens);

    /* Send a SYN|ACK together with the MSS option. */
    rc = tcp_enqueue_flags(npcb, TCP_SYN | TCP_ACK);
    if (rc != ERR_OK) {
      tcp_abandon(npcb, 0);
      return;
    }
    tcp_output(npcb);
  }
  return;
}

/**
 * Called by tcp_input() when a segment arrives for a connection in
 * TIME_WAIT.
 *
 * @param pcb the tcp_pcb for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static void
tcp_timewait_input(struct tcp_pcb *pcb, struct tcp_context *pTcpContext)
{
  /* RFC 1337: in TIME_WAIT, ignore RST and ACK FINs + any 'acceptable' segments */
  /* RFC 793 3.9 Event Processing - Segment Arrives:
   * - first check sequence number - we skip that one in TIME_WAIT (always
   *   acceptable since we only send ACKs)
   * - second check the RST bit (... return) */
  if (pTcpContext->flags & TCP_RST) {
    return;
  }
  /* - fourth, check the SYN bit, */
  if (pTcpContext->flags & TCP_SYN) {
    /* If an incoming segment is not acceptable, an acknowledgment
       should be sent in reply */
    if (TCP_SEQ_BETWEEN(pTcpContext->seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd)) {
      /* If the SYN is in the window it is an error, send a reset */
      tcp_rst(pcb->instance,pTcpContext->ackno, pTcpContext->seqno + pTcpContext->tcplen, ip_current_dest_addr(pcb->instance),
        ip_current_src_addr(pcb->instance), pTcpContext->tcphdr->dest, pTcpContext->tcphdr->src);
      return;
    }
  } else if (pTcpContext->flags & TCP_FIN) {
    /* - eighth, check the FIN bit: Remain in the TIME-WAIT state.
         Restart the 2 MSL time-wait timeout.*/
    pcb->tmr = pTcpContext->tcp_ticks;
  }

  if ((pTcpContext->tcplen > 0)) {
    /* Acknowledge data, FIN or out-of-window SYN */
    pcb->flags |= TF_ACK_NOW;
    tcp_output(pcb);
  }
  return;
}

/**
 * Implements the TCP state machine. Called by tcp_input. In some
 * states tcp_receive() is called to receive data. The tcp_seg
 * argument will be freed by the caller (tcp_input()) unless the
 * recv_data pointer in the pcb is set.
 *
 * @param pcb the tcp_pcb for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static err_t
tcp_process(struct tcp_pcb *pcb,struct tcp_context *pTcpContext)
{
  struct tcp_seg *rseg;
  u8_t acceptable = 0;
  err_t err;
  struct tcp_seg *pTcpSeg  = ((struct tcp_seg *)(pTcpContext->inseg));

  err = ERR_OK;

  /* Process incoming RST segments. */
  if (pTcpContext->flags & TCP_RST) {
    /* First, determine if the reset is acceptable. */
    if (pcb->state == SYN_SENT) {
      /* "In the SYN-SENT state (a RST received in response to an initial SYN),
          the RST is acceptable if the ACK field acknowledges the SYN." */
      if (pTcpContext->ackno == pcb->snd_nxt) {
        acceptable = 1;
      }
    } else {
      /* "In all states except SYN-SENT, all reset (RST) segments are validated
          by checking their SEQ-fields." */
      if (pTcpContext->seqno == pcb->rcv_nxt) {
        acceptable = 1;
      } else  if (TCP_SEQ_BETWEEN(pTcpContext->seqno, pcb->rcv_nxt,
                                  pcb->rcv_nxt + pcb->rcv_wnd)) {
        /* If the sequence number is inside the window, we only send an ACK
           and wait for a re-send with matching sequence number.
           This violates RFC 793, but is required to protection against
           CVE-2004-0230 (RST spoofing attack). */
        tcp_ack_now(pcb);
      }
    }

    if (acceptable) {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_process: Connection RESET\n"));
      LWIP_ASSERT("tcp_input: pcb->state != CLOSED", pcb->state != CLOSED);
      pTcpContext->recv_flags |= TF_RESET;
      pcb->flags &= ~TF_ACK_DELAY;
      return ERR_RST;
    } else {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_process: unacceptable reset seqno %"U32_F" rcv_nxt %"U32_F"\n",
       pTcpContext->seqno, pcb->rcv_nxt));
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_process: unacceptable reset seqno %"U32_F" rcv_nxt %"U32_F"\n",
       pTcpContext->seqno, pcb->rcv_nxt));
      return ERR_OK;
    }
  }

  if ((pTcpContext->flags & TCP_SYN) && (pcb->state != SYN_SENT && pcb->state != SYN_RCVD)) {
    /* Cope with new connection attempt after remote end crashed */
    tcp_ack_now(pcb);
    return ERR_OK;
  }

  if ((pcb->flags & TF_RXCLOSED) == 0) {
    /* Update the PCB (in)activity timer unless rx is closed (see tcp_shutdown) */
    pcb->tmr = pTcpContext->tcp_ticks;
  }
  pcb->keep_cnt_sent = 0;

  tcp_parseopt(pcb,pTcpContext);

  /* Do different things depending on the TCP state. */
  switch (pcb->state) {
  case SYN_SENT:
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("SYN-SENT: ackno %"U32_F" pcb->snd_nxt %"U32_F" unacked %"U32_F"\n", pTcpContext->ackno,
     pcb->snd_nxt, lwip_ntohl(pcb->unacked->tcphdr->seqno)));
    /* received SYN ACK with expected sequence number? */
    if ((pTcpContext->flags & TCP_ACK) && (pTcpContext->flags & TCP_SYN)
        && (pTcpContext->ackno == pcb->lastack + 1)) {
      pcb->rcv_nxt = pTcpContext->seqno + 1;
      pcb->rcv_ann_right_edge = pcb->rcv_nxt;
      pcb->lastack = pTcpContext->ackno;
      pcb->snd_wnd = pTcpContext->tcphdr->wnd;
      pcb->snd_wnd_max = pcb->snd_wnd;
      pcb->snd_wl1 = pTcpContext->seqno - 1; /* initialise to seqno - 1 to force window update */
      pcb->state = ESTABLISHED;

#if TCP_CALCULATE_EFF_SEND_MSS
      pcb->mss = tcp_eff_send_mss(pcb->instance,pcb->mss, &pcb->local_ip, &pcb->remote_ip);
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

      pcb->cwnd = LWIP_TCP_CALC_INITIAL_CWND(pcb->mss);
      LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_process (SENT): cwnd %"TCPWNDSIZE_F
                                   " ssthresh %"TCPWNDSIZE_F"\n",
                                   pcb->cwnd, pcb->ssthresh));
      LWIP_ASSERT("pcb->snd_queuelen > 0", (pcb->snd_queuelen > 0));
      --pcb->snd_queuelen;
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_process: SYN-SENT --queuelen %"TCPWNDSIZE_F"\n", (tcpwnd_size_t)pcb->snd_queuelen));
      rseg = pcb->unacked;
      if (rseg == NULL) {
        /* might happen if tcp_put fails in tcp_rexmit_rto()
           in which case the segment is on the unsent list */
        rseg = pcb->unsent;
        LWIP_ASSERT("no segment to free", rseg != NULL);
        pcb->unsent = rseg->next;
      } else {
        pcb->unacked = rseg->next;
      }
      tcp_seg_free(rseg);

      /* If there's nothing left to acknowledge, stop the retransmit
         timer, otherwise reset it to start again */
      if (pcb->unacked == NULL) {
        pcb->rtime = -1;
      } else {
        pcb->rtime = 0;
        pcb->nrtx = 0;
      }

      /* Call the user specified function to call when successfully
       * connected. */
#if LWIP_MPTCP_SUPPORT
      /* For meta pcb, deley notification of connected event until 3rd ACK
       * is sent */
      if(is_meta_pcb(pcb))
        pcb->delay_conn_evt = 1;
      else
#endif
      TCP_EVENT_CONNECTED(pcb, ERR_OK, err);
      if (err == ERR_ABRT) {
        return ERR_ABRT;
      }
      tcp_ack_now(pcb);
    }
    /* received ACK? possibly a half-open connection */
    else if (pTcpContext->flags & TCP_ACK) {
      /* send a RST to bring the other side in a non-synchronized state. */
      tcp_rst(pcb->instance,pTcpContext->ackno, pTcpContext->seqno + pTcpContext->tcplen, ip_current_dest_addr(pcb->instance),
        ip_current_src_addr(pcb->instance), pTcpContext->tcphdr->dest, pTcpContext->tcphdr->src);
      /* Resend SYN immediately (don't wait for rto timeout) to establish
        connection faster, but do not send more SYNs than we otherwise would
        have, or we might get caught in a loop on loopback interfaces. */
      if (pcb->nrtx < TCP_SYNMAXRTX) {
        pcb->rtime = 0;
        tcp_rexmit_rto(pcb);
      }
    }
    break;
  case SYN_RCVD:
    if (pTcpContext->flags & TCP_ACK) {
      /* expected ACK number? */
      if (TCP_SEQ_BETWEEN(pTcpContext->ackno, pcb->lastack+1, pcb->snd_nxt)) {
        pcb->state = ESTABLISHED;
        LWIP_DEBUGF(TCP_DEBUG, ("TCP connection established %"U16_F" -> %"U16_F".\n", pTcpSeg->tcphdr->src, pTcpSeg->tcphdr->dest));
#if LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG
        if (pcb->listener == NULL) {
          /* listen pcb might be closed by now */
          err = ERR_VAL;
        } else
#endif /* LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG */
        {
#if LWIP_CALLBACK_API
          LWIP_ASSERT("pcb->listener->accept != NULL", pcb->listener->accept != NULL);
#endif
          tcp_backlog_accepted(pcb);
          /* Call the accept function. */
          TCP_EVENT_ACCEPT(pcb->listener, pcb, pcb->callback_arg, ERR_OK, err);
        }
        if (err != ERR_OK) {
          /* If the accept function returns with an error, we abort
           * the connection. */
          /* Already aborted? */
          if (err != ERR_ABRT) {
            tcp_abort(pcb);
          }
          return ERR_ABRT;
        }
        /* If there was any data contained within this ACK,
         * we'd better pass it on to the application as well. */
        tcp_receive(pcb, pTcpContext);

        /* Prevent ACK for SYN to generate a sent event */
        if (pTcpContext->recv_acked != 0) {
          pTcpContext->recv_acked--;
        }

        pcb->cwnd = LWIP_TCP_CALC_INITIAL_CWND(pcb->mss);
        LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_process (SYN_RCVD): cwnd %"TCPWNDSIZE_F
                                     " ssthresh %"TCPWNDSIZE_F"\n",
                                     pcb->cwnd, pcb->ssthresh));

        if (pTcpContext->recv_flags & TF_GOT_FIN) {
          tcp_ack_now(pcb);
          pcb->state = CLOSE_WAIT;
        }
      } else {
        /* incorrect ACK number, send RST */
        tcp_rst(pcb->instance,pTcpContext->ackno, pTcpContext->seqno + pTcpContext->tcplen, ip_current_dest_addr(pcb->instance),
          ip_current_src_addr(pcb->instance), pTcpContext->tcphdr->dest, pTcpContext->tcphdr->src);
      }
    } else if ((pTcpContext->flags & TCP_SYN) && (pTcpContext->seqno == pcb->rcv_nxt - 1)) {
      /* Looks like another copy of the SYN - retransmit our SYN-ACK */
      tcp_rexmit(pcb);
    }
    break;
  case CLOSE_WAIT:
    /* FALLTHROUGH */
  case ESTABLISHED:
    tcp_receive(pcb,pTcpContext);
    if (pTcpContext->recv_flags & TF_GOT_FIN) { /* passive close */
      tcp_ack_now(pcb);
      pcb->state = CLOSE_WAIT;
    }
    break;
  case FIN_WAIT_1:
    tcp_receive(pcb,pTcpContext);
    if (pTcpContext->recv_flags & TF_GOT_FIN) {
      if ((pTcpContext->flags & TCP_ACK) && (pTcpContext->ackno == pcb->snd_nxt) &&
          pcb->unsent == NULL) {
        LWIP_DEBUGF(TCP_DEBUG,
          ("TCP connection closed: FIN_WAIT_1 %"U16_F" -> %"U16_F".\n", pTcpSeg->tcphdr->src, pTcpSeg->tcphdr->dest));
        tcp_ack_now(pcb);
        tcp_pcb_purge(pcb);
        TCP_RMV_ACTIVE(pcb);
        pcb->state = TIME_WAIT;
        TCP_REG(&pTcpContext->tcp_tw_pcbs, pcb);
      } else {
        tcp_ack_now(pcb);
        pcb->state = CLOSING;
      }
    } else if ((pTcpContext->flags & TCP_ACK) && (pTcpContext->ackno == pcb->snd_nxt) &&
               pcb->unsent == NULL) {
      pcb->state = FIN_WAIT_2;
    }
    break;
  case FIN_WAIT_2:
    tcp_receive(pcb,pTcpContext);
    if (pTcpContext->recv_flags & TF_GOT_FIN) {
      LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed: FIN_WAIT_2 %"U16_F" -> %"U16_F".\n", pTcpSeg->tcphdr->src, pTcpSeg->tcphdr->dest));
      tcp_ack_now(pcb);
      tcp_pcb_purge(pcb);
      TCP_RMV_ACTIVE(pcb);
      pcb->state = TIME_WAIT;
      TCP_REG(&pTcpContext->tcp_tw_pcbs, pcb);
    }
    break;
  case CLOSING:
    tcp_receive(pcb,pTcpContext);
    if ((pTcpContext->flags & TCP_ACK) && pTcpContext->ackno == pcb->snd_nxt && pcb->unsent == NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed: CLOSING %"U16_F" -> %"U16_F".\n", pTcpSeg->tcphdr->src, pTcpSeg->tcphdr->dest));
      tcp_pcb_purge(pcb);
      TCP_RMV_ACTIVE(pcb);
      pcb->state = TIME_WAIT;
      TCP_REG(&pTcpContext->tcp_tw_pcbs, pcb);
    }
    break;
  case LAST_ACK:
    tcp_receive(pcb,pTcpContext);
    if ((pTcpContext->flags & TCP_ACK) && pTcpContext->ackno == pcb->snd_nxt && pcb->unsent == NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed: LAST_ACK %"U16_F" -> %"U16_F".\n", pTcpSeg->tcphdr->src, pTcpSeg->tcphdr->dest));
      /* bugfix #21699: don't set pcb->state to CLOSED here or we risk leaking segments */
      pTcpContext->recv_flags |= TF_CLOSED;
    }
    break;
  default:
    break;
  }
  return ERR_OK;
}

#if TCP_QUEUE_OOSEQ
/**
 * Insert segment into the list (segments covered with new one will be deleted)
 *
 * Called from tcp_receive()
 */
static void
tcp_oos_insert_segment(struct tcp_seg *cseg, struct tcp_seg *next, struct tcp_context *pTcpContext)
{
  struct tcp_seg *old_seg;

  if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN) {
    /* received segment overlaps all following segments */
    tcp_segs_free(next);
    next = NULL;
  } else {
    /* delete some following segments
       oos queue may have segments with FIN flag */
    while (next &&
           TCP_SEQ_GEQ((pTcpContext->seqno + cseg->len),
                      (next->tcphdr->seqno + next->len))) {
      /* cseg with FIN already processed */
      if (TCPH_FLAGS(next->tcphdr) & TCP_FIN) {
        TCPH_SET_FLAG(cseg->tcphdr, TCP_FIN);
      }
      old_seg = next;
      next = next->next;
      tcp_seg_free(old_seg);
    }
    if (next &&
        TCP_SEQ_GT(pTcpContext->seqno + cseg->len, next->tcphdr->seqno)) {
      /* We need to trim the incoming segment. */
      cseg->len = (u16_t)(next->tcphdr->seqno - pTcpContext->seqno);
      pbuf_realloc(cseg->p, cseg->len);
    }
  }
  cseg->next = next;
}
#endif /* TCP_QUEUE_OOSEQ */

/**
 * Called by tcp_process. Checks if the given segment is an ACK for outstanding
 * data, and if so frees the memory of the buffered data. Next, it places the
 * segment on any of the receive queues (pcb->recved or pcb->ooseq). If the segment
 * is buffered, the pbuf is referenced by pbuf_ref so that it will not be freed until
 * it has been removed from the buffer.
 *
 * If the incoming segment constitutes an ACK for a segment that was used for RTT
 * estimation, the RTT is estimated here as well.
 *
 * Called from tcp_process().
 */
static void
tcp_receive(struct tcp_pcb *pcb, struct tcp_context *pTcpContext)
{
  struct tcp_seg *next;
#if TCP_QUEUE_OOSEQ
  struct tcp_seg *prev, *cseg;
#endif /* TCP_QUEUE_OOSEQ */
  s32_t off;
  s16_t m;
  u32_t right_wnd_edge;
  u16_t new_tot_len;
  int found_dupack = 0;
#if TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS
  u32_t ooseq_blen;
  u16_t ooseq_qlen;
#endif /* TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS */
#if LWIP_MPTCP_SUPPORT
  u8_t recv_info_need_free = 0;
  p_mptcp_recv_info recv_info = NULL;
  struct tcp_seg *mseg, *eseg = NULL;
  struct tcp_seg *pTcpSeg = (struct tcp_seg *)pTcpContext->inseg;

  if(is_sfl_pcb(pcb)){
    p_mptcp_recv_info tmp = NULL;
	recv_info = (p_mptcp_recv_info)malloc(sizeof(mptcp_recv_info));
    LWIP_ASSERT("No memory", recv_info != NULL);
    /* Need to be improved */
    recv_info_need_free = 1;
    tmp = mptcp_get_recv_info(pcb->instance, recv_info);
    if(tmp){
      /*memcpy(recv_info, tmp, sizeof(mptcp_recv_info));*/
      mptcp_invalidate_recv_info(pcb->instance);
    }
  }
#endif

  LWIP_ASSERT("tcp_receive: wrong state", pcb->state >= ESTABLISHED);

  if (pTcpContext->flags & TCP_ACK) {

#if LWIP_MPTCP_SUPPORT
    if((pcb->mpc) && (!pcb->is_master_pcb))
    {
	    if( NULL != pcb->mp_sfl_pcb)
	  	{
		  if(pcb->mp_sfl_pcb->pre_established){
		    pcb->mp_sfl_pcb->pre_established = 0;
		    pcb->mp_conn_cb->cnt_established++;
		    LWIP_DEBUGF(TCP_WND_DEBUG, ("Receive subflow final ack,leave pre_established state."));
		  }
	  	}
    }
#endif

    right_wnd_edge = pcb->snd_wnd + pcb->snd_wl2;

    /* Update window. */
    if (TCP_SEQ_LT(pcb->snd_wl1, pTcpContext->seqno) ||
       (pcb->snd_wl1 == pTcpContext->seqno && TCP_SEQ_LT(pcb->snd_wl2, pTcpContext->ackno)) ||
       (pcb->snd_wl2 == pTcpContext->ackno && (u32_t)SND_WND_SCALE(pcb, pTcpContext->tcphdr->wnd) > pcb->snd_wnd)) {
      pcb->snd_wnd = SND_WND_SCALE(pcb, pTcpContext->tcphdr->wnd);
      /* keep track of the biggest window announced by the remote host to calculate
         the maximum segment size */
      if (pcb->snd_wnd_max < pcb->snd_wnd) {
        pcb->snd_wnd_max = pcb->snd_wnd;
      }
      pcb->snd_wl1 = pTcpContext->seqno;
      pcb->snd_wl2 = pTcpContext->ackno;
      if (pcb->snd_wnd == 0) {
        if (pcb->persist_backoff == 0) {
          /* start persist timer */
          pcb->persist_cnt = 0;
          pcb->persist_backoff = 1;
        }
      } else if (pcb->persist_backoff > 0) {
        /* stop persist timer */
          pcb->persist_backoff = 0;
      }
      LWIP_DEBUGF(TCP_WND_DEBUG, ("tcp_receive: window update %"TCPWNDSIZE_F"\n", pcb->snd_wnd));
#if TCP_WND_DEBUG
    } else {
      if (pcb->snd_wnd != (tcpwnd_size_t)SND_WND_SCALE(pcb, pTcpContext->tcphdr->wnd)) {
        LWIP_DEBUGF(TCP_WND_DEBUG,
                    ("tcp_receive: no window update lastack %"U32_F" ackno %"
                     U32_F" wl1 %"U32_F" seqno %"U32_F" wl2 %"U32_F"\n",
                     pcb->lastack, pTcpContext->ackno, pcb->snd_wl1, pTcpContext->seqno, pcb->snd_wl2));
      }
#endif /* TCP_WND_DEBUG */
    }

    /* (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a
     * duplicate ack if:
     * 1) It doesn't ACK new data
     * 2) length of received packet is zero (i.e. no payload)
     * 3) the advertised window hasn't changed
     * 4) There is outstanding unacknowledged data (retransmission timer running)
     * 5) The ACK is == biggest ACK sequence number so far seen (snd_una)
     *
     * If it passes all five, should process as a dupack:
     * a) dupacks < 3: do nothing
     * b) dupacks == 3: fast retransmit
     * c) dupacks > 3: increase cwnd
     *
     * If it only passes 1-3, should reset dupack counter (and add to
     * stats, which we don't do in lwIP)
     *
     * If it only passes 1, should reset dupack counter
     *
     */

    /* Clause 1 */
    if (TCP_SEQ_LEQ(pTcpContext->ackno, pcb->lastack)) {
      /* Clause 2 */
      if (pTcpContext->tcplen == 0) {
        /* Clause 3 */
        if (pcb->snd_wl2 + pcb->snd_wnd == right_wnd_edge) {
          /* Clause 4 */
          if (pcb->rtime >= 0) {
            /* Clause 5 */
            if (pcb->lastack == pTcpContext->ackno) {
              found_dupack = 1;
              if ((u8_t)(pcb->dupacks + 1) > pcb->dupacks) {
                ++pcb->dupacks;
              }
              if (pcb->dupacks > 3) {
                /* Inflate the congestion window, but not if it means that
                   the value overflows. */
                if ((tcpwnd_size_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
                  pcb->cwnd += pcb->mss;
                }
              } else if (pcb->dupacks == 3) {
                /* Do fast retransmit */
                tcp_rexmit_fast(pcb);
              }
            }
          }
        }
      }
      /* If Clause (1) or more is true, but not a duplicate ack, reset
       * count of consecutive duplicate acks */
      if (!found_dupack) {
        pcb->dupacks = 0;
      }
    } else if (TCP_SEQ_BETWEEN(pTcpContext->ackno, pcb->lastack+1, pcb->snd_nxt)) {
      /* We come here when the ACK acknowledges new data. */

      /* Reset the "IN Fast Retransmit" flag, since we are no longer
         in fast retransmit. Also reset the congestion window to the
         slow start threshold. */
      if (pcb->flags & TF_INFR) {
        pcb->flags &= ~TF_INFR;
        pcb->cwnd = pcb->ssthresh;
      }

      /* Reset the number of retransmissions. */
      pcb->nrtx = 0;

      /* Reset the retransmission time-out. */
      pcb->rto = (pcb->sa >> 3) + pcb->sv;
      if((!is_meta_pcb(pcb)) && pcb->meta_pcb)
      {
        mptcp_set_rto(pcb->meta_pcb);
      }

      /* Reset the fast retransmit variables. */
      pcb->dupacks = 0;
      pcb->lastack = pTcpContext->ackno;

      /* Update the congestion control variables (cwnd and
         ssthresh). */
      if (pcb->state >= ESTABLISHED) {
        if (pcb->cwnd < pcb->ssthresh) {
          if ((tcpwnd_size_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
            pcb->cwnd += pcb->mss;
          }
          LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: slow start cwnd %"TCPWNDSIZE_F"\n", pcb->cwnd));
        } else {
          tcpwnd_size_t new_cwnd = (pcb->cwnd + pcb->mss * pcb->mss / pcb->cwnd);
          if (new_cwnd > pcb->cwnd) {
            pcb->cwnd = new_cwnd;
          }
          LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: congestion avoidance cwnd %"TCPWNDSIZE_F"\n", pcb->cwnd));
        }
      }
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: ACK for %"U32_F", unacked->seqno %"U32_F":%"U32_F"\n",
                                    pTcpContext->ackno,
                                    pcb->unacked != NULL?
                                    lwip_ntohl(pcb->unacked->tcphdr->seqno): 0,
                                    pcb->unacked != NULL?
                                    lwip_ntohl(pcb->unacked->tcphdr->seqno) + TCP_TCPLEN(pcb->unacked): 0));

      /* Remove segment from the unacknowledged list if the incoming
         ACK acknowledges them. */
      while (pcb->unacked != NULL &&
             TCP_SEQ_LEQ(lwip_ntohl(pcb->unacked->tcphdr->seqno) +
                         TCP_TCPLEN(pcb->unacked), pTcpContext->ackno)) {
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: removing %"U32_F":%"U32_F" from pcb->unacked\n",
                                      lwip_ntohl(pcb->unacked->tcphdr->seqno),
                                      lwip_ntohl(pcb->unacked->tcphdr->seqno) +
                                      TCP_TCPLEN(pcb->unacked)));

        next = pcb->unacked;
        pcb->unacked = pcb->unacked->next;
        LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %"TCPWNDSIZE_F" ... ", (tcpwnd_size_t)pcb->snd_queuelen));
        LWIP_ASSERT("pcb->snd_queuelen >= pbuf_clen(next->p)", (pcb->snd_queuelen >= pbuf_clen(next->p)));

        pcb->snd_queuelen -= pbuf_clen(next->p);
        pTcpContext->recv_acked += next->len;
        tcp_seg_free(next);

        LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%"TCPWNDSIZE_F" (after freeing unacked)\n", (tcpwnd_size_t)pcb->snd_queuelen));
        if (pcb->snd_queuelen != 0) {
          LWIP_ASSERT("tcp_receive: valid queue length", pcb->unacked != NULL ||
                      pcb->unsent != NULL);
        }
      }

      /* If there's nothing left to acknowledge, stop the retransmit
         timer, otherwise reset it to start again */
      if (pcb->unacked == NULL) {
        pcb->rtime = -1;
      } else {
        pcb->rtime = 0;
      }

      pcb->polltmr = 0;

#if LWIP_IPV6 && LWIP_ND6_TCP_REACHABILITY_HINTS
      if (ip_current_is_v6()) {
        /* Inform neighbor reachability of forward progress. */
        nd6_reachability_hint(ip6_current_src_addr());
      }
#endif /* LWIP_IPV6 && LWIP_ND6_TCP_REACHABILITY_HINTS*/
    } else {
      /* Out of sequence ACK, didn't really ack anything */
      tcp_send_empty_ack(pcb);
    }

    /* We go through the ->unsent list to see if any of the segments
       on the list are acknowledged by the ACK. This may seem
       strange since an "unsent" segment shouldn't be acked. The
       rationale is that lwIP puts all outstanding segments on the
       ->unsent list after a retransmission, so these segments may
       in fact have been sent once. */
    while (pcb->unsent != NULL &&
           TCP_SEQ_BETWEEN(pTcpContext->ackno, lwip_ntohl(pcb->unsent->tcphdr->seqno) +
                           TCP_TCPLEN(pcb->unsent), pcb->snd_nxt)) {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: removing %"U32_F":%"U32_F" from pcb->unsent\n",
                                    lwip_ntohl(pcb->unsent->tcphdr->seqno), lwip_ntohl(pcb->unsent->tcphdr->seqno) +
                                    TCP_TCPLEN(pcb->unsent)));

      next = pcb->unsent;
      pcb->unsent = pcb->unsent->next;
#if TCP_OVERSIZE
      if (pcb->unsent == NULL) {
        pcb->unsent_oversize = 0;
      }
#endif /* TCP_OVERSIZE */
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %"TCPWNDSIZE_F" ... ", (tcpwnd_size_t)pcb->snd_queuelen));
      LWIP_ASSERT("pcb->snd_queuelen >= pbuf_clen(next->p)", (pcb->snd_queuelen >= pbuf_clen(next->p)));
      /* Prevent ACK for FIN to generate a sent event */
      pcb->snd_queuelen -= pbuf_clen(next->p);
      pTcpContext->recv_acked += next->len;
      tcp_seg_free(next);
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%"TCPWNDSIZE_F" (after freeing unsent)\n", (tcpwnd_size_t)pcb->snd_queuelen));
      if (pcb->snd_queuelen != 0) {
        LWIP_ASSERT("tcp_receive: valid queue length",
          pcb->unacked != NULL || pcb->unsent != NULL);
      }
    }
    pcb->snd_buf += pTcpContext->recv_acked;
    /* End of ACK for new data processing. */

    LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: pcb->rttest %"U32_F" rtseq %"U32_F" ackno %"U32_F"\n",
                                pcb->rttest, pcb->rtseq, pTcpContext->ackno));

    /* RTT estimation calculations. This is done by checking if the
       incoming segment acknowledges the segment we use to take a
       round-trip time measurement. */
    if (pcb->rttest && TCP_SEQ_LT(pcb->rtseq, pTcpContext->ackno)) {
      /* diff between this shouldn't exceed 32K since this are tcp timer ticks
         and a round-trip shouldn't be that long... */
      m = (s16_t)(pTcpContext->tcp_ticks - pcb->rttest);

      LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: experienced rtt %"U16_F" ticks (%"U16_F" msec).\n",
                                  m, (u16_t)(m * TCP_SLOW_INTERVAL)));

      /* This is taken directly from VJs original code in his paper */
      m = m - (pcb->sa >> 3);
      pcb->sa += m;
      if (m < 0) {
        m = -m;
      }
      m = m - (pcb->sv >> 2);
      pcb->sv += m;
      pcb->rto = (pcb->sa >> 3) + pcb->sv;
	  if((!is_meta_pcb(pcb)) && pcb->meta_pcb)
	  {
		  mptcp_set_rto(pcb->meta_pcb);
	  }

      LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: RTO %"U16_F" (%"U16_F" milliseconds)\n",
                                  pcb->rto, (u16_t)(pcb->rto * TCP_SLOW_INTERVAL)));

      pcb->rttest = 0;
    }
  }

  /* If the incoming segment contains data, we must process it
     further unless the pcb already received a FIN.
     (RFC 793, chapter 3.9, "SEGMENT ARRIVES" in states CLOSE-WAIT, CLOSING,
     LAST-ACK and TIME-WAIT: "Ignore the segment text.") */
  if ((pTcpContext->tcplen > 0) && (pcb->state < CLOSE_WAIT)) {
    /* This code basically does three things:

    +) If the incoming segment contains data that is the next
    in-sequence data, this data is passed to the application. This
    might involve trimming the first edge of the data. The rcv_nxt
    variable and the advertised window are adjusted.

    +) If the incoming segment has data that is above the next
    sequence number expected (->rcv_nxt), the segment is placed on
    the ->ooseq queue. This is done by finding the appropriate
    place in the ->ooseq queue (which is ordered by sequence
    number) and trim the segment in both ends if needed. An
    immediate ACK is sent to indicate that we received an
    out-of-sequence segment.

    +) Finally, we check if the first segment on the ->ooseq queue
    now is in sequence (i.e., if rcv_nxt >= ooseq->seqno). If
    rcv_nxt > ooseq->seqno, we must trim the first edge of the
    segment on ->ooseq before we adjust rcv_nxt. The data in the
    segments that are now on sequence are chained onto the
    incoming segment so that we only need to call the application
    once.
    */

    /* First, we check if we must trim the first edge. We have to do
       this if the sequence number of the incoming segment is less
       than rcv_nxt, and the sequence number plus the length of the
       segment is larger than rcv_nxt. */
    /*    if (TCP_SEQ_LT(seqno, pcb->rcv_nxt)) {
          if (TCP_SEQ_LT(pcb->rcv_nxt, seqno + tcplen)) {*/
    if (TCP_SEQ_BETWEEN(pcb->rcv_nxt, pTcpContext->seqno + 1, pTcpContext->seqno + pTcpContext->tcplen - 1)) {
      /* Trimming the first edge is done by pushing the payload
         pointer in the pbuf downwards. This is somewhat tricky since
         we do not want to discard the full contents of the pbuf up to
         the new starting point of the data since we have to keep the
         TCP header which is present in the first pbuf in the chain.

         What is done is really quite a nasty hack: the first pbuf in
         the pbuf chain is pointed to by inseg.p. Since we need to be
         able to deallocate the whole pbuf, we cannot change this
         inseg.p pointer to point to any of the later pbufs in the
         chain. Instead, we point the ->payload pointer in the first
         pbuf to data in one of the later pbufs. We also set the
         inseg.data pointer to point to the right place. This way, the
         ->p pointer will still point to the first pbuf, but the
         ->p->payload pointer will point to data in another pbuf.

         After we are done with adjusting the pbuf pointers we must
         adjust the ->data pointer in the seg and the segment
         length.*/

      struct pbuf *p = pTcpSeg->p;
      off = pcb->rcv_nxt - pTcpContext->seqno;
      LWIP_ASSERT("inseg.p != NULL", pTcpSeg->p);
      LWIP_ASSERT("insane offset!", (off < 0x7fff));
      if (pTcpSeg->p->len < off) {
        LWIP_ASSERT("pbuf too short!", (((s32_t)pTcpSeg->p->tot_len) >= off));
        new_tot_len = (u16_t)(pTcpSeg->p->tot_len - off);
        while (p->len < off) {
          off -= p->len;
          /* KJM following line changed (with addition of new_tot_len var)
             to fix bug #9076
             inseg.p->tot_len -= p->len; */
          p->tot_len = new_tot_len;
          p->len = 0;
          p = p->next;
        }
        if (pbuf_header(p, (s16_t)-off)) {
          /* Do we need to cope with this failing?  Assert for now */
          LWIP_ASSERT("pbuf_header failed", 0);
        }
      } else {
        if (pbuf_header(pTcpSeg->p, (s16_t)-off)) {
          /* Do we need to cope with this failing?  Assert for now */
          LWIP_ASSERT("pbuf_header failed", 0);
        }
      }
      pTcpSeg->len -= (u16_t)(pcb->rcv_nxt - pTcpContext->seqno);
      pTcpSeg->tcphdr->seqno = pTcpContext->seqno = pcb->rcv_nxt;
    }
    else {
      if (TCP_SEQ_LT(pTcpContext->seqno, pcb->rcv_nxt)) {
        /* the whole segment is < rcv_nxt */
        /* must be a duplicate of a packet that has already been correctly handled */

        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: duplicate seqno %"U32_F"\n", pTcpContext->seqno));
        tcp_ack_now(pcb);
      }
    }

    /* The sequence number must be within the window (above rcv_nxt
       and below rcv_nxt + rcv_wnd) in order to be further
       processed. */
    if (TCP_SEQ_BETWEEN(pTcpContext->seqno, pcb->rcv_nxt,
                        pcb->rcv_nxt + pcb->rcv_wnd - 1)) {
#if LWIP_MPTCP_SUPPORT
      if(is_sfl_pcb(pcb))
        recv_info->sfl_data_csum = pTcpContext->tcp_data_csum;
#endif
      if (pcb->rcv_nxt == pTcpContext->seqno) {
        /* The incoming segment is the next in sequence. We check if
           we have to trim the end of the segment and update rcv_nxt
           and pass the data to the application. */
        pTcpContext->tcplen = TCP_TCPLEN(pTcpSeg);

        if (pTcpContext->tcplen > pcb->rcv_wnd) {
          LWIP_DEBUGF(TCP_INPUT_DEBUG,
                      ("tcp_receive: other end overran receive window"
                       "seqno %"U32_F" len %"U16_F" right edge %"U32_F"\n",
                       pTcpContext->seqno, pTcpContext->tcplen, pcb->rcv_nxt + pcb->rcv_wnd));
          if (TCPH_FLAGS(pTcpSeg->tcphdr) & TCP_FIN) {
            /* Must remove the FIN from the header as we're trimming
             * that byte of sequence-space from the packet */
            TCPH_FLAGS_SET(pTcpSeg->tcphdr, TCPH_FLAGS(pTcpSeg->tcphdr) & ~(unsigned int)TCP_FIN);
          }
          /* Adjust length of segment to fit in the window. */
          TCPWND_CHECK16(pcb->rcv_wnd);
          pTcpSeg->len = (u16_t)pcb->rcv_wnd;
          if (TCPH_FLAGS(pTcpSeg->tcphdr) & TCP_SYN) {
            pTcpSeg->len -= 1;
          }
          pbuf_realloc(pTcpSeg->p, pTcpSeg->len);
          pTcpContext->tcplen = TCP_TCPLEN(pTcpSeg);
          LWIP_ASSERT("tcp_receive: segment not trimmed correctly to rcv_wnd\n",
                      (pTcpContext->seqno + pTcpContext->tcplen) == (pcb->rcv_nxt + pcb->rcv_wnd));
        }
#if TCP_QUEUE_OOSEQ
        /* Received in-sequence data, adjust ooseq data if:
           - FIN has been received or
           - inseq overlaps with ooseq */
        if (pcb->ooseq != NULL) {
          if (TCPH_FLAGS(pTcpSeg->tcphdr) & TCP_FIN) {
            LWIP_DEBUGF(TCP_INPUT_DEBUG,
                        ("tcp_receive: received in-order FIN, binning ooseq queue\n"));
            /* Received in-order FIN means anything that was received
             * out of order must now have been received in-order, so
             * bin the ooseq queue */
            while (pcb->ooseq != NULL) {
              struct tcp_seg *old_ooseq = pcb->ooseq;
              pcb->ooseq = pcb->ooseq->next;
              tcp_seg_free(old_ooseq);
            }
          } else {
            next = pcb->ooseq;
            /* Remove all segments on ooseq that are covered by inseg already.
             * FIN is copied from ooseq to inseg if present. */
            while (next &&
                   TCP_SEQ_GEQ(pTcpContext->seqno + pTcpContext->tcplen,
                               next->tcphdr->seqno + next->len)) {
              /* inseg cannot have FIN here (already processed above) */
              if ((TCPH_FLAGS(next->tcphdr) & TCP_FIN) != 0 &&
                  (TCPH_FLAGS(pTcpSeg->tcphdr) & TCP_SYN) == 0) {
                TCPH_SET_FLAG(pTcpSeg->tcphdr, TCP_FIN);
                pTcpContext->tcplen = TCP_TCPLEN(pTcpSeg);
              }
              prev = next;
              next = next->next;
              tcp_seg_free(prev);
            }
            /* Now trim right side of inseg if it overlaps with the first
             * segment on ooseq */
            if (next &&
                TCP_SEQ_GT(pTcpContext->seqno + pTcpContext->tcplen,
                           next->tcphdr->seqno)) {
              /* inseg cannot have FIN here (already processed above) */
              pTcpSeg->len = (u16_t)(next->tcphdr->seqno - pTcpContext->seqno);
              if (TCPH_FLAGS(pTcpSeg->tcphdr) & TCP_SYN) {
                pTcpSeg->len -= 1;
              }
              pbuf_realloc(pTcpSeg->p, pTcpSeg->len);
              pTcpContext->tcplen = TCP_TCPLEN(pTcpSeg);
              LWIP_ASSERT("tcp_receive: segment not trimmed correctly to ooseq queue\n",
                          (pTcpContext->seqno + pTcpContext->tcplen) == next->tcphdr->seqno);
            }
            pcb->ooseq = next;
          }
        }
#endif /* TCP_QUEUE_OOSEQ */

        pcb->rcv_nxt = pTcpContext->seqno + pTcpContext->tcplen;

        /* Update the receiver's (our) window. */
        LWIP_ASSERT("tcp_receive: tcplen > rcv_wnd\n", pcb->rcv_wnd >= pTcpContext->tcplen);
        pcb->rcv_wnd -= pTcpContext->tcplen;

        tcp_update_rcv_ann_wnd(pcb);

        /* If there is data in the segment, we make preparations to
           pass this up to the application. The ->recv_data variable
           is used for holding the pbuf that goes to the
           application. The code for reassembling out-of-sequence data
           chains its data on this pbuf as well.

           If the segment was a FIN, we set the TF_GOT_FIN flag that will
           be used to indicate to the application that the remote side has
           closed its end of the connection. */
        if (pTcpSeg->p->tot_len > 0) {
#if LWIP_MPTCP_SUPPORT
          if(is_sfl_pcb(pcb)){
            LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: recved in order data, pcb=%p"
              ", len=%d, seq=%08x", __FUNCTION__, __LINE__, pcb,
              TCP_TCPLEN(pTcpSeg), pTcpContext->seqno));
            mseg = tcp_seg_copy(pcb->instance,pTcpSeg);
            LWIP_ASSERT("No memory", mseg != NULL); /* Need to be improved */
            mseg->next = NULL;
            mseg->recv_info = recv_info;
            recv_info_need_free = 0;
            pTcpContext->mptcp_recv_data = eseg = mseg;
            pbuf_free(pTcpSeg->p); /* decrease p->ref , as it increased by
                                 * tcp_seg_copy() */
          }else
#endif
          pTcpContext->recv_data = pTcpSeg->p;
          /* Since this pbuf now is the responsibility of the
             application, we delete our reference to it so that we won't
             (mistakingly) deallocate it. */
          pTcpSeg->p = NULL;
        }
        if (TCPH_FLAGS(pTcpSeg->tcphdr) & TCP_FIN) {
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: received FIN.\n"));
          pTcpContext->recv_flags |= TF_GOT_FIN;
        }

#if TCP_QUEUE_OOSEQ
        /* We now check if we have segments on the ->ooseq queue that
           are now in sequence. */
        while (pcb->ooseq != NULL &&
               pcb->ooseq->tcphdr->seqno == pcb->rcv_nxt) {

          cseg = pcb->ooseq;
          pTcpContext->seqno = pcb->ooseq->tcphdr->seqno;

          pcb->rcv_nxt += TCP_TCPLEN(cseg);
          LWIP_ASSERT("tcp_receive: ooseq tcplen > rcv_wnd\n",
                      pcb->rcv_wnd >= TCP_TCPLEN(cseg));
          pcb->rcv_wnd -= TCP_TCPLEN(cseg);

          tcp_update_rcv_ann_wnd(pcb);

          if (cseg->p->tot_len > 0) {
            /* Chain this pbuf onto the pbuf that we will pass to
               the application. */
            /* With window scaling, this can overflow recv_data->tot_len, but
               that's not a problem since we explicitly fix that before passing
               recv_data to the application. */
#if LWIP_MPTCP_SUPPORT
            if(is_sfl_pcb(pcb)){
              LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: OFO data become in order, "
                "pcb=%p, len=%d, seq=%08x", __FUNCTION__, __LINE__, pcb,
                TCP_TCPLEN(cseg), pTcpContext->seqno));
              if(eseg){
                eseg->next = cseg;
                eseg = cseg;
              }else
                pTcpContext->mptcp_recv_data = eseg = cseg;
            }else{
#endif
            if (pTcpContext->recv_data) {
              pbuf_cat(pTcpContext->recv_data, cseg->p);
            } else {
              pTcpContext->recv_data = cseg->p;
            }
            cseg->p = NULL;
#if LWIP_MPTCP_SUPPORT
            }
#endif
          }
          if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN) {
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: dequeued FIN.\n"));
            pTcpContext->recv_flags |= TF_GOT_FIN;
            if (pcb->state == ESTABLISHED) { /* force passive close or we can move to active close */
              pcb->state = CLOSE_WAIT;
            }
          }

          pcb->ooseq = cseg->next;
#if LWIP_MPTCP_SUPPORT
          if(is_sfl_pcb(pcb)){
            if(eseg)
              eseg->next = NULL;
          }else
#endif
          tcp_seg_free(cseg);
        }
#endif /* TCP_QUEUE_OOSEQ */


        /* Acknowledge the segment(s). */
          tcp_ack(pcb);
#if LWIP_IPV6 && LWIP_ND6_TCP_REACHABILITY_HINTS
        if (ip_current_is_v6()) {
          /* Inform neighbor reachability of forward progress. */
          nd6_reachability_hint(ip6_current_src_addr());
        }
#endif /* LWIP_IPV6 && LWIP_ND6_TCP_REACHABILITY_HINTS*/

      } else {
        /* We get here if the incoming segment is out-of-sequence. */
#ifdef SACK_FOR_MPTCP_SUPPORT
        //if(is_sfl_pcb(pcb)){
          if(pcb->sack_enabled){
            pcb->sack_edge_valid = 1;
			if(pcb->sack_edge + pcb->sack_len == pTcpContext->seqno){
				/*if have scak a segment, and now the seq location after the sack segment, grow the sack_len*/
				pcb->sack_len += TCP_TCPLEN(pTcpSeg);
			}
			else if(pTcpContext->seqno + TCP_TCPLEN(pTcpSeg)== pcb->sack_edge){
				/*if current seq match the  segment*/
				pcb->sack_edge_valid = 0;
			}
			else{
                pcb->sack_len = TCP_TCPLEN(pTcpSeg);
                pcb->sack_edge = pTcpContext->seqno;
			}
            tcp_ack_now(pcb);
          }
       // }
#endif
        tcp_send_empty_ack(pcb);
#if TCP_QUEUE_OOSEQ
#if LWIP_MPTCP_SUPPORT
        if(is_sfl_pcb(pcb)){
          LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: recved OFO data, pcb=%p"
            ", len=%d, seq=%08x", __FUNCTION__, __LINE__, pcb,
            TCP_TCPLEN(pTcpSeg), pTcpContext->seqno));
          cseg = tcp_seg_copy(pcb->instance,pTcpSeg);
          LWIP_ASSERT("No memory", cseg != NULL); /* Need to be improved */
          cseg->next = NULL;
          cseg->recv_info = recv_info;
          recv_info_need_free = 0;
        }
#endif
        /* We queue the segment on the ->ooseq queue. */
        if (pcb->ooseq == NULL) {
#if LWIP_MPTCP_SUPPORT
          if(is_sfl_pcb(pcb))
            pcb->ooseq = cseg;
          else
#endif
          pcb->ooseq = tcp_seg_copy(pcb->instance,pTcpSeg);
        } else {
          /* If the queue is not empty, we walk through the queue and
             try to find a place where the sequence number of the
             incoming segment is between the sequence numbers of the
             previous and the next segment on the ->ooseq queue. That is
             the place where we put the incoming segment. If needed, we
             trim the second edges of the previous and the incoming
             segment so that it will fit into the sequence.

             If the incoming segment has the same sequence number as a
             segment on the ->ooseq queue, we discard the segment that
             contains less data. */

          prev = NULL;
          for (next = pcb->ooseq; next != NULL; next = next->next) {
            if (pTcpContext->seqno == next->tcphdr->seqno) {
              /* The sequence number of the incoming segment is the
                 same as the sequence number of the segment on
                 ->ooseq. We check the lengths to see which one to
                 discard. */
              if (pTcpSeg->len > next->len) {
                /* The incoming segment is larger than the old
                   segment. We replace some segments with the new
                   one. */
#if LWIP_MPTCP_SUPPORT
                if(!is_sfl_pcb(pcb))
#endif
                cseg = tcp_seg_copy(pcb->instance,pTcpSeg);
                if (cseg != NULL) {
                  if (prev != NULL) {
                    prev->next = cseg;
                  } else {
                    pcb->ooseq = cseg;
                  }
                  tcp_oos_insert_segment(cseg, next, pTcpContext);
                }
                break;
              } else {
                /* Either the lengths are the same or the incoming
                   segment was smaller than the old one; in either
                   case, we ditch the incoming segment. */
                break;
              }
            } else {
              if (prev == NULL) {
                if (TCP_SEQ_LT(pTcpContext->seqno, next->tcphdr->seqno)) {
                  /* The sequence number of the incoming segment is lower
                     than the sequence number of the first segment on the
                     queue. We put the incoming segment first on the
                     queue. */
#if LWIP_MPTCP_SUPPORT
                  if(!is_sfl_pcb(pcb))
#endif
                  cseg = tcp_seg_copy(pcb->instance,pTcpSeg);
                  if (cseg != NULL) {
                    pcb->ooseq = cseg;
                    tcp_oos_insert_segment(cseg, next,pTcpContext);
                  }
                  break;
                }
              } else {
                /*if (TCP_SEQ_LT(prev->tcphdr->seqno, seqno) &&
                  TCP_SEQ_LT(seqno, next->tcphdr->seqno)) {*/
                if (TCP_SEQ_BETWEEN(pTcpContext->seqno, prev->tcphdr->seqno+1, next->tcphdr->seqno-1)) {
                  /* The sequence number of the incoming segment is in
                     between the sequence numbers of the previous and
                     the next segment on ->ooseq. We trim trim the previous
                     segment, delete next segments that included in received segment
                     and trim received, if needed. */
#if LWIP_MPTCP_SUPPORT
                  if(!is_sfl_pcb(pcb))
#endif
                  cseg = tcp_seg_copy(pcb->instance,pTcpSeg);
                  if (cseg != NULL) {
                    if (TCP_SEQ_GT(prev->tcphdr->seqno + prev->len, pTcpContext->seqno)) {
                      /* We need to trim the prev segment. */
                      prev->len = (u16_t)(pTcpContext->seqno - prev->tcphdr->seqno);
                      pbuf_realloc(prev->p, prev->len);
                    }
                    prev->next = cseg;
                    tcp_oos_insert_segment(cseg, next, pTcpContext);
                  }
                  break;
                }
              }
              /* If the "next" segment is the last segment on the
                 ooseq queue, we add the incoming segment to the end
                 of the list. */
              if (next->next == NULL &&
                  TCP_SEQ_GT(pTcpContext->seqno, next->tcphdr->seqno)) {
                if (TCPH_FLAGS(next->tcphdr) & TCP_FIN) {
                  /* segment "next" already contains all data */
                  break;
                }
#if LWIP_MPTCP_SUPPORT
                if(is_sfl_pcb(pcb))
                    next->next = cseg;
                else
#endif
                next->next = tcp_seg_copy(pcb->instance,pTcpSeg);
                if (next->next != NULL) {
                  if (TCP_SEQ_GT(next->tcphdr->seqno + next->len, pTcpContext->seqno)) {
                    /* We need to trim the last segment. */
                    next->len = (u16_t)(pTcpContext->seqno - next->tcphdr->seqno);
                    pbuf_realloc(next->p, next->len);
                  }
                  /* check if the remote side overruns our receive window */
                  if (TCP_SEQ_GT((u32_t)pTcpContext->tcplen + pTcpContext->seqno, pcb->rcv_nxt + (u32_t)pcb->rcv_wnd)) {
                    LWIP_DEBUGF(TCP_INPUT_DEBUG,
                                ("tcp_receive: other end overran receive window"
                                 "seqno %"U32_F" len %"U16_F" right edge %"U32_F"\n",
                                 pTcpContext->seqno, pTcpContext->tcplen, pcb->rcv_nxt + pcb->rcv_wnd));
                    if (TCPH_FLAGS(next->next->tcphdr) & TCP_FIN) {
                      /* Must remove the FIN from the header as we're trimming
                       * that byte of sequence-space from the packet */
                      TCPH_FLAGS_SET(next->next->tcphdr, TCPH_FLAGS(next->next->tcphdr) & ~TCP_FIN);
                    }
                    /* Adjust length of segment to fit in the window. */
                    next->next->len = (u16_t)(pcb->rcv_nxt + pcb->rcv_wnd - pTcpContext->seqno);
                    pbuf_realloc(next->next->p, next->next->len);
                    pTcpContext->tcplen = TCP_TCPLEN(next->next);
                    LWIP_ASSERT("tcp_receive: segment not trimmed correctly to rcv_wnd\n",
                                (pTcpContext->seqno + pTcpContext->tcplen) == (pcb->rcv_nxt + pcb->rcv_wnd));
                  }
                }
                break;
              }
            }
            prev = next;
          }
        }
#if TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS
        /* Check that the data on ooseq doesn't exceed one of the limits
           and throw away everything above that limit. */
        ooseq_blen = 0;
        ooseq_qlen = 0;
        prev = NULL;
        for (next = pcb->ooseq; next != NULL; prev = next, next = next->next) {
          struct pbuf *p = next->p;
          ooseq_blen += p->tot_len;
          ooseq_qlen += pbuf_clen(p);
          if ((ooseq_blen > TCP_OOSEQ_MAX_BYTES) ||
              (ooseq_qlen > TCP_OOSEQ_MAX_PBUFS)) {
             /* too much ooseq data, dump this and everything after it */
             tcp_segs_free(next);
             if (prev == NULL) {
               /* first ooseq segment is too much, dump the whole queue */
               pcb->ooseq = NULL;
             } else {
               /* just dump 'next' and everything after it */
               prev->next = NULL;
             }
             break;
          }
        }
#endif /* TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS */
#endif /* TCP_QUEUE_OOSEQ */
      }
    } else {
      /* The incoming segment is not within the window. */
      tcp_send_empty_ack(pcb);
    }
  } else {
    /* Segments with length 0 is taken care of here. Segments that
       fall out of the window are ACKed. */
    if (!TCP_SEQ_BETWEEN(pTcpContext->seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd - 1)) {
      tcp_ack_now(pcb);
    }
  }
#if LWIP_MPTCP_SUPPORT
  if(is_sfl_pcb(pcb) && recv_info_need_free)
    free(recv_info);
#endif
}

static u8_t
tcp_getoptbyte(struct tcp_context *pTcpContext)
{
  if ((pTcpContext->tcphdr_opt2 == NULL) || (pTcpContext->tcp_optidx < pTcpContext->tcphdr_opt1len)) {
    u8_t* opts = (u8_t *)pTcpContext->tcphdr + TCP_HLEN;
    return opts[pTcpContext->tcp_optidx++];
  } else {
    u8_t idx = (u8_t)(pTcpContext->tcp_optidx++ - pTcpContext->tcphdr_opt1len);
    return pTcpContext->tcphdr_opt2[idx];
  }
}
#if SACK_FOR_MPTCP_SUPPORT
static inline int sack_before(u32_t seq1,u32_t seq2){
    return (seq1-seq2) < TCP_WND && (seq1- seq2)!= 0;
}
/**
 * move the sack need segment to unsent 
 */
void move_sack_segment_to_unsent(struct tcp_pcb *pcb,struct sack_option *pOption){
    struct tcp_seg *tmp = NULL,*prev = NULL;
	u32_t left,right;
	u32_t seq;
	u16_t rtrans_num = 0;
    LWIP_DEBUGF(SACK_DEBUG, ("sack pcb->unacked:%p pcb->dupacks:%d pcb->sack_update:%d", pcb->unacked, pcb->dupacks, pcb->sack_update));
	if(pcb->unacked != NULL && pcb->dupacks > 3 && pcb->sack_update){
		tmp = prev = pcb->unacked;
		/* if the sack haven't been set ,set as tha last ack*/
		if(pcb->sack_receive == 0){
			pcb->sack_receive = pcb->lastack;
		}
		while(tmp){
			right = pOption->pairs[pOption->sack_pair_num-1].sack_left;//right edage for lost
			left = pcb->sack_receive; //left edage for lost
            seq = lwip_ntohl(tmp->tcphdr->seqno);
			for(int i = pOption->sack_pair_num; i>0; i--){
				LWIP_DEBUGF(SACK_DEBUG,(" sack seq:%u left:%u right:%u", seq, left, right));
				if(sack_before(seq,left) && sack_before(right,seq)){
					LWIP_DEBUGF(SACK_DEBUG, ("sack match this segment to send"));
					/* move out from unsacked list*/
					if(tmp == prev){
						pcb->unacked = tmp->next;
					}else{
					    prev->next = tmp->next;
					}
					/*move the segment to unsent list*/
					tmp->rexmit = 1;
					tmp->next = pcb->unsent;
					pcb->unsent = tmp;
					tmp = prev;//tmp have in the unsent list,reset to the unacked list
					rtrans_num++;
                    goto NEXT;
				}else{
				    if(i - 1 >= 0 && i - 2 >= 0){
				       left = pOption->pairs[i-1].sack_right;
				       right = pOption->pairs[i-2].sack_left;
					   LWIP_DEBUGF(SACK_DEBUG,("sack update the left:%u right:%u",left,right));
					}
                }
			}
			LWIP_DEBUGF(SACK_DEBUG,("get Next Segment to compare"));
NEXT:		prev = tmp;
			tmp = tmp->next;
		}
        pcb->sack_receive = pcb->sack_hight_recv;
		LWIP_DEBUGF(SACK_DEBUG,("sack  update sack_receive:%u number of sack segment to be sent:%d tmp:%p",
            pcb->sack_receive,rtrans_num,tmp));
	}
	pcb->sack_update = 0;
    if(pcb->dupacks<3){
		LWIP_DEBUGF(SACK_DEBUG,("sack restore the pcb->sack hight recv"));
		pcb->sack_hight_recv = pcb->lastack;
	}
	/*retarns*/
	for(u16_t i = 0;i< rtrans_num;i++)
		tcp_output(pcb);
	LWIP_DEBUGF(SACK_DEBUG,("exit sack %s",__func__));
	END:
		return;
}
#endif

/**
 * Parses the options contained in the incoming segment.
 *
 * Called from tcp_listen_input() and tcp_process().
 * Currently, only the MSS option is supported!
 *
 * @param pcb the tcp_pcb for which a segment arrived
 */
static void
tcp_parseopt(struct tcp_pcb *pcb,struct tcp_context *pTcpContext)
{
  u8_t data;
  u16_t mss;
#if LWIP_TCP_TIMESTAMPS
  u32_t tsval;
#endif
#if SACK_FOR_MPTCP_SUPPORT
  int len = 0;
  u16_t index = 0;
  u32_t tmp = 0;
  int i;
#endif

  /* Parse the TCP MSS option, if present. */
  if (pTcpContext->tcphdr_optlen != 0) {
    for (pTcpContext->tcp_optidx = 0; pTcpContext->tcp_optidx < pTcpContext->tcphdr_optlen; ) {
      u8_t opt = tcp_getoptbyte(pTcpContext);
      switch (opt) {
      case LWIP_TCP_OPT_EOL:
        /* End of options. */
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: EOL\n"));
        return;
      case LWIP_TCP_OPT_NOP:
        /* NOP option. */
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: NOP\n"));
        break;
      case LWIP_TCP_OPT_MSS:
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: MSS\n"));
        if (tcp_getoptbyte(pTcpContext) != LWIP_TCP_OPT_LEN_MSS || (pTcpContext->tcp_optidx - 2 + LWIP_TCP_OPT_LEN_MSS) > pTcpContext->tcphdr_optlen) {
          /* Bad length */
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
          return;
        }
        /* An MSS option with the right option length. */
        mss = (tcp_getoptbyte(pTcpContext) << 8);
        mss |= tcp_getoptbyte(pTcpContext);
        /* Limit the mss to the configured TCP_MSS and prevent division by zero */
#if LWIP_PERFORMANCE_IMPROVE
              {
                  u16_t guard_mss = pcb->is_nat_pcb ? TUN_TCP_MSS : TCP_MSS;
                  pcb->mss = ((mss > guard_mss) || (mss == 0)) ? guard_mss : mss;
              }
#else
              pcb->mss = ((mss > TCP_MSS) || (mss == 0)) ? TCP_MSS : mss;
#endif
        break;
#if SACK_FOR_MPTCP_SUPPORT
      case LWIP_TCP_OPT_SACK:
	  	LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: SACK\n"));
		len = tcp_getoptbyte(pTcpContext);
		#define LEFT_RIGHT_LEN 8
		#define SACK_TYPE_LEN  2
		if(len <= pTcpContext->tcphdr_optlen - pTcpContext->tcp_optidx + SACK_TYPE_LEN){
            /*sack len = 8*n + 2 KIND 5 OPTLEN len LEFT EDAGE + RIGHT EDAGE = 8*/
			if((len - 2) % LEFT_RIGHT_LEN == 0){
				struct sack_option *sackOption = pTcpContext->sackOption;
				sackOption->sack_pair_num = (u16_t)((len -2)/LEFT_RIGHT_LEN);
				u8_t* opt = (u8_t *)pTcpContext->tcphdr + TCP_HLEN;
				LWIP_DEBUGF(SACK_DEBUG,("sack len:%d sack number:%d seqno:%u ackno:%u", len, sackOption->sack_pair_num, pTcpContext->seqno, pTcpContext->ackno));
				sackOption->pairs = pTcpContext->sackOption->pairs;
				memset(sackOption->pairs,0,sizeof(struct sack_pair)*(sackOption->sack_pair_num));
				LWIP_DEBUGF(SACK_DEBUG,("sack lastack:%u hight_recv:%u sack_receive:%u",pTcpContext->ackno, pcb->sack_hight_recv, pcb->sack_receive));
				for(int i = 0;i< sackOption->sack_pair_num;i++){
					tmp = *(u32_t*)(opt+pTcpContext->tcp_optidx);
					//LWIP_DEBUGF(SACK_DEBUG,("sack left data:%u",tmp));
					sackOption->pairs[i].sack_left = lwip_ntohl(tmp);
					pTcpContext->tcp_optidx += sizeof(u32_t)/sizeof(u8_t);

					tmp = *(u32_t*)(opt+pTcpContext->tcp_optidx);
                    //LWIP_DEBUGF(SACK_DEBUG,("sack right data:%u",tmp));
                    // get sack right edage
					sackOption->pairs[i].sack_right = lwip_ntohl(tmp);
					pTcpContext->tcp_optidx += sizeof(u32_t)/sizeof(u8_t);
					LWIP_DEBUGF(SACK_DEBUG,("sack count:%u sack left:%u sack_right:%u ,pcb->sack_hight_recv:%u",
						i, sackOption->pairs[i].sack_left, sackOption->pairs[i].sack_right, pcb->sack_hight_recv));

				}
				/*the sack order is from big to small*/
				for(i = sackOption->sack_pair_num;i>0;i--){
					if(sack_before(sackOption->pairs[i-1].sack_right,pcb->sack_hight_recv) && pcb->dupacks >3){
						LWIP_DEBUGF(SACK_DEBUG,("pcb update the sack hight recv"));
						pcb->sack_hight_recv = sackOption->pairs[i-1].sack_right;
						pcb->sack_update = 1;
						index++;
					}
				}
                sackOption->sack_pair_num = index;
				LWIP_DEBUGF(SACK_DEBUG,("sack valid data number is: %u",index));
				if(index){
				 	move_sack_segment_to_unsent(pcb,sackOption);
				}
				else
				 LWIP_DEBUGF(SACK_DEBUG,("sack have receive in this range"));	
				/*
				free(sackOption->pairs);
				free(sackOption);
				*/
			}
        }else{
           LWIP_DEBUGF(TCP_INPUT_DEBUG,("tcp_parseopt: sack len error!"));
           return ;
		}
        break;
#endif
#if LWIP_WND_SCALE
      case LWIP_TCP_OPT_WS:
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: WND_SCALE\n"));
        if (tcp_getoptbyte(pTcpContext) != LWIP_TCP_OPT_LEN_WS || (pTcpContext->tcp_optidx - 2 + LWIP_TCP_OPT_LEN_WS) > pTcpContext->tcphdr_optlen) {
          /* Bad length */
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
          return;
        }
        /* If syn was received with wnd scale option,
           activate wnd scale opt, but only if this is not a retransmission */
        if ((pTcpContext->flags & TCP_SYN) && !(pcb->flags & TF_WND_SCALE)) {
          /* An WND_SCALE option with the right option length. */
          data = tcp_getoptbyte(pTcpContext);
          pcb->snd_scale = data;
          if (pcb->snd_scale > 14U) {
            pcb->snd_scale = 14U;
          }
          pcb->rcv_scale = TCP_RCV_SCALE;
          pcb->flags |= TF_WND_SCALE;
          /* window scaling is enabled, we can use the full receive window */
          LWIP_ASSERT("window not at default value", pcb->rcv_wnd == TCPWND_MIN16(TCP_WND));
          LWIP_ASSERT("window not at default value", pcb->rcv_ann_wnd == TCPWND_MIN16(TCP_WND));
          pcb->rcv_wnd = pcb->rcv_ann_wnd = TCP_WND;
        }
        break;
#endif
#if LWIP_TCP_TIMESTAMPS
      case LWIP_TCP_OPT_TS:
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: TS\n"));
        if (tcp_getoptbyte(pTcpContext) != LWIP_TCP_OPT_LEN_TS || (pTcpContext->tcp_optidx - 2 + LWIP_TCP_OPT_LEN_TS) > pTcpContext->tcphdr_optlen) {
          /* Bad length */
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
          return;
        }
        /* TCP timestamp option with valid length */
        tsval = tcp_getoptbyte(pTcpContext);
        tsval |= (tcp_getoptbyte(pTcpContext) << 8);
        tsval |= (tcp_getoptbyte(pTcpContext) << 16);
        tsval |= (tcp_getoptbyte(pTcpContext) << 24);
        if (pTcpContext->flags & TCP_SYN) {
          pcb->ts_recent = lwip_ntohl(tsval);
          /* Enable sending timestamps in every segment now that we know
             the remote host supports it. */
#if LWIP_MPTCP_SUPPORT
          if(!pcb->is_accept_pcb)
#endif
          pcb->flags |= TF_TIMESTAMP;
        } else if (TCP_SEQ_BETWEEN(pcb->ts_lastacksent, pTcpContext->seqno, pTcpContext->seqno+pTcpContext->tcplen)) {
          pcb->ts_recent = lwip_ntohl(tsval);
        }
        /* Advance to next option (6 bytes already read) */
        pTcpContext->tcp_optidx += LWIP_TCP_OPT_LEN_TS - 6;
        break;
#endif
#if LWIP_MPTCP_SUPPORT
#ifdef SACK_FOR_MPTCP_SUPPORT
      case LWIP_TCP_OPT_SACK_PERM:
        if(tcp_getoptbyte(pTcpContext) != LWIP_TCP_OPT_LEN_SACK_PERM){
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length for Sack Permitted\n"));
          return;
        }
        pcb->sack_enabled = 1;
        break;
#endif
      case LWIP_TCP_OPT_MPTCP:{
            data = tcp_getoptbyte(pTcpContext);
            u8_t *opt = (u8_t *)(&pTcpContext->opt[0]);
            if ((data -2) > (pTcpContext->tcphdr_optlen - pTcpContext->tcp_optidx) || data < 2 )
                    return; /* don't parse partial options */

            if (pTcpContext->tcphdr_opt2) {
                /*opt = (u8_t*)malloc(pTcpContext->tcphdr_optlen);*/
                memcpy(opt, (u8_t *)pTcpContext->tcphdr + TCP_HLEN, pTcpContext->tcphdr_opt1len);
                opt += pTcpContext->tcphdr_opt1len;
                memcpy(opt, pTcpContext->tcphdr_opt2, pTcpContext->tcphdr_optlen-pTcpContext->tcphdr_opt1len);
                opt -= pTcpContext->tcphdr_opt1len;
            } else {
                opt = (u8_t *)pTcpContext->tcphdr + TCP_HLEN;
            }

            if(pcb->mptcp_is_support)
				mptcp_parse_options(pcb, data, &opt[(u8_t)pTcpContext->tcp_optidx - 2]);
            // Only free the memory when options was splitted into two seg.
            //if (pTcpContext->tcphdr_opt2)
            //        free(opt);
            break;
      }
#endif
      default:
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: other\n"));
        data = tcp_getoptbyte(pTcpContext);
        if (data < 2) {
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
          /* If the length field is zero, the options are malformed
             and we don't process them further. */
          return;
        }
        /* All other options have a length field, so that we easily
           can skip past them. */
        pTcpContext->tcp_optidx += data - 2;
      }
    }
  }
}

void
tcp_trigger_input_pcb_close(void *pTcpContext)
{
  ((struct tcp_context *)pTcpContext)->recv_flags |= TF_CLOSED;
}

#if LWIP_MPTCP_SUPPORT
u32_t tcp_input_get_current_seqno(void *instance){
  struct lwip_instance *pLwipInstance = (struct lwip_instance *)instance;
  struct module_conext *tcp_module_context = &pLwipInstance->module_conext[CONTEXT_TCP_TYPE];
  void *pTcpContext = tcp_module_context->pCcontext;
  
  return ((struct tcp_context *)pTcpContext)->seqno;
}
#endif

#endif /* LWIP_TCP */
