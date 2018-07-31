/*===========================================================================

                         mptcp_state.c

DESCRIPTION

Introduce the mptcp state and fill or parse the field in tcp options for mptcp.

Copyright (c) 2017.04 - 2017.05  Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/
#include "lwip/lwipopts.h"
#include "lwip/mptcp/mptcp_state.h"
#include "lwip/mptcp/mptcp_unaligned.h"
#include <lwip/mptcp/mptcp_session.h>
#include <lwip/mptcp/mptcp_tcp.h>
#include "lwip/mptcp/mptcp_debug.h"
#include "lwip/mptcp/mptcp_tcp.h"
#include "lwip/mptcp/mptcp_input_output.h"
#include "lwip/mptcp_fin.h"
#include "lwip/mptcp/mptcp_ipv4.h"
#include "lwip/module.h"
#include "../../../../../mccp/mccp.h"

#if LINUX_PLATFORM
#include "tools/common.h"
#endif

#if LWIP_MPTCP_SUPPORT

/*static mptcp_recv_info recv_info;*/
extern int isSetWifiAddr;

#if WIFI_LTE_SWITCH
extern int isSetLteAddr;
#endif

void mptcp_recv_info_init(void **pRecv_info)
{
    void *pBuffer = malloc(sizeof(mptcp_recv_info));

	if(pBuffer != NULL)
		memset(pBuffer, 0x0,sizeof(mptcp_recv_info));
	*pRecv_info = pBuffer;
}

/**
 * Init mptcp state.
 *
 * @Parameter pcb - struct tcp_pcb
 */
void initMptcpState(struct tcp_pcb *pcb) {
  transferToState(pcb, MPTCP_MP_CAPABLE_SYN_SEND);
}

/**
 * Transfer to the state.
 *
 * @Parameter pcb - struct tcp_pcb
 * @Parameter state - int
 */
void transferToState(struct tcp_pcb *pcb, int state) {
  pcb->mptcp_state = state;
  if(is_meta_pcb(pcb)){
    if(state >= MPTCP_MP_CAPABLE_SYN_SEND && state <= MPTCP_MP_ESTABLISHED){
      /* At this point of time, it's expected that only master_pcb exists
       * in the connection list */
      struct tcp_pcb *master_pcb = NULL;
      if(pcb->mp_conn_cb != NULL)
        master_pcb = pcb->mp_conn_cb->connection_list;
      if(master_pcb != NULL && master_pcb->is_master_pcb)
        master_pcb->mptcp_state = state;
    }
  }
}

/**
 * Get current mptcp state.
 *
 * @Parameter pcb - struct tcp_pcb
 * @Return currentState - int
 */
int getCurrentState(struct tcp_pcb *pcb) {
  return pcb->mptcp_state;
}

/**
 * Get previous mptcp state.
 *
 * @Parameter pcb - struct tcp_pcb
 * @Return preState - int
 */
u16_t get_mptcp_opt_flag(struct tcp_pcb *pcb) {
  switch (getCurrentState(pcb)) {
    case MPTCP_MP_CAPABLE_SYN_SEND:
      return TF_SEG_OPTS_MP_CAPABLE_SYN;
    case MPTCP_MP_CAPABLE_ACK_SEND:
      return TF_SEG_OPTS_MP_CAPABLE_ACK;
    case MPTCP_MP_JOIN_SYN_SEND:
      return TF_SEG_OPTS_MP_JOIN_SYN;
    case MPTCP_MP_JOIN_ACK_SEND:
      return TF_SEG_OPTS_MP_JOIN_ACK;
    /* Option buffer for MP_DSS is processed in special way. */
    case MPTCP_MP_ESTABLISHED:
      /* return TF_SEG_OPTS_MP_DSS; */
      return 0;
    case MPTCP_MP_FASTCLOSE_SENT:
      return TF_SEG_OPTS_MP_FAST_CLOSE;
    default:
      return 0;
  }
}

#if MPTCP_SUB_SERVER_ADDR
static void mptcp_build_server_addr_option(u32_t *opts, struct tcp_pcb *pcb)
{
  /* customization subtype server_add */

  struct mp_server_addr *mps = (struct mp_server_addr *)opts;
  mps->kind = TF_TCPOPT_MPTCP;
#ifdef SACK_FOR_MPTCP_SUPPORT
  mps->len = 9;
#else
  mps->len = 10;
#endif
  mps->ipver = 4;
  mps->sub = MPTCP_SUB_SER_ADDR;
#ifdef SACK_FOR_MPTCP_SUPPORT
  memcpy(&mps->addr[0], &pcb->mptcp_server4.addr.s_addr, 4);
  memcpy(&mps->port[0], &pcb->mptcp_server4.port, 2);
#else
  mps->addr_id = pcb->mptcp_server4.server4_id;
  mps->v4.addr.s_addr = pcb->mptcp_server4.addr.s_addr;
  mps->v4.port = pcb->mptcp_server4.port;
  mps->v4.aligned = 0x0101;
  opts += MPTCP_SUB_LEN_SER_ADDR4_ALIGN >> 2;
  
  LWIP_DEBUGF(API_MSG_DEBUG, ("Add server address:addr_id:%d, addr:%d , port: %d", mps->addr_id, mps->v4.addr.s_addr, mps->v4.port));
  list_mp_server_addr(mps);
#endif
}
#endif

/**
  * The mptcp state machine for send data.
  *
  * @Paramter pcb - struct tcp_pcb
  * @Paramter ptr - u32_t point to the position of tcp option.
  */
void mptcpStateProcess(struct tcp_pcb *pcb, u32_t *ptr) {
  mptcpStateProcessWithSeg(pcb, ptr, NULL);
}

void mptcpStateProcessWithSeg(struct tcp_pcb *pcb, u32_t *ptr, struct tcp_seg *seg) {
  int state = pcb->mptcp_state;

  LIST_STATE(state);

  switch (state) {
    case MPTCP_MP_CAPABLE_SYN_SEND: {
#ifdef SACK_FOR_MPTCP_SUPPORT
      u32_t optbuf[6], *tmp_ptr;
      struct mp_capable *mpc = (struct mp_capable *)&optbuf[0];
      u8_t *tmp_ptr1 = (u8_t *)ptr;
      memset(optbuf, 0, sizeof(optbuf));
#else
      struct mp_capable *mpc = (struct mp_capable *) ptr;
#endif

      mpc->kind = TF_TCPOPT_MPTCP;

      mpc->sender_key = pcb->mp_conn_cb->loc_key;
      mpc->len = MPTCP_SUB_LEN_CAPABLE_SYN;
      mpc->ver = pcb->mptcp_ver;
      mpc->sub = MPTCP_SUB_CAPABLE;
      mpc->a = MPTCP_DSS_CSUM_WANTED;
      mpc->b = 0;
      mpc->rsv = 0;
      mpc->h = 1;
#ifdef SACK_FOR_MPTCP_SUPPORT
      /*For MPTCP_CAPABLE*/
      tmp_ptr1--;//1 
      /*byte left in Window Scale option*/
      tmp_ptr = &optbuf[0];
      memcpy(tmp_ptr1, tmp_ptr, MPTCP_SUB_LEN_CAPABLE_SYN);
      tmp_ptr1 += MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
      ptr += MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN >> 2;

      /*For MPTCP_SERVER_ADDR*/
#if MPTCP_SUB_SERVER_ADDR
      tmp_ptr = &optbuf[MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN >> 2];
      mptcp_build_server_addr_option(tmp_ptr, pcb);
      memcpy(tmp_ptr1, tmp_ptr, 9);
      ptr += MPTCP_SUB_LEN_SER_ADDR4_ALIGN >> 2;
#endif /* MPTCP_SUB_SERVER_ADDR */
#else /* SACK_FOR_MPTCP_SUPPORT */
      ptr += MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN >> 2;
#if MPTCP_SUB_SERVER_ADDR
      mptcp_build_server_addr_option(ptr, pcb);
#endif
#endif
      pcb->mptcp_enabled = 0;
      break;
    }
    case MPTCP_MP_CAPABLE_ACK_SEND: {
      struct mp_capable *mpc = (struct mp_capable *) ptr;

      mpc->kind = TF_TCPOPT_MPTCP;
      mpc->sender_key = pcb->mp_conn_cb->loc_key;
      mpc->receiver_key = pcb->mp_conn_cb->rem_key;
      mpc->len = MPTCP_SUB_LEN_CAPABLE_ACK;
      mpc->ver = pcb->mptcp_ver;
      mpc->sub = MPTCP_SUB_CAPABLE;
      mpc->a = pcb->mp_conn_cb->dss_csum;
      mpc->b = 0;
      mpc->rsv = 0;
      mpc->h = 1;
      ptr += MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN >> 2;

      struct mp_dss *mdss = (struct mp_dss *) ptr;
      mdss->kind = TF_TCPOPT_MPTCP;
      mdss->sub = MPTCP_SUB_DSS;
      mdss->M = 0; /* Seq*/
      mdss->m = 0; /* Seq is 4 bytes */
      mdss->A = 1; /* Ack */
      mdss->a = 0; /* Ack is 4 bytes */
      mdss->F = 0;
      mdss->rsv1 = 0;
      mdss->rsv2 = 0;
      mdss->len = mptcp_count_dss_opt_len(0, 1, pcb->mp_conn_cb->dss_csum);
      ptr++;

      struct tcp_pcb *master_pcb;
      if (is_meta_pcb(pcb)) {
              master_pcb = pcb->mp_conn_cb->connection_list;
      } else {
              master_pcb = pcb;
      }
      *ptr++ = lwip_htonl(master_pcb->rcv_nxt);
      pcb->mp_conn_cb->cnt_established++;
      transferToState(pcb, MPTCP_MP_ESTABLISHED);
      break;
    }
    case MPTCP_MP_JOIN_SYN_SEND: {
      struct mp_join *mpj = (struct mp_join *) ptr;
	  u32_t *pMptcp_seed;

	  mptcp_get_seed(pcb->instance, &pMptcp_seed);

      mpj->kind = TF_TCPOPT_MPTCP;
      mpj->sub = MPTCP_SUB_JOIN;
      mpj->rsv = 0;
      mpj->len = MPTCP_SUB_LEN_JOIN_SYN;
      mpj->u.syn.token = pcb->mp_conn_cb->rem_token;
      pcb->mp_sfl_pcb->loc_nonce = mptcp_v4_get_nonce(pcb->local_ip.addr,
              pcb->remote_ip.addr, pcb->local_port, pcb->remote_port,
              pMptcp_seed,mptcp_get_secret(pcb->instance));
      mpj->u.syn.nonce = pcb->mp_sfl_pcb->loc_nonce;
      mpj->b = 0;
      /* Currently, address id is set to fixed value 2 to match the server
       * side logic */
#if 0
      mpj->addr_id = pcb->addr_id;
#else
      mpj->addr_id = 2;
#endif
      ptr += MPTCP_SUB_LEN_JOIN_SYN_ALIGN >> 2;
      break;
    }
    case MPTCP_MP_JOIN_ACK_SEND: {
      struct mp_join *mpj = (struct mp_join *) ptr;

      mpj->kind = TF_TCPOPT_MPTCP;
      mpj->sub = MPTCP_SUB_JOIN;
      mpj->rsv = 0;
      mpj->len = MPTCP_SUB_LEN_JOIN_ACK;
      mpj->addr_id = 0; /* addr_id is rsv (RFC 6824, p. 21) */
      mpj->b = 0;
      memcpy(mpj->u.ack.mac, &pcb->mp_sfl_pcb->sender_mac[0], 20);
      ptr += MPTCP_SUB_LEN_JOIN_ACK_ALIGN >> 2;
      /*Wait for the third ack checked*/
      pcb->mp_sfl_pcb->pre_established = 1;
      transferToState(pcb, MPTCP_MP_ESTABLISHED);
      break;
    }
    case MPTCP_MP_ADD_ADDR_SND: {
      struct mp_add_addr *mpadd = (struct mp_add_addr *) ptr;
      mpadd->kind = TF_TCPOPT_MPTCP;
      mpadd->sub = MPTCP_SUB_ADD_ADDR;
      mpadd->ipver = 4;
      mpadd->addr_id = pcb->addr_id;
     // mpadd->addr.addr = pcb->add_addr4.addr;
      if (pcb->mptcp_ver < MPTCP_VERSION_1) {
        mpadd->len = MPTCP_SUB_LEN_ADD_ADDR4;
        ptr += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN >> 2;
      } else {
        memcpy((char *) mpadd->addr.mac - 2, (char *) &pcb->mp_sfl_pcb->sender_mac[0], 8);
        mpadd->len = MPTCP_SUB_LEN_ADD_ADDR4_VER1;
        ptr += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1 >> 2;
      }
      break;
    }
    case MPTCP_MP_REMOVE_ADDR_SND: {
      struct mp_remove_addr *mprem = (struct mp_remove_addr *) ptr;
      int len, len_align;

      len = mptcp_sub_len_remove_addr(pcb->remove_addrs);
      len_align = mptcp_sub_len_remove_addr_align(pcb->remove_addrs);
      mprem->kind = TF_TCPOPT_MPTCP;
      mprem->len = len;
      mprem->sub = MPTCP_SUB_REMOVE_ADDR;
      mprem->rsv = 0;
      //TODO
      mprem->addrs_id = 0;

      ptr += len_align >> 2;
      break;
    }
    case MPTCP_MP_ESTABLISHED: {
      struct mp_dss *mdss = (struct mp_dss *) ptr;
      int has_data = (seg != NULL && seg->len > 0);
      struct tcp_pcb *meta_pcb = pcb->meta_pcb;
      struct mptcp_cb *mpcb = pcb->mp_conn_cb;
      struct mptcp_subflow_pcb* spcb = pcb->mp_sfl_pcb;

      if(seg != NULL && seg->rexmit){
        break;
      }

#if !WIFI_LTE_SWITCH
#if WIFI_SWITCH_FEATURE
      /* if the wifi been open, and the cnt_subflow */
      LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("isSetwifiAddr:%d,and is set add addr:%d",isSetWifiAddr,pcb->mp_conn_cb->is_set_add_addr));
      if(isSetWifiAddr && pcb->mp_conn_cb->is_set_add_addr)
      {
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("cnt subflow:%d",meta_pcb->mp_conn_cb->cnt_subflows));
        if(mpcb->cnt_subflows < 2 && !mpcb->rmt_fin_recved && !mpcb->lcl_fin_sent)
        {
          LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("create a new subflow when the wifi open again"));
          start_new_subflow(meta_pcb, &(pcb->mp_conn_cb->sfl_add_addr));
        }
      }
#endif
#else
      /* if the wifi been open, and the cnt_subflow */
      LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("isSetwifiAddr:%d,and is set add addr:%d",isSetWifiAddr,pcb->mp_conn_cb->is_set_add_addr));
      LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("isSetLteAddr:%d",isSetLteAddr));
      if(isSetWifiAddr && pcb->mp_conn_cb->is_set_add_addr && (pcb->mp_conn_cb->sfl_add_addr.addr.addr.s_addr == ppca_s->mccp_mpgw_ip1))
      {
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("cnt subflow:%d",meta_pcb->mp_conn_cb->cnt_subflows));
        if(mpcb->cnt_subflows < 2 && !mpcb->rmt_fin_recved && !mpcb->lcl_fin_sent)
        {
          LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("create a new subflow when the wifi open again"));
          start_new_subflow(meta_pcb, &(pcb->mp_conn_cb->sfl_add_addr));
        }
      }
      if(isSetLteAddr && pcb->mp_conn_cb->is_set_add_addr && (pcb->mp_conn_cb->sfl_add_addr.addr.addr.s_addr == ppca_s->mccp_mpgw_ip))
      {
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("cnt subflow:%d",meta_pcb->mp_conn_cb->cnt_subflows));
        if(mpcb->cnt_subflows < 2 && !mpcb->rmt_fin_recved && !mpcb->lcl_fin_sent)
        {
          LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("create a new subflow when the wifi open again"));
          start_new_subflow(meta_pcb, &(pcb->mp_conn_cb->sfl_add_addr));
        }
      }
#endif
      /* Case of seg == NULL is to send DSS_ACK in empty subflow ack frame.
       * Used for case of tcp_send_empty_ack() in tcp_out.c */
      mdss->kind = TF_TCPOPT_MPTCP;
      mdss->sub = MPTCP_SUB_DSS;
      mdss->M = ((seg == NULL) ? 0 : 1); /* Seq*/
      mdss->m = 0; /* Seq is 4 bytes */
      mdss->A = 1; /* Ack */
      mdss->a = 0; /* Ack is 4 bytes */
      mdss->F = (mpcb->mptcp_flags & MPTCPHDR_FIN) ? 1 : 0;
      if(mpcb->mptcp_flags & MPTCPHDR_FIN)
        mpcb->mptcp_flags &= ~MPTCPHDR_FIN;
      if(mpcb->lcl_fin_sent){
        mdss->F = 0;
      }
      ptr++;

      /* if all data received, ACK the DATA_FIN */
      if(mpcb->rmt_fin_recved && meta_pcb->rcv_nxt == mpcb->rmt_fin_seqno){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: ack remote DATA_FIN, meta_pcb=%p",
          __FUNCTION__, __LINE__, meta_pcb));
        mpcb->rmt_fin_acked = 1;
        meta_pcb->rcv_nxt++;
        mptcp_fin_add_close_candidate(meta_pcb);
      }
      *ptr++ = lwip_htonl(meta_pcb->rcv_nxt);

      if(seg == NULL){
        if(mdss->F){
          u16_t csum, *ptmp;
          u32_t meta_seq;

          /* See lower part of P29 of RFC6824 */
          meta_seq = meta_pcb->snd_nxt;
          mdss->M = 1;
          *ptr++ = lwip_htonl(meta_seq);
          *ptr++ = lwip_htonl(0); /* Sub Sequence */
          ptmp = (u16_t *) ptr;
          *ptmp++ = lwip_htons(1); /* Data length */
          mpcb->lcl_fin_seqno = meta_seq + 1;
          if(mpcb->dss_csum)
            *ptmp++ = mptcp_calculate_fin_csum(pcb, meta_seq, 1); /* Checksum */
          mdss->len = mptcp_count_dss_opt_len(1, 1, pcb->mp_conn_cb->dss_csum);
          mpcb->lcl_fin_sent = 1;
          meta_pcb->snd_nxt++;
        }else
          mdss->len = mptcp_count_dss_opt_len(0, 1, 0);
        break;
      }else{
        u32_t sub_data_seq = pcb->snd_nxt - pcb->mp_sfl_pcb->snt_isn;
        u16_t data_len = seg->len;
        u16_t csum, *ptmp;
        //Todo: consider sub_data_seq in the situation containing FIN
        //data sequence of connection level
        *ptr++ = lwip_htonl(seg->meta_seq);
        //data sequence of subflow level
        *ptr++ = lwip_htonl(sub_data_seq);
        //data_len
        ptmp = (u16_t *) ptr;
        if(mdss->F){
            mpcb->lcl_fin_sent = 1;
            data_len += 1;
        }
        *ptmp++ = lwip_htons(data_len);
        mpcb->lcl_fin_seqno = seg->meta_seq + data_len;

        //checksum
        if(pcb->mp_conn_cb->dss_csum){
          csum = mptcp_calculate_outgoing_csum(pcb, seg, seg->meta_seq,
              sub_data_seq, data_len);
          *ptmp++ = csum;
        }
      }
      /* Todo: consider the situation where checksum is not needed */
      mdss->len = mptcp_count_dss_opt_len(1, 1, pcb->mp_conn_cb->dss_csum);
      break;
    }
    case MPTCP_MP_FASTCLOSE_SENT: {
      struct mp_fclose *mpfclose = (struct mp_fclose *) ptr;

      mpfclose->kind = TF_TCPOPT_MPTCP;
      mpfclose->len = MPTCP_SUB_LEN_FCLOSE;
      mpfclose->sub = MPTCP_SUB_FCLOSE;
      mpfclose->rsv1 = 0;
      mpfclose->rsv2 = 0;
      mpfclose->key = pcb->mp_conn_cb->rem_key;

      ptr += MPTCP_SUB_LEN_FCLOSE_ALIGN >> 2;
      break;
    }
#if 0
    /*  case MPTCP_MP_FAIL_RCV: {
          struct mp_fail *mpfail = (struct mp_fail *)ptr;

          mpfail->kind = TCPOPT_MPTCP;
          mpfail->len = MPTCP_SUB_LEN_FAIL;
          mpfail->sub = MPTCP_SUB_FAIL;
          mpfail->rsv1 = 0;
          mpfail->rsv2 = 0;
          // TODO:: htonll is implemented as be64_to_cpu, consider if it's needed.
          //mpfail->data_seq = htonll(tp->mpcb->csum_cutoff_seq);

          ptr += MPTCP_SUB_LEN_FAIL_ALIGN >> 2;
          break;
      }*/
#endif
    default:
      break;
  }
}

/**
 * Parse the mptcp options of receive data.
 *
 * @Paramter pcb - tcp_pcb
 * @Parameter opsize - u8_t
 * @Parameter ptr - u32_t point to the position of tcp option.
 *
 * This function only can be called in tcp_parseopt().
 */
void mptcp_parse_options(struct tcp_pcb *pcb, u8_t opsize, u8_t *ptr) {
  const struct mptcp_option *mp_opt = (struct mptcp_option *) ptr;
  mptcp_recv_info *pRecv_info = NULL;
  
  LIST_RCV_OPT(mp_opt->sub);

  switch (mp_opt->sub) {
    case MPTCP_SUB_CAPABLE: {
      const struct mp_capable *mpcapable = (struct mp_capable *) ptr;
      LIST_MP_CAPABLE(mpcapable);

      if (getCurrentState(pcb) == MPTCP_MP_CAPABLE_SYN_SEND
              && opsize != MPTCP_SUB_LEN_CAPABLE_SYN_ACK) {
          break;
      }

      /* MPTCP-RFC 6824:
        * "If receiving a message with the 'B' flag set to 1, and this
        * is not understood, then this SYN MUST be silently ignored;
        */
      if (mpcapable->b) {
        pcb->drop_me = 1;
        break;
      }

      /* MPTCP-RFC 6824:
        * "An implementation that only supports this method MUST set
        *  bit "H" to 1, and bits "C" through "G" to 0."
        */
      if (!mpcapable->h)
        break;

      pcb->is_meta_pcb = 1;
      /*LogE("mptcp_parse_options remote_key=%lu",my_ntohll(mpcapable->sender_key));*/

      // In my understanding, peer's sender key is stand for themselves.
      pcb->mp_conn_cb->rem_key = mpcapable->sender_key;
      pcb->mptcp_ver = mpcapable->ver;
      pcb->mptcp_enabled = 1;

      mptcp_create_master_pcb(pcb, pcb->mp_conn_cb->rem_key);
      if(pcb->mp_conn_cb)
        pcb->mp_conn_cb->dss_csum =
          ((MPTCP_DSS_CSUM_WANTED && mpcapable->a) ? 1 : 0);

      transferToState(pcb, MPTCP_MP_CAPABLE_ACK_SEND);
      break;
    }
    case MPTCP_SUB_JOIN: {
      const struct mp_join *mpjoin = (struct mp_join *) ptr;
      LIST_MP_JOIN(mpjoin);

      if (getCurrentState(pcb) == MPTCP_MP_JOIN_SYN_SEND
              && opsize != MPTCP_SUB_LEN_JOIN_SYN_ACK) {
          break;
      }
      if(pcb->mp_sfl_pcb == NULL) {
          break;
      }
      pcb->mp_sfl_pcb->rcv_low_prio = mpjoin->b;
      pcb->addr_id = mpjoin->addr_id;
      pcb->mp_sfl_pcb->rem_id = mpjoin->addr_id;
      pcb->mp_sfl_pcb->rem_nonce= mpjoin->u.synack.nonce;

      //hash-mac check
      u8_t hash_mac_check[20];
      struct mptcp_cb *mpcb = pcb->mp_conn_cb;
      mptcp_hmac_sha1((u8_t *)&mpcb->rem_key,
                      (u8_t *)&mpcb->loc_key,
                      (u32_t *)hash_mac_check, 2,
                      4, (u8_t *)&pcb->mp_sfl_pcb->rem_nonce,
                      4, (u8_t *)&pcb->mp_sfl_pcb->loc_nonce);

      if (memcmp(hash_mac_check, (char *)&mpjoin->u.synack.mac, 8)) {
          LWIP_DEBUGF(API_MSG_DEBUG, ("Check sender's hash-mac fail."));
          tcp_rst(pcb->instance,pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,
                  pcb->local_port, pcb->remote_port);
          return;
      }

      mptcp_hmac_sha1((u8_t *)&mpcb->loc_key,
                      (u8_t *)&mpcb->rem_key,
                      (u32_t *)&pcb->mp_sfl_pcb->sender_mac[0], 2,
                      4, (u8_t *)&pcb->mp_sfl_pcb->loc_nonce,
                      4, (u8_t *)&pcb->mp_sfl_pcb->rem_nonce);

      if(pcb->unacked && pcb->unacked->tcphdr)
        pcb->mp_sfl_pcb->snt_isn = lwip_ntohl(pcb->unacked->tcphdr->seqno);
      else
        pcb->mp_sfl_pcb->snt_isn = pcb->snd_nxt - 1;
      pcb->mp_sfl_pcb->rcv_isn = tcp_input_get_current_seqno(pcb->instance);

      transferToState(pcb, MPTCP_MP_JOIN_ACK_SEND);
      break;
    }
    case MPTCP_SUB_DSS: {
      u32_t data_ack;
      struct mptcp_subflow_pcb *spcb;
      struct mptcp_cb* mpcb;
      const struct mp_dss *mdss = (struct mp_dss *) ptr;
      LIST_MP_DSS(mdss);

	  pRecv_info = (mptcp_recv_info *)mptcp_get_recv_info_ptr(pcb->instance);

      memset((void *)(pRecv_info), 0, sizeof(mptcp_recv_info));

      if (getCurrentState(pcb) != MPTCP_MP_ESTABLISHED || !is_sfl_pcb(pcb)) {
          break;
      }
      if(pcb->mp_sfl_pcb == NULL) {
         break;
      }
      spcb = pcb->mp_sfl_pcb;
      mpcb = pcb->mp_conn_cb;

      /* We check opsize for the csum and non-csum case. We do this,
        * because the draft says that the csum SHOULD be ignored if
        * it has not been negotiated in the MP_CAPABLE but still is
        * present in the data.
        *
        * It will get ignored later in mptcp_queue_skb.
        */
      if (opsize != mptcp_sub_len_dss(mdss, 0) &&
          opsize != mptcp_sub_len_dss(mdss, 1))
        break;

      ptr += 4;

      if (mdss->A) {
        if (mdss->a) {
          /* Todo: to be further considered */
          data_ack = (u32_t)my_ntohll(*((u64_t *)ptr));
          ptr += MPTCP_SUB_LEN_ACK_64;
        } else {
          data_ack = lwip_ntohl(*((u32_t *)ptr));
          ptr += MPTCP_SUB_LEN_ACK;
        }
        mptcp_check_incoming_ack(pcb, data_ack);
        if(mpcb->lcl_fin_sent)
          if(data_ack == mpcb->lcl_fin_seqno){
            LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: local DATA_FIN is acked",
              __FUNCTION__, __LINE__));
            mpcb->lcl_fin_acked = 1;
            mptcp_fin_add_close_candidate(pcb->meta_pcb);
          }
      }

      if (mdss->M) {
        if (mdss->m) {
          pRecv_info->recv_data_seq = (u32_t)my_ntohll(*((u64_t *)ptr));
          ptr += 8; /* 64-bit dseq */
        } else {
          pRecv_info->recv_data_seq = lwip_ntohl(*((u32_t *)ptr));
          ptr += 4; /* 32-bit dseq */
        }
        pRecv_info->recv_sub_data_seq = lwip_ntohl(*((u32_t *)ptr));
        ptr += 4; /* 32-bit sub dseq */
        pRecv_info->recv_data_len = lwip_ntohs(*((u16_t *)ptr));
        ptr += 2; /* 16-bit data length */

        if (opsize == mptcp_sub_len_dss(mdss, 1)) {
          pRecv_info->recv_csum = *((u16_t *)ptr);
        }
        pRecv_info->mptcp_info_valid = 1;
      }

      /* DATA_FIN can be present without DSS-mapping? */
      if (mdss->F) {
        pRecv_info->recv_fin_valid = 1;
        if(mdss->M && mpcb->dss_csum && pRecv_info->recv_sub_data_seq == 0 &&
            pRecv_info->recv_data_len == 1){
          u16_t csum = mptcp_calculate_fin_csum(pcb, pRecv_info->recv_data_seq, 0);
          if(pRecv_info->recv_csum != csum){
            LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: received DATA_FIN, incorrect"
              " csum, csum=%04x, recv_csum=%04x", __FUNCTION__, __LINE__,
              csum, pRecv_info->recv_csum));
            break;
          }
        }
        mpcb->rmt_fin_recved = 1;
        if(pRecv_info->recv_sub_data_seq == 0)
          mpcb->rmt_fin_seqno = pRecv_info->recv_data_seq;
        else
          mpcb->rmt_fin_seqno = pRecv_info->recv_data_seq + pRecv_info->recv_data_len - 1;
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: received DATA_FIN, rmt_fin_seqno"
          "=%08x", __FUNCTION__, __LINE__, mpcb->rmt_fin_seqno));
        tcp_ack_now(pcb);
        tcp_output(pcb);
        /* Trigger close process. Not required by RFC6824 but by customer */
        mptcp_fin_trigger_close(pcb->meta_pcb, pcb, NULL);
      }
      break;
    }
    case MPTCP_SUB_ADD_ADDR: {
      struct mp_add_addr *mpadd = (struct mp_add_addr *) ptr;
      LIST_MP_ADD_ADDR(mpadd);

      if (!is_valid_addropt_opsize(pcb->mptcp_ver, mpadd, opsize)) {
        break;
      }
      if(pcb->mp_conn_cb == NULL) {
          break;
      }
#if WIFI_SWITCH_FEATURE
      MEMCPY(&pcb->mp_conn_cb->sfl_add_addr,mpadd,sizeof(struct mp_add_addr));
      pcb->mp_conn_cb->is_set_add_addr = 1;
#endif
      struct tcp_pcb *meta_pcb = is_meta_pcb(pcb) ? pcb : pcb->meta_pcb;
      if (pcb->mp_conn_cb->cnt_subflows < 2) {
          start_new_subflow(meta_pcb, mpadd);
      }
      break;
    }
    case MPTCP_SUB_REMOVE_ADDR: {
      LIST_MP_REMOVE_ADDR((struct mp_remove_addr *) ptr);
      if ((opsize - MPTCP_SUB_LEN_REMOVE_ADDR) < 0) {
        break;
      }
        if(pcb->mp_conn_cb == NULL) {
            break;
        }
      struct mp_remove_addr *mprmadd = (struct mp_remove_addr *) ptr;
      //Iterates over all subflows and remove all the subflows related to this address
      //struct tcp_pcb *pcb_it;
      //mptcp_for_each_pcb(pcb->mp_conn_cb, pcb_it) {
        //struct mptcp_subflow_pcb *mptcp = pcb_it->mp_sfl_pcb;
      //}
      break;
    }
    case MPTCP_SUB_PRIO: {
      const struct mp_prio *mpprio = (struct mp_prio *) ptr;

      if (opsize != MPTCP_SUB_LEN_PRIO && opsize != MPTCP_SUB_LEN_PRIO_ADDR) {
        break;
      }
      if(pcb->mp_sfl_pcb == NULL) {
          break;
      }
      pcb->mp_sfl_pcb->rcv_low_prio = mpprio->b;

      if (opsize == MPTCP_SUB_LEN_PRIO_ADDR) {

        struct tcp_pcb *pcb_it;
        mptcp_for_each_pcb(pcb->mp_conn_cb, pcb_it) {
          struct mptcp_subflow_pcb *mptcp = pcb_it->mp_sfl_pcb;
          if(mptcp&&(mptcp->rem_id == mpprio->addr_id))  //bugly #2920
            mptcp->rcv_low_prio = mpprio->b;
        }
      }
      break;
    }
      /*case MPTCP_SUB_FAIL:
          if (opsize != MPTCP_SUB_LEN_FAIL) {
              break;
          }
          pcb->mopt->mp_fail = 1;
          break; */
    case MPTCP_SUB_FCLOSE:{
      struct mp_fclose *mp = (struct mp_fclose *)ptr;
      LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: received MP_FASTCLOSE",
        __FUNCTION__, __LINE__));
      LIST_MP_FCLOSE(mp);
      if (opsize != MPTCP_SUB_LEN_FCLOSE) {
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: invalid opsize", __FUNCTION__,
          __LINE__));
        break;
      }
      if(is_sfl_pcb(pcb))
        mptcp_fin_handle_fastclose(pcb, mp->key);
      else
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: invalid pcb", __FUNCTION__,
          __LINE__));
      break;
    }
    default:
      break;
  }  
}

static inline int is_valid_addropt_opsize(u8_t mptcp_ver, struct mp_add_addr *mpadd, int opsize) {
  if (mptcp_ver < MPTCP_VERSION_1 && mpadd->ipver == 4)
    return opsize == MPTCP_SUB_LEN_ADD_ADDR4 || opsize == MPTCP_SUB_LEN_ADD_ADDR4 + 2;
  if (mptcp_ver >= MPTCP_VERSION_1 && mpadd->ipver == 4)
    return opsize == MPTCP_SUB_LEN_ADD_ADDR4_VER1 || opsize == MPTCP_SUB_LEN_ADD_ADDR4_VER1 + 2;
  return 0;
}

static inline int mptcp_sub_len_remove_addr(u16_t bitfield) {
  unsigned int c;
  for (c = 0; bitfield; c++)
    bitfield &= bitfield - 1;
  return MPTCP_SUB_LEN_REMOVE_ADDR + c - 1;
}

int mptcp_sub_len_remove_addr_align(u16_t bitfield) {
  return ALIGN(mptcp_sub_len_remove_addr(bitfield), 4);
}

void mptcp_invalidate_recv_info(void *instance){
	mptcp_recv_info *pRecv_info = (mptcp_recv_info *)mptcp_get_recv_info_ptr(instance);

	pRecv_info->mptcp_info_valid = 0;
}

p_mptcp_recv_info mptcp_get_recv_info(void *instance, mptcp_recv_info *pTcpRecvInfo){	
	mptcp_recv_info *pRecv_info = (mptcp_recv_info *)mptcp_get_recv_info_ptr(instance);
    if(!pRecv_info->mptcp_info_valid)
        return NULL;
	pTcpRecvInfo->recv_data_seq = pRecv_info->recv_data_seq;
	pTcpRecvInfo->recv_sub_data_seq = pRecv_info->recv_sub_data_seq;
	pTcpRecvInfo->recv_data_len = pRecv_info->recv_data_len;
	pTcpRecvInfo->recv_csum = pRecv_info->recv_csum;
	pTcpRecvInfo->sfl_data_seq = pRecv_info->sfl_data_seq;
	pTcpRecvInfo->sfl_data_len = pRecv_info->sfl_data_len;
	pTcpRecvInfo->sfl_data_csum = pRecv_info->sfl_data_csum;
	pTcpRecvInfo->recv_fin_valid = pRecv_info->recv_fin_valid;
	pTcpRecvInfo->recv_csum_valid = pRecv_info->recv_csum_valid;
	pTcpRecvInfo->mptcp_info_valid = pRecv_info->mptcp_info_valid;
	pTcpRecvInfo->sfl_fin_valid = pRecv_info->sfl_fin_valid;

    return pRecv_info;
}

#endif
