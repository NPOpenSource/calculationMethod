/*===========================================================================

                         mptcp_session.c

DESCRIPTION
MPTCP implementation - MPTCP-session



Copyright (c) 2017.04 - 2017.05 Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/

#include <string.h>
#include "lwip/lwipopts.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/mptcp/mptcp_session.h"
#include "lwip/mptcp/mptcp_state.h"
#include "lwip/mptcp/mptcp_ipv4.h"
#if LINUX_PLATFORM
#include "tools/common.h"
#endif

#if LWIP_MPTCP_SUPPORT

/**
 * Create master pcb.
 *
 * @parameter struct tcp_pcb - meta_pcb
 * @parameter u64_t - remote_key
 *
 * @return struct tcp_pcb
 */
int mptcp_create_master_pcb(struct tcp_pcb *meta_pcb, u64_t remote_key)
{
  struct tcp_pcb *master_pcb;
  u64_t idsn = 0, idsn1;
  struct mptcp_cb *mp_conn_pcb;
  int i = 0;
#if MPTCP_TXRX_DUMP_DATA
  char data_dump_file_path[40];
#endif

  if (NULL == meta_pcb || 0 == remote_key)
  {
      return MPTCP_DROP;
  }

  mp_conn_pcb = meta_pcb->mp_conn_cb;
  master_pcb = tcp_new(meta_pcb->instance);

  if(!master_pcb)
  {
    return MPTCP_DROP;
  }

  (void)MEMCPY(master_pcb, meta_pcb, sizeof(struct tcp_pcb));
  master_pcb->is_master_pcb = 1;
  master_pcb->mptcp_is_support = 1;

  /* Generate Initial data-sequence-numbers */
  mptcp_key_sha1(mp_conn_pcb->loc_key, NULL, &idsn);
  idsn1 = idsn;
  idsn = my_ntohll(idsn) + 1;  /* 1 is for sent SYN */
  mp_conn_pcb->snd_high_order = idsn >> 32;
  /* For now, local idsn is stored in snd_nxt of master_pcb.
   * rcv_nxt is exchanged btw meta_pcb and master_pcb after 3rd ACK
   * is sent. It's to let sequence number in 3rd ACK correct. */
  master_pcb->snd_nxt = (u32_t)idsn;
  /*LogE("mptcp_create_master_pcb local mp_conn_pcb->loc_key=%lu idsn=%lu and orgin=%lu snd data ack=0x%08x",mp_conn_pcb->loc_key,idsn, idsn1, master_pcb->snd_nxt);*/

  //TODO:
  //sequence-numbers init

  mp_conn_pcb->rem_key = remote_key;
  mptcp_key_sha1(mp_conn_pcb->rem_key, &mp_conn_pcb->rem_token, &idsn);
  idsn1 = idsn;
  idsn = my_ntohll(idsn) + 1; /* 1 is for received SYN */
  mp_conn_pcb->rcv_high_order = idsn >> 32;
  mp_conn_pcb->dss_csum = 0;
  mp_conn_pcb->loc_id = 0;
  /*mp_conn_pcb->connection_list = NULL;*/
  /* meta_pcb->state = ESTABLISHED; */

  /* For now, remote idsn is stored in rcv_nxt of master_pcb.
   * rcv_nxt is exchanged btw meta_pcb and master_pcb after 3rd ACK
   * is sent. It's to let ACK number in 3rd ACK correct. */
  master_pcb->rcv_nxt = (u32_t)idsn;
  /*LogE("mptcp_create_master_pcb remote mp_conn_pcb->rem_key=%lu idsn=%lu and orgin=%lu rcv_nxt data ack=0x%08x",my_ntohll(mp_conn_pcb->rem_key),idsn, idsn1, master_pcb->rcv_nxt);*/

  meta_pcb->mp_sfl_pcb = NULL;
  /* Set mptcp-pointers */
  //master_pcb->mp_conn_cb = mp_conn_pcb;
  master_pcb->meta_pcb = meta_pcb;
  master_pcb->is_meta_pcb = 0;
  master_pcb->mptcp_enabled = 1;
  meta_pcb->mp_conn_cb = mp_conn_pcb;
  meta_pcb->meta_pcb = meta_pcb;
  meta_pcb->mpc = 1;
 // meta_pcb->ops = &mptcp_meta_specific;

  mptcp_add_pcb(meta_pcb, master_pcb, mp_conn_pcb->loc_id, 0);

  /* For now, real communication is still via meta_pcb, so use its state
   * for snt_isn and rcv_isn. */
  if(meta_pcb->unacked && meta_pcb->unacked->tcphdr)
    master_pcb->mp_sfl_pcb->snt_isn = lwip_ntohl(meta_pcb->unacked->tcphdr->seqno);
  else
    master_pcb->mp_sfl_pcb->snt_isn = meta_pcb->snd_nxt - 1;
  master_pcb->mp_sfl_pcb->rcv_isn = tcp_input_get_current_seqno(meta_pcb->instance);
#if MPTCP_TXRX_DUMP_DATA
  sprintf(data_dump_file_path, "%s/%p_%08x_rx", TXRX_DATA_DUMP_DIR,
    meta_pcb, master_pcb->snd_nxt);
  mp_conn_pcb->rx_data_file = fopen(data_dump_file_path, "wb");
  if(mp_conn_pcb->rx_data_file == NULL)
    LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: fopen() for rx_data_file failed,"
      "path=%s" , __FUNCTION__, __LINE__, data_dump_file_path));
#endif

  return MPTCP_OK;
}

/**
 * Create subflow pcb.
 *
 * @parameter struct tcp_pcb - meta_pcb
 *
 * @return struct tcp_pcb
 */
struct tcp_pcb* mptcp_create_subflow_pcb(struct tcp_pcb *meta_pcb, struct mp_add_addr *mpadd) {
  if (NULL == meta_pcb)
  {
      return NULL;
  }

  struct tcp_pcb  *subflow_pcb;

  subflow_pcb = tcp_new(meta_pcb->instance);
  if(!subflow_pcb)
  {
      return NULL;
  }
  subflow_pcb->local_ip = meta_pcb->local_ip;
  subflow_pcb->callback_arg = meta_pcb->callback_arg;
  subflow_pcb->is_master_pcb = 0;
  subflow_pcb->is_meta_pcb = 0;
  subflow_pcb->is_subflow_pcb = 1;
  subflow_pcb->mptcp_enabled = 1;
  subflow_pcb->state = CLOSED;
  subflow_pcb->mptcp_state = MPTCP_MP_JOIN_SYN_SEND;
  subflow_pcb->local_port = 0; /*Assigned by lwip stack dynamically */
  subflow_pcb->addr_id = mpadd->addr_id;
  subflow_pcb->mptcp_is_support = 1;

  mptcp_add_pcb(meta_pcb, subflow_pcb, meta_pcb->mp_conn_cb->loc_id,  mpadd->addr_id);
  return subflow_pcb;
}

/**
 * Add new_pcb into meta_pcb.
 *
 * @parameter struct tcp_pcb - meta_pcb
 * @parameter struct tcp_pcb - pcb
 * @parameter u8_t - loc_id
 * @parameter u8_t - rem_id
 *
 * @return int
 */

int mptcp_add_pcb(struct tcp_pcb *meta_pcb, struct tcp_pcb *pcb, u8_t loc_id, u8_t rem_id)
{
  pcb->mp_sfl_pcb = (struct mptcp_subflow_pcb *)memp_malloc(MEMP_MPTCP_SUBPCB);
  if (NULL == pcb->mp_sfl_pcb)
      return 0;

  memset(pcb->mp_sfl_pcb, 0 ,sizeof(struct mptcp_subflow_pcb));

  pcb->mp_conn_cb = meta_pcb->mp_conn_cb;
  pcb->meta_pcb = meta_pcb;
  pcb->mpc = 1;
  pcb->mp_sfl_pcb->loc_id = loc_id;
  pcb->mp_sfl_pcb->rem_id = rem_id;
  // connection_list should point to the lastest subflow pcb.
  pcb->mp_sfl_pcb->next = meta_pcb->mp_conn_cb->connection_list;
  meta_pcb->mp_conn_cb->connection_list = pcb;
  meta_pcb->mp_conn_cb->cnt_subflows++;
  return MPTCP_OK;
}

#endif
