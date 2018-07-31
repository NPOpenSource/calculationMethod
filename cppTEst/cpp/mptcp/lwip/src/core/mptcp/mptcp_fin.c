
#include <unistd.h>
#include "lwip/mptcp/mptcp_state.h"
#include "lwip/mptcp/mptcp.h"
#include "lwip/mptcp_fin.h"

#if LWIP_MPTCP_SUPPORT

static inline err_t check_and_close_tcp(struct tcp_pcb *sfl_pcb){
    enum tcp_state state = sfl_pcb->state;
    if(state == ESTABLISHED || state == CLOSE_WAIT)
        return tcp_close(sfl_pcb);
    else if(state == SYN_SENT || state == SYN_RCVD) {
        tcp_abandon(sfl_pcb, 1);
        return ERR_ABRT;
    }
    return ERR_OK;
}

/* Send DATA_FIN on a subflow */
void mptcp_fin_send_data_fin(struct tcp_pcb *sfl_pcb){
    struct mptcp_cb* mpcb;

    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, pcb=%p", __FUNCTION__,
        __LINE__, sfl_pcb));
    mpcb = sfl_pcb->mp_conn_cb;
    if(mpcb->lcl_fin_acked){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: DATA_FIN is acked, not to"
            " send it again.", __FUNCTION__, __LINE__));
        return;
    }
    if(sfl_pcb->rcv_fast_close){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: the pcb meta pcb have been close"
                " do not send data fin", __FUNCTION__, __LINE__));
        return ;
    }
    mpcb->mptcp_flags |= MPTCPHDR_FIN;
    tcp_ack_now(sfl_pcb);
    tcp_output(sfl_pcb);
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
}


/* Only MPTCP related portion is released.
 * Regular TCP portion is still needed for TCP interaction. */
err_t mptcp_fin_remove_sfl(struct tcp_pcb *pcb, u8_t cls_type){
    struct mptcp_cb* mpcb = pcb->mp_conn_cb;
    struct tcp_pcb *meta_pcb = pcb->meta_pcb;
    struct tcp_pcb *tmp, *prev, *next;
    err_t errNo = ERR_OK;
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, pcb=%p, cls_type=%d",
        __FUNCTION__, __LINE__, pcb, cls_type));
    if(pcb->mptcp_close_performed)
        return errNo;
    pcb->mptcp_close_performed = 1;
    /* remove the pcb from subflow pcb list */
    if(pcb == mpcb->connection_list){
        mpcb->connection_list = MEMB_OF_SFL_PCB(pcb,next);
    }else{
        prev = mpcb->connection_list;
        if(prev && prev->mp_sfl_pcb != NULL)
            tmp = MEMB_OF_SFL_PCB(prev,next);
        else
            tmp = NULL;
        while(tmp != NULL){
            if(tmp == pcb){
                if(prev->mp_sfl_pcb != NULL)
                prev->mp_sfl_pcb->next = MEMB_OF_SFL_PCB(pcb,next);
                break;
            }
            prev = tmp;
            tmp = MEMB_OF_SFL_PCB(tmp,next);
        }
    }
    if(pcb->mptcp_state == MPTCP_MP_ESTABLISHED &&
            !MEMB_OF_SFL_PCB(pcb,pre_established))
        mpcb->cnt_established--;
    mpcb->cnt_subflows--;

    if(MEMB_OF_SFL_PCB(pcb,data_buf) != NULL){
        pbuf_free(pcb->mp_sfl_pcb->data_buf);
        pcb->mp_sfl_pcb->data_buf = NULL;
    }
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: release mp_sfl_pcb, pcb=%p, "
        "mp_sfl_pcb=%p", __FUNCTION__, __LINE__, pcb, pcb->mp_sfl_pcb));
    memp_free(MEMP_MPTCP_SUBPCB, pcb->mp_sfl_pcb);
    /*reset flow flag, deal as tcp link*/
    pcb->mp_sfl_pcb = NULL;
    pcb->meta_pcb = NULL;
    pcb->is_meta_pcb = 0;
    pcb->is_master_pcb = 0;
    pcb->is_subflow_pcb = 0;
    pcb->mpc = 0;
    if(cls_type == CLOSE_TYPE_RESET)
        pcb->mptcp_state = MPTCP_MP_CLOSED; /* Do nothing */
    else if(cls_type == CLOSE_TYPE_FASTCLOSE){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: release subflow pcb by "
            "calling tcp_abandon(), pcb=%p", __FUNCTION__, __LINE__, pcb));
        pcb->mptcp_state = MPTCP_MP_CLOSED;
        tcp_abandon(pcb, 0);
        errNo = ERR_ABRT;
    }else{
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: release subflow pcb by "
            "calling check_and_close_tcp(), pcb=%p", __FUNCTION__, __LINE__,
            pcb));
        pcb->mptcp_state = MPTCP_MP_CLOSED;
        errNo = check_and_close_tcp(pcb);
    }
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return errNo;
}

/* Perform release work (MPTCP portion) for close. It may be called in
 * active close or passive close.
 * Normally subflow pcb is release by tcp_close().
 * For active close, meta_pcb is released here.
 * For passive close, meta_pcb is released when final close() is called. */
err_t mptcp_fin_perform_close(struct tcp_pcb *meta_pcb, u8_t cls_type,
        u8_t *tcp_closed_on_master_pcb){
    struct mptcp_cb* mpcb = meta_pcb->mp_conn_cb;
    struct tcp_pcb *next, *tmp = mpcb->connection_list;
    err_t errNo = ERR_OK;
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, meta_pcb=%p, cls_type=%d",
        __FUNCTION__, __LINE__, meta_pcb, cls_type));
    if(meta_pcb->mptcp_close_performed)
        return errNo;
    meta_pcb->mptcp_close_performed = 1;
    while(tmp){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: tmp=%p, tmp->mp_sfl_pcb =%p", __FUNCTION__,
                __LINE__,tmp,tmp->mp_sfl_pcb));
        next = MEMB_OF_SFL_PCB(tmp,next);
        if(tmp->mptcp_close_performed){
            tmp = next;
            continue;
        }
        /*update the connection_list */
        mpcb->connection_list = next;
        mpcb->cnt_subflows --;

        tmp->mptcp_close_performed = 1;
        if(MEMB_OF_SFL_PCB(tmp,data_buf) != NULL){
            pbuf_free(tmp->mp_sfl_pcb->data_buf);
            tmp->mp_sfl_pcb->data_buf = NULL;
        }
        if(tcp_closed_on_master_pcb && tmp->is_master_pcb)
            *tcp_closed_on_master_pcb = 1;
        memp_free(MEMP_MPTCP_SUBPCB, tmp->mp_sfl_pcb);
        tmp->mp_sfl_pcb = NULL;
        tmp->meta_pcb = NULL;
        tmp->mp_conn_cb = NULL;
        tmp->is_meta_pcb = 0;
        tmp->is_master_pcb = 0;
        tmp->is_subflow_pcb = 0;

        tmp->mpc = 0;
        if(cls_type == CLOSE_TYPE_NORMAL) {
            LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: release subflow pcb by "
                    "calling check_and_close_tcp(), pcb=%p", __FUNCTION__, __LINE__,
                    tmp));
            tmp->mptcp_state = MPTCP_MP_CLOSED;
            errNo = check_and_close_tcp(tmp);
        }
        else {
            LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: release subflow pcb by "
                "calling tcp_abandon(), pcb=%p, type=%d", __FUNCTION__, __LINE__, tmp,cls_type));
            tmp->mptcp_state = MPTCP_MP_CLOSED;
            tcp_abandon(tmp, 0);
            errNo = ERR_ABRT;
        }
        tmp = next;
    }
    /* Notify close event to socket API. */
    /* For active close, fields like recv may be NULL here. */
    if(meta_pcb->recv && meta_pcb->callback_arg)
        meta_pcb->recv(meta_pcb->callback_arg, meta_pcb, NULL, ERR_OK);
    /* Remove meta_pcb for active pcb list. */
    tcp_rmv_active_mptcp(meta_pcb);
#if MPTCP_BUF_RECV_OFO_DATA
    if(mpcb->recv_ofo_queue != NULL){
        ofo_data_entry *entry, *prev;
        entry = mpcb->recv_ofo_queue;
        while(entry != NULL){
            prev = entry;
            entry = entry->next;
            pbuf_free(prev->p);
            free(prev);
        }
        mpcb->recv_ofo_queue = NULL;
    }
#endif
#if MPTCP_TXRX_DUMP_DATA
    if(mpcb->rx_data_file != NULL){
        fflush(mpcb->rx_data_file);
        fclose(mpcb->rx_data_file);
    }
#endif
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: mpcb=%p", __FUNCTION__,
            __LINE__,mpcb));
    mptcp_fin_rm_close_candidate(meta_pcb);
    memp_free(MEMP_MPTCP_MPCB, mpcb);
    meta_pcb->mp_conn_cb = NULL;
    meta_pcb->mptcp_state = MPTCP_MP_CLOSED;
    tcp_pcb_purge(meta_pcb);
    meta_pcb->is_meta_pcb = 0;
    meta_pcb->is_master_pcb = 0;
    meta_pcb->is_subflow_pcb = 0;
    meta_pcb->mpc = 0;
    meta_pcb->state = CLOSED;
    if(meta_pcb->meta_active_close){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: release meta_pcb", __FUNCTION__,
            __LINE__));
#if TCP_FIND
    //tcp_port_remove_from_list(meta_pcb->local_port);
#endif
        memp_free(MEMP_TCP_PCB, meta_pcb);
    }else
        meta_pcb->meta_passive_close = 1;
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return errNo;
}

/* Called when local or remote DATA_FIN is acked to check and trigger the
 * close process.
 * For remote DATA_FIN ack case, this function is called at the end of
 * tcp_output() where DATA_FIN ack is sent. */
void mptcp_fin_check_and_perform_close(struct tcp_pcb *meta_pcb){
    struct mptcp_cb* mpcb = meta_pcb->mp_conn_cb;

    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, meta_pcb=%p", __FUNCTION__,
        __LINE__, meta_pcb));
    if(meta_pcb->mptcp_close_performed ||
            meta_pcb->mptcp_state < MPTCP_MP_ESTABLISHED){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: mptcp_close_performed is true"
            ", or mptcp_state is invalid", __FUNCTION__, __LINE__));
        return;
    }
    if(!mpcb->lcl_fin_acked || !mpcb->rmt_fin_acked){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: DATA_FIN is not interacted",
            __FUNCTION__, __LINE__));
        return;
    }
    mptcp_fin_perform_close(meta_pcb, CLOSE_TYPE_NORMAL, NULL);
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
}

/* Close candidate count and list */
/*
#define CLS_CAND_LIST_SIZE 8
static u16_t cnt_cls_cand = 0;
static struct tcp_pcb *cls_cand_list[CLS_CAND_LIST_SIZE];
*/
void mptcp_fin_add_close_candidate(struct tcp_pcb *meta_pcb){
    u16_t i;
    u16_t *pCnt_cls_cand;

    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, meta_pcb=%p", __FUNCTION__,
        __LINE__, meta_pcb));
    mptcp_get_cls_cand(meta_pcb->instance, &pCnt_cls_cand);
    for(i = 0; i < *pCnt_cls_cand; i++)
        if(mptcp_get_cls_cand_list_elem(meta_pcb->instance, i) == meta_pcb)
            break;
    if(i == *pCnt_cls_cand && *pCnt_cls_cand < CLS_CAND_LIST_SIZE)
        mptcp_update_cls_cand_list_elem(meta_pcb->instance,(*pCnt_cls_cand)++,meta_pcb);
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
}
void mptcp_fin_rm_close_candidate(struct tcp_pcb *meta_pcb){
    u16_t i;
    u16_t *pCnt_cls_cand;

    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, meta_pcb=%p", __FUNCTION__,
            __LINE__, meta_pcb));

    mptcp_get_cls_cand(meta_pcb->instance, &pCnt_cls_cand);
    for(i = 0; i < *pCnt_cls_cand; i++) {
        if(mptcp_get_cls_cand_list_elem(meta_pcb->instance, i) == meta_pcb) {
            mptcp_update_cls_cand_list_elem(meta_pcb->instance,i,NULL);
            LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: rm pcb in cls_cand_list. meta_pcb=%p ",
                    __FUNCTION__,__LINE__, meta_pcb));
	    if(i< (*pCnt_cls_cand -1))
	    {
	       mptcp_update_cls_cand_list_elem(meta_pcb->instance,i,mptcp_get_cls_cand_list_elem(meta_pcb->instance, (*pCnt_cls_cand -1)));
            (*pCnt_cls_cand) --;
	    }
            break;
        }
    }
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
}
void mptcp_fin_close_candidate_check(void *instance){
    u16_t i, cnt, temp;
    u16_t *pCnt_cls_cand;
    struct tcp_pcb *pcb;

    mptcp_get_cls_cand(instance, &pCnt_cls_cand);
    cnt = *pCnt_cls_cand;
    for(i = 0; i < cnt; i++){
        pcb = mptcp_get_cls_cand_list_elem(instance, i);
        if(pcb != NULL) {
            if (pcb->mptcp_fc_pending_close) {
                pcb->mptcp_fc_pending_close = 0;
                mptcp_fin_perform_close(pcb, CLOSE_TYPE_FASTCLOSE, NULL);
            } else
                mptcp_fin_check_and_perform_close(pcb);
        }
    }
    *pCnt_cls_cand = 0;
}

/* Perform close when close() or shutdown() socket API is called */
void mptcp_fin_trigger_close(struct tcp_pcb *meta_pcb, struct tcp_pcb *sfl_pcb,
        u8_t *tcp_close_needed){
    struct mptcp_cb* mpcb = meta_pcb->mp_conn_cb;
    u8_t tcp_closed_on_master_pcb = 0;

    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, meta_pcb=%p", __FUNCTION__,
        __LINE__, meta_pcb));
    if(tcp_close_needed)
        *tcp_close_needed = 0;
    /* Close already performed */
    if(meta_pcb->meta_passive_close)
        return;
    if(meta_pcb->mptcp_state < MPTCP_MP_ESTABLISHED){
        /* Is it correct? Is DATA_FIN interaction needed in this case? */
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: MPTCP connection is not established, "
            "call mptcp_fin_perform_close()", __FUNCTION__, __LINE__));
        mptcp_fin_perform_close(meta_pcb, CLOSE_TYPE_NORMAL,
            &tcp_closed_on_master_pcb);
        if(tcp_close_needed && !tcp_closed_on_master_pcb)
            *tcp_close_needed = 1;
    }else if(!mpcb->lcl_fin_sent){
        struct tcp_pcb *tmp;
        if(sfl_pcb)
            tmp = sfl_pcb;
        else{
            /* Select a subflow to send DATA_FIN. Master subflow is preferred */
            tmp = mpcb->connection_list;
            while(tmp){
                if(tmp->is_master_pcb)
                    break;
                tmp = MEMB_OF_SFL_PCB(tmp,next);
            }
            if(!tmp)
                tmp = mpcb->connection_list;
        }
        if(tmp){
            LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: call mptcp_fin_send_data_fin"
                "(), pcb=%p", __FUNCTION__, __LINE__, tmp));
            mptcp_fin_send_data_fin(tmp);
        }else{
            LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: No subflow is available. call"
                " mptcp_fin_perform_close()", __FUNCTION__, __LINE__));
            mptcp_fin_perform_close(meta_pcb, CLOSE_TYPE_NORMAL, NULL);
        }
    }
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
}

/* Called when FIN is received from subflow (but not acked) */
err_t mptcp_fin_sfl_recved_fin(struct tcp_pcb *sfl_pcb){
    struct mptcp_cb* mpcb = sfl_pcb->mp_conn_cb;
    struct tcp_pcb *meta_pcb = sfl_pcb->meta_pcb;
    u8_t wait_data_fin_ack = 0;
    err_t errNo = ERR_OK;

    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, sfl_pcb=%p", __FUNCTION__,
        __LINE__, sfl_pcb));
    if(mpcb == NULL || meta_pcb == NULL || sfl_pcb->mptcp_close_performed)
        return errNo;
    if(mpcb->cnt_established > 1){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: subflow count > 1, only release"
            " this subflow", __FUNCTION__, __LINE__));
        return mptcp_fin_remove_sfl(sfl_pcb, CLOSE_TYPE_NORMAL);
    }
    /* If DATA_FIN is sent or received, perform close of connection level. */
    if(mpcb->rmt_fin_recved && !mpcb->lcl_fin_sent){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: DATA_FIN received, but not sent,"
            " send it now", __FUNCTION__, __LINE__));
        wait_data_fin_ack = 1;
        mptcp_fin_send_data_fin(sfl_pcb);
    }
    if(mpcb->lcl_fin_sent && !mpcb->lcl_fin_acked)
        wait_data_fin_ack = 1;

    /* Wait sometime to allow server ack DATA_FIN. If FIN is acked too
     * quickly, we may fail to receive ack of DATA_FIN from server */
    if(wait_data_fin_ack){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: sleep 50ms to allow the peer"
            " ack the DATA_FIN", __FUNCTION__, __LINE__));
        usleep(50000);
    }
    /* Add a remedy in case that DATA_FINs don't interact properly */
    meta_pcb->mptcp_cls_chk_tmr++;
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return errNo;
}

err_t mptcp_fin_sfl_recved_rst(struct tcp_pcb *sfl_pcb){
    struct mptcp_cb* mpcb = sfl_pcb->mp_conn_cb;
    struct tcp_pcb *meta_pcb = sfl_pcb->meta_pcb;
    err_t errNo = ERR_OK;
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, sfl_pcb=%p", __FUNCTION__,
        __LINE__, sfl_pcb));
    if(mpcb == NULL || meta_pcb == NULL || sfl_pcb->mptcp_close_performed)
        return errNo;
    if(mpcb->cnt_established > 1){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: subflow count > 1, only release"
            " this subflow", __FUNCTION__, __LINE__));
        return mptcp_fin_remove_sfl(sfl_pcb, CLOSE_TYPE_RESET);
    }
    /* Received RST on a subflow that is not established */
    if(sfl_pcb->mptcp_state != MPTCP_MP_ESTABLISHED ||
            MEMB_OF_SFL_PCB(sfl_pcb,pre_established)){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: subflow is not established, "
            "release it", __FUNCTION__, __LINE__));
        return mptcp_fin_remove_sfl(sfl_pcb, CLOSE_TYPE_RESET);
    }
    /* No established subflow left, perform close of connection level. */
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return mptcp_fin_perform_close(meta_pcb, CLOSE_TYPE_RESET, NULL);
}

void mptcp_fin_handle_fastclose(struct tcp_pcb *sfl_pcb, u64_t sender_key){
    struct mptcp_cb* mpcb = sfl_pcb->mp_conn_cb;
    struct tcp_pcb *meta_pcb = sfl_pcb->meta_pcb;
    struct tcp_pcb *pcb;
    int ret = 0;

    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: enter, sfl_pcb=%p, sender_key="
        "%llx, loc_key=%llx", __FUNCTION__, __LINE__, sfl_pcb, sender_key,
        mpcb->loc_key));
    if(memcmp(&mpcb->loc_key, &sender_key, sizeof(u64_t)) != 0){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: invalid sender_key, recved=%llx, "
            "expected=%llx", __FUNCTION__, __LINE__, sfl_pcb, sender_key,
             mpcb->loc_key));
        return;
    }
    pcb = sfl_pcb;
    tcp_rst(pcb->instance,pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,
        pcb->local_port, pcb->remote_port);
    pcb = mpcb->connection_list;

    while(pcb != NULL){
        if(pcb != sfl_pcb) {
            if(pcb->mptcp_state == MPTCP_MP_ESTABLISHED)
              tcp_rst(pcb->instance, pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip,
                    &pcb->remote_ip, pcb->local_port, pcb->remote_port);
            LWIP_DEBUGF(MPTCP_FIN_DEBUG,("current pcb:%p mptcp_state:%d",pcb,pcb->mptcp_state));
        }
        sfl_pcb->rcv_fast_close = 1; /*set rcv fast close flag, don't need send data fin again*/
        pcb = MEMB_OF_SFL_PCB(pcb,next);
    }
    meta_pcb->mptcp_fc_pending_close = 1;
    TCP_EVENT_CLOSED(meta_pcb,ret);  /* notify the socket api to know the meta_pcb have been closed*/
    mptcp_fin_add_close_candidate(meta_pcb); /*handle the fast closed to clear subflow resource in the mate_pcb*/
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
}
#endif
