
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/inet_chksum.h"
#include "lwip/mptcp/mptcp.h"
#include "lwip/mptcp/mptcp_tcp.h"
#include "lwip/mptcp/mptcp_input_output.h"
#include <string.h>

#if LWIP_MPTCP_SUPPORT

#define MAX_DATA_LEN 65535

struct tcp_seg *
tcp_create_segment_extra(struct tcp_pcb *pcb, struct pbuf *p, u8_t flags,
    u32_t seqno, u16_t optflags, u8_t for_mt_data);

static inline int before(u32_t seq1, u32_t seq2){
    return (seq1-seq2) > TCP_WND*2;
}
#define after(seq2, seq1) before(seq1, seq2)

void mptcp_check_incoming_ack(struct tcp_pcb *sfl_pcb, u32_t data_ack){
    struct tcp_pcb *meta_pcb = sfl_pcb->meta_pcb;
    struct mptcp_subflow_pcb* spcb = sfl_pcb->mp_sfl_pcb;
    struct tcp_seg *next;
    u16_t acked_len = 0;
    meta_pcb->lastack = data_ack; /* add for meta pcb last ack */

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter sfl_pcb=%p, meta_pcb=%p, "
        "data_ack=%08x", __FUNCTION__, __LINE__, sfl_pcb, meta_pcb, data_ack));

    if(meta_pcb->unacked == NULL){
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: no unacked data",
            __FUNCTION__, __LINE__));
        return;
    }

    next = meta_pcb->unacked;
    if(next){
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: next=%p, seqno=%08x, seg_len=%d",
            __FUNCTION__, __LINE__, next, lwip_ntohl(next->tcphdr->seqno),
            TCP_TCPLEN(next)));
    }
    while(next && TCP_SEQ_LEQ(lwip_ntohl(next->tcphdr->seqno) +
            TCP_TCPLEN(next), data_ack)){
        meta_pcb->snd_queuelen -= pbuf_clen(next->p);
        acked_len += next->len;
        meta_pcb->unacked = next->next;
        tcp_seg_free(next);
        next = meta_pcb->unacked;
        if(next){
            LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: seqno=%08x, seg_len=%d",
                __FUNCTION__, __LINE__, lwip_ntohl(next->tcphdr->seqno),
                TCP_TCPLEN(next)));
        }
    }
    meta_pcb->snd_buf += acked_len;
    if(meta_pcb->sent && meta_pcb->callback_arg)
        meta_pcb->sent(meta_pcb->callback_arg, meta_pcb, acked_len);
    if(acked_len > 0)
        mptcp_output(meta_pcb);
    LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: leave, acked_len=%d",
        __FUNCTION__, __LINE__, acked_len));
}

static u16_t mptcp_add_chksum(u16_t cnt, u16_t *csums, u16_t *lengs){
    u32_t acc = 0;
    u8_t swapped = 0;
    u16_t i;

    for(i = 0; i < cnt; i++){
        acc += csums[i];
        acc = (u32_t)FOLD_U32T(acc);
        if((lengs[i] % 2) != 0){
            swapped = 1 - swapped;
            acc = SWAP_BYTES_IN_WORD(acc);
        }
    }
    if(swapped)
        acc = SWAP_BYTES_IN_WORD(acc);
    return (u16_t)(acc & 0x0000ffff);
}

u16_t mptcp_calculate_outgoing_csum(struct tcp_pcb *pcb, struct tcp_seg *seg,
        u32_t meta_seq, u32_t sub_data_seq, u16_t data_len){
    struct mptcp_cb *mpcb = pcb->mp_conn_cb;
    u64_t data_seq;
    /* See P26 (3.1.1) of RFC6824 for structure of pseudo header */
    u8_t pseudo_header[16] = {0};
    u32_t acc;
    u16_t result;
    void *pdata;
	u64_t *pdata_seq = (u64_t *)pseudo_header;
	u32_t *psub_data_seq = (u32_t *)(pseudo_header+8);
	u16_t *pdata_len = (u16_t *)(pseudo_header+12);

    *pdata_seq = my_htonll((((u64_t)(mpcb->snd_high_order) << 32) | (u64_t)meta_seq));
    //memset(pseudo_header, 0, 16);
    //data_seq = my_htonll(data_seq);
    //memcpy(pseudo_header, &data_seq, 8); /* 8 octets of Data Sequence */
    *psub_data_seq = lwip_htonl(sub_data_seq);
    //memcpy(&pseudo_header[8], &sub_data_seq, 4); /* 4 octets of subflow Sequence */
    *pdata_len = lwip_htons(data_len);
    //memcpy(&pseudo_header[12], &data_len, 2); /* 2 octets of data length */
    acc = (u32_t)lwip_standard_chksum(pseudo_header, 16);

    /* data must be in a single pbuf */
    pdata = (void *)((u8_t *)seg->p->payload + (seg->p->tot_len - seg->len));
    seg->mptcp_data_chksum = lwip_standard_chksum(pdata, seg->len);
    acc += seg->mptcp_data_chksum;

    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);
    result = (u16_t)~(acc & 0xffffUL);

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave, result=%04x", __FUNCTION__,
        __LINE__, result));
    return result;
}

u16_t mptcp_calculate_fin_csum(struct tcp_pcb *pcb, u32_t meta_seq,
        u8_t snd_or_rcv){
    struct mptcp_cb *mpcb = pcb->mp_conn_cb;
    /* See P26 (3.1.1) of RFC6824 for structure of pseudo header */
    u8_t pseudo_header[16];
    u64_t data_seq;
    u32_t sub_data_seq = 0, high_order;
    u16_t data_len = 1, result;

    if(snd_or_rcv)
        high_order = mpcb->snd_high_order;
    else
        high_order = mpcb->rcv_high_order;
    data_seq = ((((u64_t)high_order) << 32) | (u64_t)meta_seq);
    memset(pseudo_header, 0, 16);
    data_seq = my_htonll(data_seq);
    memcpy(pseudo_header, &data_seq, 8); /* 8 octets of Data Sequence */
    sub_data_seq = lwip_htonl(sub_data_seq);
    memcpy(&pseudo_header[8], &sub_data_seq, 4); /* 4 octets of subflow Sequence */
    data_len = lwip_htons(data_len);
    memcpy(&pseudo_header[12], &data_len, 2); /* 2 octets of data length */
    result = inet_chksum(pseudo_header, 16);
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("%s:%d: pcb=%p, meta_seq=%08x, snd_or_rcv=%d"
        ", result=%04x", __FUNCTION__, __LINE__, pcb, meta_seq, snd_or_rcv, result));
    return result;
}

static int mptcp_detect_mapping(struct tcp_pcb *pcb,
        p_mptcp_recv_info recv_info){
    struct tcp_pcb *meta_pcb = pcb->meta_pcb;
    struct mptcp_subflow_pcb *spcb = pcb->mp_sfl_pcb;
    struct mptcp_cb *mpcb = pcb->mp_conn_cb;
    u32_t data_seq, sub_seq, data_len, tcp_start_seq, tcp_end_seq, tmp, nxt;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, pcb=%p, len=%d", __FUNCTION__,
        __LINE__, pcb, recv_info->sfl_data_len));
    if(!recv_info->mptcp_info_valid)
        return 0;

    if(spcb == NULL)
    {
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: spcb is NULL, pcb=%p, len=%d", __FUNCTION__,
        __LINE__, pcb, recv_info->sfl_data_len));
        return 1;
    }

    data_seq = recv_info->recv_data_seq;
    sub_seq = recv_info->recv_sub_data_seq + spcb->rcv_isn;
    data_len = (u32_t)recv_info->recv_data_len;
    tcp_start_seq = recv_info->sfl_data_seq;
    tcp_end_seq = tcp_start_seq + recv_info->sfl_data_len;

    if(spcb->mapping_present && (
            data_seq != (u32_t)spcb->map_data_seq ||
            sub_seq != spcb->map_subseq ||
            data_len != spcb->map_data_len + spcb->map_data_fin ||
            recv_info->recv_fin_valid != spcb->map_data_fin)){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: mapping already exist and not"
            "match with this received one data_seq:%08x nxt:%08x mp_seq:%p map_subSeq:%08x",
                __FUNCTION__, __LINE__, data_seq, meta_pcb->rcv_nxt, spcb->map_data_seq, spcb->map_subseq));
        return 1;
    }

    if(spcb->mapping_present)
        return 0;

    /* FIN increased the mapping-length by 1 */
    if(recv_info->recv_fin_valid)
        data_len--;

    /* subflow-fin is not part of the mapping - ignore it here ! */
    if(recv_info->sfl_fin_valid)
        tcp_end_seq--;
    if((!before(sub_seq, tcp_end_seq) && after(tcp_end_seq, tcp_start_seq)) ||
        (recv_info->recv_fin_valid && (tcp_end_seq - tcp_start_seq) == 0 && after(sub_seq, tcp_end_seq)) ||
        (!after(sub_seq + data_len, tcp_start_seq) && after(tcp_end_seq, tcp_start_seq))){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: mapping not valid, tcp_start_seq",
            "=%08x, tcp_end_seq=%08x, sub_seq=%08x, data_len=%d, recv_fin_valid=%d",
            __FUNCTION__, __LINE__, tcp_start_seq, tcp_end_seq, sub_seq,
            data_len, recv_info->recv_fin_valid));
        return 1;
    }

    /* Check whether data is duplicanted(received) data */
    tmp = data_seq + data_len;
    nxt = meta_pcb->rcv_nxt;
    if(tmp < nxt && !((nxt + TCP_WND*2 < nxt) && (tmp < nxt + TCP_WND*2))){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: duplicated mapping data received"
            ", ignore, end=%08x, nxt=%08x", __FUNCTION__, __LINE__, tmp, nxt));
        return 1;
    }

    /* Check whether data is too far advanced. */
    /* Case of that nxt is about to wrap is checked in the above
     * duplication check. */
    if(tmp > nxt && (tmp - nxt > TCP_WND)){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: received mapping data is too far"
            " advanced, ignore, end=%08x, nxt=%08x", __FUNCTION__, __LINE__,
            tmp, nxt));
        return 1;
    }

    /* Check whether data is partly duplicated */
    /* For simplicity, discard such data for now */
    if(data_seq < nxt && (data_seq + data_len >= nxt)){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: partly duplicated mapping data "
            "received, ignore, seq=%08x, nxt=%08x, len=%d", __FUNCTION__,
            __LINE__, data_seq, nxt, spcb->map_data_len));
        return 1;
    }

    /* Currently assume seq is 32bit */
    if(before(data_seq + data_len,  data_seq)) /* Wrapped around? */
        spcb->map_data_seq = (((u64_t)(++(mpcb->rcv_high_order)) << 32) | data_seq);
    else
        spcb->map_data_seq = (((u64_t)(mpcb->rcv_high_order) << 32) | data_seq);

    spcb->map_data_len = (u16_t)data_len;
    spcb->map_subseq = recv_info->recv_sub_data_seq;
    spcb->map_csum = recv_info->recv_csum;
    spcb->map_data_fin = recv_info->recv_fin_valid;
    spcb->mapping_present = 1;
    spcb->csum_acc = 0;
    LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: map_data_seq=%llx, map_data_len"
        "=%d, map_subseq=%08x, map_csum=%04x, map_data_fin=%d" , __FUNCTION__,
        __LINE__, spcb->map_data_seq, spcb->map_data_len, spcb->map_subseq,
        spcb->map_csum, spcb->map_data_fin));

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return 0;
}

static int mptcp_validate_mapping(struct tcp_pcb *pcb,
        p_mptcp_recv_info recv_info){
    struct tcp_pcb *meta_pcb = pcb->meta_pcb;
    struct mptcp_subflow_pcb *spcb = pcb->mp_sfl_pcb;
    struct mptcp_cb *mpcb = pcb->mp_conn_cb;
    u32_t tcp_start_seq, tcp_end_seq, map_subseq;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, pcb=%p, len=%d", __FUNCTION__,
        __LINE__, pcb, recv_info->sfl_data_len));
    if(!spcb->mapping_present)
        return 0;

    map_subseq = spcb->map_subseq + spcb->rcv_isn;
    tcp_start_seq = recv_info->sfl_data_seq;
    tcp_end_seq = tcp_start_seq + recv_info->sfl_data_len;

    if(before(tcp_start_seq, map_subseq) &&
            after(tcp_end_seq, map_subseq)){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: validation failed, start_seq="
            "%08x, map_subseq=%08x, end_seq=%08x, map_subseq=%08x",
            __FUNCTION__, __LINE__, tcp_start_seq, map_subseq, tcp_end_seq));
        return 1;
    }

    if(recv_info->sfl_fin_valid)
        tcp_end_seq--;
    if(after(tcp_end_seq, map_subseq + spcb->map_data_len)){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: validation failed, end_seq=%08x"
            ", map_subseq=%08x, map_data_len=%d", __FUNCTION__, __LINE__,
            tcp_end_seq, map_subseq, spcb->map_data_len));
        return 1;
    }

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return 0;
}
#if 1
static int mptcp_check_checksum(struct tcp_pcb *pcb){
    return 0;
}
#else
static int mptcp_check_checksum(struct tcp_pcb *pcb){
    struct mptcp_subflow_pcb *spcb = pcb->mp_sfl_pcb;
    /* See P26 (3.1.1) of RFC6824 for structure of pseudo header */
    u8_t pseudo_header[16];
    u16_t csum, result, data_len;
    u64_t data_seq;
    u32_t sub_seq, acc;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, pcb=%p",
        __FUNCTION__, __LINE__, pcb));
    LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: map_data_seq=%llx, "
        "map_data_len=%d, map_subseq=%08x, map_csum=%04x, map_data_fin=%d",
        __FUNCTION__, __LINE__, spcb->map_data_seq, spcb->map_data_len,
        spcb->map_subseq, spcb->map_csum, spcb->map_data_fin));
    memset(pseudo_header, 0, 16);
    data_seq = my_htonll(spcb->map_data_seq);
    memcpy(pseudo_header, &data_seq, 8); /* 8 octets of Data Sequence */
    sub_seq = lwip_htonl(spcb->map_subseq);
    memcpy(&pseudo_header[8], &sub_seq, 4); /* 4 octets of subflow Sequence */
    data_len = lwip_htons(spcb->map_data_len + spcb->map_data_fin);
    memcpy(&pseudo_header[12], &data_len, 2); /* 2 octets of data length */
    csum = lwip_standard_chksum(pseudo_header, 16);

    acc = spcb->csum_acc;
    acc += csum;
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);
    result = (u16_t)~(acc & 0xffffUL);

    if(result != spcb->map_csum){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: checksum not match, map_csum="
            "%04x, result=%04x", __FUNCTION__, __LINE__, spcb->map_csum,
            result));
        return 1;
    }else
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: leave, map_csum=%04x, "
            "result=%04x", __FUNCTION__, __LINE__, spcb->map_csum, result));

    return 0;
}
#endif
#define DISTANCE_OFO TCP_WND*2
int before_ofo_packet(ofo_data_entry *o1,ofo_data_entry *o2){
    u32_t  dis = 0;
    dis = o1->seq - o2->seq;
    if(dis < DISTANCE_OFO){
        return 0;
    }else{
        return 1;
    }
}
static int mptcp_queue_packet(struct tcp_pcb *pcb, struct pbuf *recv_data,
        p_mptcp_recv_info recv_info){
    struct tcp_pcb *meta_pcb = pcb->meta_pcb;
    struct mptcp_subflow_pcb *spcb = pcb->mp_sfl_pcb;
    struct mptcp_cb *mpcb = pcb->mp_conn_cb;
#if MPTCP_BUF_RECV_OFO_DATA
    ofo_data_entry *ofo_data, *entry, *prev;
#endif
    u32_t tmp, nxt;
    u16_t data_len;
    err_t ret = ERR_OK;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter", __FUNCTION__, __LINE__));
    if(!spcb->mapping_present){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: mapping is not present",
            __FUNCTION__, __LINE__));
        return 1;
    }

    if(spcb->data_buf == NULL)
        spcb->data_buf = recv_data;
    else
        pbuf_cat(spcb->data_buf, recv_data);

    spcb->csum_acc += recv_info->sfl_data_csum;

    /* Have we not yet received the full mapping? */
    tmp = spcb->map_subseq + spcb->rcv_isn;
    nxt = recv_info->sfl_data_seq + recv_info->sfl_data_len;
    if(before(nxt, tmp + spcb->map_data_len) ||
            (((tmp + spcb->map_data_len) < tmp) && tmp < nxt)){
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: Not received full mapping",
            __FUNCTION__, __LINE__));
        return 0;
    }

    /* Invalidate the mapping */
    spcb->mapping_present = 0;

    /* check checksum */
    if(mptcp_check_checksum(pcb)){
        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: mptcp_check_checksum() failed",
            __FUNCTION__, __LINE__));
        pbuf_free(spcb->data_buf);
        goto leave;
    }

    if(pcb->is_master_pcb)
        spcb->data_buf->flags |= PBUF_FLAG_MSTR_RCV_DATA;

#if MPTCP_BUF_RECV_OFO_DATA
#define entry_before(a, b) \
(((a)->wrapped && !(b)->wrapped) || \
 ((a)->wrapped == (b)->wrapped && (a)->seq < (b)->seq))

    /* If received data is OFO, put it in OFO queue */
    tmp = (u32_t)(spcb->map_data_seq & 0xFFFFFFFF);
    nxt = meta_pcb->rcv_nxt;
    if(tmp != nxt){
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: received OFO data, seq=%08x, "
            "nxt=%08x", __FUNCTION__, __LINE__, tmp, nxt));
        ofo_data = (ofo_data_entry *)malloc(sizeof(ofo_data_entry));
        if(ofo_data == NULL)
            goto leave;
        memset(ofo_data, 0, sizeof(ofo_data_entry));
        ofo_data->p = spcb->data_buf;
        ofo_data->seq = tmp;
        ofo_data->data_len = spcb->map_data_len;
        //ofo_data->wrapped = tmp < nxt ? 1 : 0;
        prev = entry = mpcb->recv_ofo_queue;
        while(entry != NULL){
            /* Received duplicanted advanced data, discard it */
            if(tmp == entry->seq){
                pbuf_free(ofo_data->p);
                free(ofo_data);
                goto leave;
            }
            if(before_ofo_packet(ofo_data,entry))
                break;
            prev = entry;
            entry = entry->next;
        }
        ofo_data->next = entry;
        if(prev == entry)
            mpcb->recv_ofo_queue = ofo_data;
        else
            prev->next = ofo_data;
        goto leave;
    }
#endif

    /* checksume checked OK, update acked count of meta_pcb */
    tmp = meta_pcb->rcv_nxt;
    meta_pcb->rcv_nxt += spcb->data_buf->tot_len;
    /* check wrapped around and update rcv_high_order */
    if(before(meta_pcb->rcv_nxt, tmp)){
        mpcb->rcv_high_order++;
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: meta_pcb->rcv_nxt wrapped",
            __FUNCTION__, __LINE__));
    }

    /* Notify data to upper layer application */
#if MPTCP_TXRX_DUMP_DATA
    if(mpcb->rx_data_file != NULL){
        fwrite(spcb->data_buf->payload, 1, spcb->data_buf->tot_len,
            mpcb->rx_data_file);
        fflush(mpcb->rx_data_file);
    }
#endif
    meta_pcb->recv_cnt += spcb->data_buf->tot_len;
//LWIP_PLATFORM_DIAG(("[wuzmdebug]%s:%d: pcb=%p, meta_pcb=%p, recv_cnt=%d", __FUNCTION__, __LINE__, pcb, meta_pcb, meta_pcb->recv_cnt));
    if(meta_pcb->recv && meta_pcb->callback_arg){
        ret = meta_pcb->recv(meta_pcb->callback_arg, meta_pcb, spcb->data_buf,
            ERR_OK);
        if(ret != ERR_OK){
            LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: recv() callback failed, "
                "meta_pcb=%p, ret=%d", __FUNCTION__, __LINE__, meta_pcb, ret));
            pbuf_free(spcb->data_buf);
        }
    }

#if MPTCP_BUF_RECV_OFO_DATA
    /* Check data in ofo queue whether it's in order now. If so notify it to
     * application layer */
    if(mpcb->recv_ofo_queue != NULL){
        entry = mpcb->recv_ofo_queue;
        while(entry != NULL){
            if(entry->seq == meta_pcb->rcv_nxt){
                tmp = meta_pcb->rcv_nxt;
                meta_pcb->rcv_nxt += entry->p->tot_len;
                if(before(meta_pcb->rcv_nxt, tmp)){
                    mpcb->rcv_high_order++;
                    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: meta_pcb->rcv_nxt "
                        "wrapped", __FUNCTION__, __LINE__));
                }
#if MPTCP_TXRX_DUMP_DATA
                if(mpcb->rx_data_file != NULL){
                    fwrite(entry->p->payload, 1, entry->p->tot_len,
                        mpcb->rx_data_file);
                    fflush(mpcb->rx_data_file);
                }
#endif
                meta_pcb->recv_cnt += entry->p->tot_len;
//LWIP_PLATFORM_DIAG(("[wuzmdebug]%s:%d: pcb=%p, meta_pcb=%p, recv_cnt=%d", __FUNCTION__, __LINE__, pcb, meta_pcb, meta_pcb->recv_cnt));
                if(meta_pcb->recv && meta_pcb->callback_arg){
                    ret = meta_pcb->recv(meta_pcb->callback_arg, meta_pcb,
                        entry->p, ERR_OK);
                    if(ret != ERR_OK){
                        LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: recv() callback"
                            " failed, meta_pcb=%p, ret=%d", __FUNCTION__,
                            __LINE__, meta_pcb, ret));
                        pbuf_free(entry->p);
                    }
                }
                prev = entry;
                mpcb->recv_ofo_queue = entry = entry->next;
                free(prev);
            }else if(entry->seq < meta_pcb->rcv_nxt){
                /* Discard the bufferred data */
                /*if the data is ok,the seq has been overflow*/
                if( before(entry->seq,meta_pcb->rcv_nxt)){
                    prev = entry;
                    mpcb->recv_ofo_queue = entry = entry->next;
                    pbuf_free(prev->p);
                    free(prev);
                }else{
                     /*not overflow ,head not match the rceive_next*/
                    break;
                }
            }else {
                if (entry != NULL)
                    LWIP_DEBUGF(LWIP_DBG_OFF,
                                ("%s:%d entry seq:%8x", __func__, __LINE__, entry->seq));
                break;
            }
        }
    }
#endif

leave:
    spcb->data_buf = NULL;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return 0;
}

err_t mptcp_input(struct tcp_pcb *sfl_pcb, struct pbuf *recv_data,
        p_mptcp_recv_info recv_info){
    u16_t data_len = recv_data->tot_len;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, sfl_pcb=%p, data_len=%d",
            __FUNCTION__, __LINE__, sfl_pcb, data_len));

    /* If error occurs in mapping detecting and validating, discard the
     * mapping and the data by returning ERR_OK. */
    if(mptcp_detect_mapping(sfl_pcb, recv_info)) {
        tcp_recved(sfl_pcb, recv_info->sfl_data_len);
        pbuf_free(recv_data);
        goto leave;
    }

    if(mptcp_validate_mapping(sfl_pcb, recv_info)) {
        tcp_recved(sfl_pcb, recv_info->sfl_data_len);
        pbuf_free(recv_data);
        goto leave;
    }

#if 0 /* Temporarily delete it. Need to be further considered. */
    if(sfl_pcb->meta_pcb->rcv_wnd < recv_data->tot_len){
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: rcv_wnd of meta_pcb is too "
            "small", __FUNCTION__, __LINE__));
        return ERR_MEM;
    }
#endif

    /* recv_data->tot_len may change in mptcp_queue_packet(). */
    if(mptcp_queue_packet(sfl_pcb, recv_data, recv_info)){
        tcp_recved(sfl_pcb, recv_info->sfl_data_len);
        pbuf_free(recv_data);
    }

leave:
    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return ERR_OK;
}

err_t mptcp_output(struct tcp_pcb *meta_pcb){
    err_t ret;
    u16_t hdr_len, opt_len;
    u32_t old_value;
    struct tcp_pcb *sfl_pcb;
    struct tcp_seg *seg, *nseg, *tmp;
    struct pbuf *buf;
    struct mptcp_cb *mpcb = meta_pcb->mp_conn_cb;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, meta_pcb=%p", __FUNCTION__,
        __LINE__, meta_pcb));
    if(meta_pcb->mptcp_close_performed == 1) {
        LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: all sub flow has closed, return", __FUNCTION__,
                __LINE__));
        return ERR_CLSD;
    }

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("%s:%d meta_pcb->snd_nxt:%08x,meta_pcb->lastack:%08x,meta_pcb->snd_wnd:%08x port:%d",__func__,__LINE__,meta_pcb->snd_nxt,meta_pcb->lastack,meta_pcb->snd_wnd,meta_pcb->local_port));

    while((seg = meta_pcb->unsent) != NULL){
        if(lwip_ntohl(seg->tcphdr->seqno) - meta_pcb->lastack + seg->len > meta_pcb->snd_wnd ){
            LWIP_DEBUGF(LWIP_DBG_ON,("%s:%d window is full, pcb->snd_nxt:%u last_ack:%u pcb->snd_wnd:%u",__func__,__LINE__,meta_pcb->snd_nxt,meta_pcb->lastack, meta_pcb->snd_wnd));
            return ERR_OK;
        }
        sfl_pcb = mptcp_get_available_subflow(meta_pcb, seg->len);
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: got subflow, sfl_pcb=%p",
            __FUNCTION__, __LINE__, sfl_pcb));
        if(sfl_pcb == NULL){
            LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: No subflow is available",
                __FUNCTION__, __LINE__));
            return ERR_WOULDBLOCK;
        }
        opt_len = mptcp_count_dss_opt_len(1, 1, mpcb->dss_csum);
        opt_len += LWIP_TCP_OPT_LENGTH(seg->flags);
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: seg_len=%d, opt_len=%d",
            __FUNCTION__, __LINE__, seg->len, opt_len));
        buf = pbuf_alloc(meta_pcb->instance,PBUF_TRANSPORT, seg->len + opt_len, PBUF_RAM);
        if(buf == NULL){
            LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: pbuf_alloc() failed",
                __FUNCTION__, __LINE__));
            return ERR_MEM;
        }
        hdr_len = seg->p->tot_len - seg->len;
        if(pbuf_copy_partial(seg->p, (void *)(((u8_t *)buf->payload) + opt_len),
                seg->len, hdr_len) <= 0){
            LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: pbuf_copy_partial() failed",
                __FUNCTION__, __LINE__));
            return ERR_MEM;
        }
        /* Todo: flags and optflags arguments need to be further considered */
        if((nseg = tcp_create_segment_extra(sfl_pcb, buf, 0, sfl_pcb->snd_lbb,
                seg->flags, 1)) == NULL){
            LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: tcp_create_segment_extra() "
                "failed, sfl_pcb=%p", __FUNCTION__, __LINE__, sfl_pcb));
            return ERR_MEM;
        }
        nseg->meta_seq = meta_pcb->snd_nxt;
        TCPH_SET_FLAG(nseg->tcphdr, TCP_PSH);
        nseg->rexmit = 0;
        //add new segment to the unsent queue of the subflow
        if(sfl_pcb->unsent){
            tmp = sfl_pcb->unsent;
            while(tmp->next)
                tmp = tmp->next;
            tmp->next = nseg;
        }else
            sfl_pcb->unsent = nseg;
        sfl_pcb->snd_buf -= nseg->len;
        sfl_pcb->snd_queuelen += pbuf_clen(nseg->p);
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: update sfl_pcb state, "
            "sfl_pcb=%p, snd_buf=%d, snd_queuelen=%d", __FUNCTION__, __LINE__,
            sfl_pcb, sfl_pcb->snd_buf, sfl_pcb->snd_queuelen));
        ret = tcp_output(sfl_pcb);
        if(ret != ERR_OK){
            LWIP_DEBUGF(ERROR_LOGGING, ("%s:%d: tcp_output() failed, ret=%d, "
                "sfl_pcb=%p", __FUNCTION__, __LINE__, ret, sfl_pcb));
            return ret;
        }
        sfl_pcb->snd_lbb += TCP_TCPLEN(nseg);
        meta_pcb->unsent = meta_pcb->unsent->next;
        seg->next = NULL;
        /* Add old segment to the unacked queue of meta_pcb */
        if(meta_pcb->unacked == NULL)
            meta_pcb->unacked = seg;
        else{
            tmp = meta_pcb->unacked;
            while(tmp->next)
                tmp = tmp->next;
            tmp->next = seg;
        }
        if(meta_pcb->unsent == NULL)
            meta_pcb->unsent_oversize = 0;
        /* Update dsn */
        old_value = meta_pcb->snd_nxt;
        meta_pcb->snd_nxt += seg->len;
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: update snd_nxt, old_value="
            "%08x, new_value=%08x", __FUNCTION__, __LINE__, old_value,
             meta_pcb->snd_nxt));
        /* Check wrapped around and update snd_high_order */
        if(before(meta_pcb->snd_nxt, old_value)){
            mpcb->snd_high_order++;
            LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: snd_nxt wrapped, "
                "new snd_high_order=%08x", __FUNCTION__, __LINE__,
                mpcb->snd_high_order));
        }
    }
    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
    return ERR_OK;
}

void mptcp_update_master_pcb(struct tcp_pcb *meta_pcb){
    u32_t saved_snd_nxt, saved_rcv_nxt;
    size_t copy_len;
    struct tcp_pcb *master_pcb = NULL;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, meta_pcb=%p", __FUNCTION__,
        __LINE__, meta_pcb));
    /* At this point of time, it's expected that only master_pcb exists
     * in the connection list */
    if(meta_pcb->mp_conn_cb)
        master_pcb = meta_pcb->mp_conn_cb->connection_list;
    if(master_pcb == NULL || !master_pcb->is_master_pcb)
        return;

    saved_snd_nxt = master_pcb->snd_nxt;
    saved_rcv_nxt = master_pcb->rcv_nxt;

    copy_len = (size_t)((unsigned char *)&meta_pcb->mptcp_cls_chk_tmr - (unsigned char *)meta_pcb);
    MEMCPY(master_pcb, meta_pcb, copy_len);
    meta_pcb->snd_nxt = saved_snd_nxt;
    meta_pcb->rcv_nxt = saved_rcv_nxt;
    meta_pcb->snd_lbb = saved_snd_nxt - 1;
    meta_pcb->lastack = saved_snd_nxt - 1;
    meta_pcb->rcv_ann_right_edge = saved_rcv_nxt;
    meta_pcb->output_via_master = 1;

    LWIP_DEBUGF(MPTCP_TXRX_DEBUG,("%s:%d snd_nxt:%08x lastack:%08x",__func__,__LINE__,meta_pcb->snd_nxt,meta_pcb->lastack));
    master_pcb->poll = NULL;
    master_pcb->errf = NULL;
    master_pcb->recv = NULL;
    tcp_reg_active_mptcp(master_pcb);
    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave", __FUNCTION__, __LINE__));
}
#if MPCB_CHECK
void mptcp_check_mp_cb(struct tcp_pcb* pcb){
    if(pcb->mp_conn_cb && ((unsigned long)(pcb->mp_conn_cb->connection_list) & 0xffff000000000000UL)){
        LWIP_DEBUGF(MPTCP_FIN_DEBUG,("pcb:%p pcb->meta_pcb:%p pcb->mp_conn_cb->connection_list:%p",pcb,pcb->meta_pcb,pcb->mp_conn_cb->connection_list));
        abort();
    }
}
#endif
#endif
