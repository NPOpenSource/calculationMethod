
#ifndef MYAPPLICATION_MPTCP_INPUT_OUTPUT_H
#define MYAPPLICATION_MPTCP_INPUT_OUTPUT_H

#if LWIP_MPTCP_SUPPORT

void mptcp_check_incoming_ack(struct tcp_pcb *sfl_pcb, u32_t data_ack);
u16_t mptcp_calculate_outgoing_csum(struct tcp_pcb *pcb, struct tcp_seg *seg,
        u32_t meta_seq, u32_t sub_data_seq, u16_t data_len);
u16_t mptcp_calculate_fin_csum(struct tcp_pcb *pcb, u32_t meta_seq,
        u8_t snd_or_rcv);
err_t mptcp_input(struct tcp_pcb *sfl_pcb, struct pbuf *recv_data,
        p_mptcp_recv_info recv_info);
err_t mptcp_output(struct tcp_pcb *meta_pcb);
void mptcp_update_master_pcb(struct tcp_pcb *meta_pcb);
static inline u16_t mptcp_count_dss_opt_len(u8_t m, u8_t a, u8_t c){
    u16_t len = 0;

    len += ((m || a) ? 4 : 0);
    len += (a ? 4 : 0);
    len += (m ? 10 : 0);
    if(m && c)
        len += 2;
    return len;
}
#if MPCB_CHECK
void mptcp_check_mp_cb(struct tcp_pcb* pcb);
#endif
#endif
#endif
