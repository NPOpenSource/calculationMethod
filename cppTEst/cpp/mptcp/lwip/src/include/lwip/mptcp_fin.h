#ifndef LWIP_MPTCP_FIN_H
#define LWIP_MPTCP_FIN_H

#include "lwip/tcp.h"

#define CLOSE_TYPE_NORMAL 0
#define CLOSE_TYPE_FASTCLOSE 1
#define CLOSE_TYPE_RESET 2

err_t mptcp_fin_perform_close(struct tcp_pcb *meta_pcb, u8_t cls_type,
        u8_t *tcp_closed_on_master_pcb);
void mptcp_fin_check_and_perform_close(struct tcp_pcb *pcb);
void mptcp_fin_add_close_candidate(struct tcp_pcb *meta_pcb);
void mptcp_fin_rm_close_candidate(struct tcp_pcb *meta_pcb);
void mptcp_fin_close_candidate_check(void *instance);
void mptcp_fin_trigger_close(struct tcp_pcb *meta_pcb, struct tcp_pcb *sfl_pcb,
        u8_t *tcp_close_needed);
err_t mptcp_fin_sfl_recved_fin(struct tcp_pcb *sfl_pcb);
err_t mptcp_fin_sfl_recved_rst(struct tcp_pcb *sfl_pcb);
void mptcp_fin_handle_fastclose(struct tcp_pcb *sfl_pcb, u64_t sender_key);
err_t mptcp_fin_remove_sfl(struct tcp_pcb *pcb, u8_t cls_type);
#endif //end of LWIP_MPTCP_FIN_H

