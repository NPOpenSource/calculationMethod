//
// Created by user on 17-4-25.
//

#ifndef MYAPPLICATION_MPTCP_SESSION_H
#define MYAPPLICATION_MPTCP_SESSION_H

#include <lwip/dns.h>
#include "lwip/tcp.h"


#if LWIP_MPTCP_SUPPORT

int mptcp_create_master_pcb(struct tcp_pcb *sub_pcb, u64_t remote_key);
struct tcp_pcb* mptcp_create_subflow_pcb(struct tcp_pcb *meta_pcb, struct mp_add_addr *mpadd);
int mptcp_add_pcb(struct tcp_pcb *meta_pcb, struct tcp_pcb *pcb, u8_t loc_id, u8_t rem_id);

#endif
#endif //MYAPPLICATION_MPTCP_SESSION_H
