#ifndef LWIP_MPTCP_STATE_H
#define LWIP_MPTCP_STATE_H

#include <string.h>

#include "lwip/arch.h"
#include "lwip/priv/tcp_priv.h"

#if LWIP_MPTCP_SUPPORT

#if LINUX_PLATFORM
#define typeof __typeof__
#endif
#define ALIGN(x, a)     __ALIGN_LWIP_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_LWIP_MASK(x, mask)    (((x) + (mask)) & ~(mask))

#define ffs(x) ({\
        unsigned long i = 0;\
        if(x == 0)\
            i = 32;\
        else {\
            while((x & (1<<i)) == 0)\
            {\
                i ++;\
            }\
            i++;\
            }\
        i;})

/* Iterates over all bit set to 1 in a bitset */
#define mptcp_for_each_bit_set(b, i) \
    for (i = ffs(b) - 1; i >= 0; i = ffs(b >> (i + 1) << (i + 1)) - 1)

#define mptcp_for_each_bit_unset(b, i) \
    mptcp_for_each_bit_set(b,i)(~b, i)



void initMptcpState(struct tcp_pcb* pcb);

void transferToState(struct tcp_pcb* pcb, int state);

int getCurrentState(struct tcp_pcb* pcb);

u16_t get_mptcp_opt_flag(struct tcp_pcb* pcb);

void mptcpStateProcess(struct tcp_pcb* pcb, u32_t* opts);
void mptcpStateProcessWithSeg(struct tcp_pcb* pcb, u32_t* opts, struct tcp_seg *seg);

void mptcp_parse_options(struct tcp_pcb *pcb, u8_t opsize, u8_t *ptr);

//static int mptcp_write_dss_data_ack(const struct tcp_pcb *tp, const struct sk_buff *skb,  __be32 *ptr);

//static int mptcp_write_dss_data_seq(const struct tcp_pcb *tp, struct sk_buff *skb,  __be32 *ptr);

static inline int is_valid_addropt_opsize(u8_t mptcp_ver, struct mp_add_addr *mpadd, int opsize);

static inline int mptcp_sub_len_remove_addr(u16_t bitfield);

//static inline int mptcp_sub_len_dss(const struct mp_dss *m, const int csum);

//static int mptcp_write_dss_data_seq(const struct tcp_sock *tp, struct sk_buff *skb, __be32 *ptr);

//static void mptcp_save_dss_data_seq(const struct tcp_sock *tp, struct sk_buff *skb);

//static int mptcp_write_dss_data_ack(const struct tcp_sock *tp, const struct sk_buff *skb, __be32 *ptr);

//static int mptcp_write_dss_mapping(const struct tcp_sock *tp, const struct sk_buff *skb, __be32 *ptr);

int mptcp_sub_len_remove_addr_align(u16_t bitfield);

void mptcp_invalidate_recv_info(void *instance);
p_mptcp_recv_info mptcp_get_recv_info(void *instance, mptcp_recv_info *pTcpRecvInfo);
void mptcp_recv_info_init(void **pRecv_info);

#endif
#endif
