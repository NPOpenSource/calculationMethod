/*Created by wyjap on 2017/10/28.*/


#ifndef MYAPPLICATION_TCP_COMMON_CONTEXT_H
#define MYAPPLICATION_TCP_COMMON_CONTEXT_H

struct tcp_context {
        /*tcp*/
        struct tcp_pcb *tcp_bound_pcbs;
        /*union tcp_listen_pcbs_t tcp_listen_pcbs;*/
        union {
            struct tcp_pcb_listen *listen_pcbs;
            struct tcp_pcb *pcbs;
        }tcp_listen_pcbs;
        struct tcp_pcb *tcp_active_pcbs;
        struct tcp_pcb *tcp_tw_pcbs;
        struct tcp_pcb **tcp_pcb_lists[4];
#if TCP_FIND
        struct tcp_pcb **mptcp_list;
#endif
        u8_t tcp_active_pcbs_changed;
        u8_t tcp_timer;
        u8_t tcp_timer_ctr;
        u8_t reserved;
        u16_t tcp_port;
        u32_t tcp_ticks;
        int tcpip_tcp_timer_active;
        int seed_id;
    
        /*tcpip*/
        tcpip_init_done_fn tcpip_init_done;
        void *tcpip_init_done_arg;
        sys_mbox_t mbox;
#if LWIP_TCPIP_CORE_LOCKING
        sys_mutex_t lock_tcpip_core;
#endif
    
        /*tcp_in*/
        void *inseg;
        struct tcp_hdr *tcphdr;
        u16_t tcphdr_optlen;
        u16_t tcphdr_opt1len;
        u8_t* tcphdr_opt2;
        u32_t seqno;
        u32_t ackno;
        tcpwnd_size_t recv_acked;
        u16_t tcp_optidx;
        u16_t tcplen;
        struct pbuf *recv_data;
        struct sack_option *sackOption;
        u8_t flags;
        u8_t recv_flags;
        
#if LWIP_MPTCP_SUPPORT
        u16_t tcp_data_csum;
        struct tcp_seg *mptcp_recv_data;
#endif
    
        struct tcp_pcb *tcp_input_pcb;
        struct tcp_pcb *last_input_pcb;

        unsigned int exitFlag;

        u8_t opt[TCP_MSS];
};

#endif //MYAPPLICATION_TCP_COMMON_CONTEXT_H
