//
// Created by user on 17-4-20.
//

#ifndef MYAPPLICATION_MPTCP_TCP_H
#define MYAPPLICATION_MPTCP_TCP_H

#ifdef __cplusplus
extern "C" {
#endif
#if MPTCP_TXRX_DUMP_DATA
#include <stdio.h>
#define TXRX_DATA_DUMP_DIR "/data/mptcp"
#endif
#include "lwip/lwipopts.h"
#include "lwip/arch.h"
#include "lwip/sys.h"
#if !LINUX_PLATFORM
#include <sys/endian.h>
#else
#include <linux/types.h>
#endif
#ifndef _ARPA_INET_H
#include <lwip/inet.h>
#endif

#define MPTCP_MAX_ADDR 8
#define MPTCP_RSTLINK 1 /*reset tcp link*/
#define MPTCP_DROP 2   /*drop tcp packet*/
#define MPTCP_FALLBACK 3 /* fallback mp to regular tcp*/
#define MPTCP_OK 1

typedef struct{
    volatile int counter;
}atomic_t;

struct mptcp_option {
    u8_t kind;
    u8_t len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    u8_t ver:4,
         sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    u8_t sub:4,
         ver:4;
#endif
};

struct mp_capable {
	u8_t	kind;
	u8_t	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8_t	ver:4,
		sub:4;
	u8_t	h:1,
		rsv:5,
		b:1,
		a:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8_t	sub:4,
		ver:4;
	u8_t	a:1,
		b:1,
		rsv:5,
		h:1;
#endif
	u64_t	sender_key;
	u64_t	receiver_key;
} __attribute__((__packed__));

struct mp_join {
	u8_t	kind;
	u8_t	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8_t	b:1,
		rsv:3,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8_t	sub:4,
		rsv:3,
		b:1;
#endif
	u8_t	addr_id;
	union {
		struct {
			u32_t	token;
			u32_t	nonce;
		} syn;
		struct {
			u64_t	mac;
			u32_t	nonce;
		} synack;
		struct {
			u8_t	mac[20];
		} ack;
	} u;
} __attribute__((__packed__));

struct mp_dss {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		A:1,
		a:1,
		M:1,
		m:1,
		F:1,
		rsv2:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:3,
		F:1,
		m:1,
		M:1,
		a:1,
		A:1;
#endif
};

struct mp_add_addr {
	u8_t kind;
	u8_t len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8_t ipver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8_t sub:4,
		ipver:4;
#endif
	u8_t addr_id;
		struct {
			struct in_addr  addr;
			u16_t  port;
            u64_t  mac;
		} addr;
} __attribute__((__packed__));

struct mp_remove_addr {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	rsv:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:4;
#endif
	/* list of addr_id */
	__u8	addrs_id;
};

struct mp_server_addr {
		__u8	kind;
		__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
		__u8	ipver:4,
			sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__u8	sub:4,
			ipver:4;
#endif
#ifdef SACK_FOR_MPTCP_SUPPORT
        __u8	addr[4];
        __u8	port[2];
#else
		__u8	addr_id;
		struct {
			struct in_addr  addr;
			__be16  port;
			__be16 aligned;
		} v4;
#endif
};

struct mp_fail {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		rsv2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:8;
#endif
	__be64	data_seq;
} __attribute__((__packed__));

struct mp_fclose {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		rsv2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:8;
#endif
	__u64	key;
} __attribute__((__packed__));

struct mp_prio {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	b:1,
		rsv:3,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:3,
		b:1;
#endif
	__u8	addr_id;
} __attribute__((__packed__));

static inline int mptcp_sub_len_dss(const struct mp_dss *m, const int csum)
{
    return 4 + m->A * (4 + m->a * 4) + m->M * (10 + m->m * 4 + csum * 2);
}


struct mptcp_subflow_pcb
{
    struct tcp_pcb *meta_pcb;
    struct tcp_pcb *next;    /* Next subflow pcb */

    /* Those three fields record the current mapping */
    u64_t map_data_seq;
    u32_t map_subseq;
    u16_t map_data_len;
    u16_t map_csum;
    u16_t mapping_present:1,
          map_data_fin:1,
          low_prio:1,
          rcv_low_prio:1,
          pre_established:1;

    u32_t snt_isn;
    u32_t rcv_isn;
    u8_t loc_id;
    u8_t rem_id;
    u32_t unnoti_recv_len;
    u32_t csum_acc;

    // struct tcp_seg *ssn_queue;
    u32_t loc_nonce;
    u32_t rem_nonce;

    /* MP_JOIN subflow: timer for retransmitting the 3rd ack */
    //struct timer_list mptcp_ack_timer;

    /* HMAC of the third ack */
    char sender_mac[20];

    struct pbuf *data_buf; /* data buffered for checking by checksum */
};

#if MPTCP_BUF_RECV_OFO_DATA
typedef struct ofo_data_entry_t{
    struct ofo_data_entry_t *next;
    struct pbuf *p;
    u32_t seq;
    u16_t data_len;
    u8_t wrapped;
}ofo_data_entry;
#endif

struct mptcp_cb{
    /*list of sockets in this mutipath connection*/
    // Looks no need.
    struct tcp_pcb *connection_list;

    /* High-order bits of 64-bit sequence numbers */
    u32_t snd_high_order;
    u32_t rcv_high_order;
    u16_t   dss_csum:1,
            lcl_fin_sent:1,
            lcl_fin_acked:1,
            rmt_fin_recved:1,
            rmt_fin_acked:1;
    /* socket count in this connection */
    u8_t cnt_subflows;
    u8_t cnt_established;

    u32_t lcl_fin_seqno;
    u32_t rmt_fin_seqno;

    u64_t loc_key;
    u64_t rem_key;
    u32_t loc_token;
    u32_t rem_token;

#if MPTCP_BUF_RECV_OFO_DATA
    ofo_data_entry *recv_ofo_queue;
#endif

#if MPTCP_TXRX_DUMP_DATA
    FILE *rx_data_file;
#endif

    u32_t path_index_bits;
    /* Next pi to pick up in case a new path becomes available */
    u8_t next_path_index;

    /* Mutex needed, because otherwise mptcp_close will complain that the
     * socket is owned by the user.
     * E.g., mptcp_sub_close_wq is taking the meta-lock.
     */
    u8_t mptcp_flags;
    u8_t loc_id;
	u16_t min_rtt;
#if WIFI_SWITCH_FEATURE
    u8_t   is_set_add_addr;
    struct mp_add_addr sfl_add_addr;
#endif
    void *instance;
};

#define mptcp_for_each_pcb(mpcb, pcb)                           \
    for((pcb) = (struct tcp_pcb *)(mpcb)->connection_list;      \
        (pcb);                                                    \
        (pcb) = (pcb->mp_sfl_pcb != NULL ?(struct tcp_pcb *)(pcb)->mp_sfl_pcb->next:NULL))

#ifdef __cplusplus
}
#endif

#endif //MYAPPLICATION_MPTCP_TCP_H
