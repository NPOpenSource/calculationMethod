/*===========================================================================

                         mptcp.h

DESCRIPTION

 MPTCP implementation


Copyright (c) 2017.04 - 2017.05  Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/

#ifndef MYAPPLICATION_MPTCP_H
#define MYAPPLICATION_MPTCP_H

#include "lwip/arch.h"
#include "lwip/mptcp/cryptohash.h"
#include "lwip/tcp.h"
#include "lwip/module.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_MPTCP_SUPPORT

struct tcp_pcb;
/*
extern u32_t mptcp_secret[MD5_MESSAGE_BYTES / 4];
extern u32_t mptcp_seed;
*/
#define MPTCP_TMR_INTERVAL        500

/* MPTCP flags: both TX and RX */
#define MPTCPHDR_SEQ		0x01 /* DSS.M option is present */
#define MPTCPHDR_FIN		0x02 /* DSS.F option is present */
#define MPTCPHDR_SEQ64_INDEX	0x04 /* index of seq in mpcb->snd_high_order */
/* MPTCP flags: RX only */
#define MPTCPHDR_ACK		0x08
#define MPTCPHDR_SEQ64_SET	0x10 /* Did we received a 64-bit seq number?  */
#define MPTCPHDR_SEQ64_OFO	0x20 /* Is it not in our circular array? */
#define MPTCPHDR_DSS_CSUM	0x40
#define MPTCPHDR_JOIN		0x80
/* MPTCP flags: TX only */
#define MPTCPHDR_INF		0x08
#define MPTCP_REINJECT		0x10 /* Did we reinject this segment? */
#define CLS_CAND_LIST_SIZE  8

/**
 * Define the state for mptcp which is dependent to the state of tcp.
 */
enum {
    MPTCP_MP_IDLE, /*The first state when mptcp is supported*/
    MPTCP_MP_CAPABLE_SYN_SEND, /*The state for send the SYN flag with MP_CAPABLE*/
    MPTCP_MP_CAPABLE_SYN_ACK_RCV, /*The state for receive the SYNACK flag with MP_CAPABLE*/
    MPTCP_MP_CAPABLE_ACK_SEND, /*The state for send the ACK flag with MP_CAPABLE*/
    MPTCP_MP_ESTABLISHED, /*The state for a master flow and a subflow have been established succesfully */
    MPTCP_MP_JOIN_SYN_SEND, /*The state for send the SYN flag with MP_JOIN*/
    MPTCP_MP_JOIN_ACK_SEND, /*The state for send the ACK flag with MP_JOIN*/
    MPTCP_MP_ADD_ADDR_RCV, /*The state for receive MP_ADD_ADDR.(consider if this state is needed)*/
    MPTCP_MP_ADD_ADDR_SND, /* The state for send MP_ADD_ADDR */
    MPTCP_MP_REMOVE_ADDR_RCV, /*The state for receive MP_REMOVE_ADDR.(consider if this state is needed)*/
    MPTCP_MP_REMOVE_ADDR_SND, /*The state for send MP_REMOVE_ADDR.*/
    MPTCP_MP_FASTCLOSE_SENT, /*The state for send MP_FCLOSE.*/
    MPTCP_MP_FAIL_RCV,
    MPTCP_MP_CLOSED
};

/* Request-sockets can be hashed in the tk_htb for collision-detection or in
 * the regular htb for join-connections. We need to define different NULLS
 * values so that we can correctly detect a request-socket that has been
 * recycled. See also c25eb3bfb9729.
 */
#define MPTCP_REQSK_NULLS_BASE (1U << 29)

static inline int is_meta_pcb(const struct tcp_pcb *pcb)
{
    return pcb->is_meta_pcb;
}

static inline int is_sfl_pcb(const struct tcp_pcb *pcb){
    return pcb->is_subflow_pcb || pcb->is_master_pcb;
}

static inline int is_mptcp_pcb(const struct tcp_pcb *pcb)
{
    return pcb->mptcp_enabled && pcb->mptcp_state > MPTCP_MP_CAPABLE_SYN_SEND;
}

/**
 * this function used to judge the pcb have sent fin or recv_fin
 * */
static inline int get_fin_occure(const struct tcp_pcb *pcb){
    if(is_meta_pcb(pcb) || is_sfl_pcb(pcb)){
        struct mptcp_cb * mpcb = pcb->mp_conn_cb;
        if(mpcb->lcl_fin_sent || mpcb->rmt_fin_recved){
            return 1;
        }
        return 0;
    }
    return 0;
}

static inline u64_t my_ntohll(u64_t num){
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
    return num;
#else
    u64_t nnum;
    u8_t *p1 = (u8_t *)&nnum, *p2 = (u8_t *)&num, i;

    /*for(i = 0; i < 8; i++)
        p1[i] = p2[7 - i];*/
    p1[0] = p2[7];
	p1[1] = p2[6];
	p1[2] = p2[5];
	p1[3] = p2[4];
	p1[4] = p2[3];
	p1[5] = p2[2];
	p1[6] = p2[1];
	p1[7] = p2[0];
        
    return nnum;
#endif
}
#define my_htonll(x) my_ntohll(x)

void mptcp_init(struct module_conext *pMptcpModuleContext);
err_t lwip_mptcp_connected(void *arg, struct tcp_pcb *pcb, err_t err);
void start_new_subflow(struct tcp_pcb *meta_pcb, struct mp_add_addr *mpadd);
void mptcp_key_sha1(u64_t key, u32_t *token, u64_t *idsn);
void mptcp_hmac_sha1(u8_t *key_1, u8_t *key_2, u32_t *hash_out, int arg_num, ...);
void mptcp_connect_init(struct tcp_pcb *pcb);
struct tcp_pcb * mptcp_get_available_subflow(struct tcp_pcb *meta_pcb, int send_len);
void mptcp_get_seed(void *instance, u32_t **pMptcp_seed);
void mptcp_get_port(void *instance, u16_t **pPort);
u8_t *mptcp_get_secret(void *instance);
void *mptcp_get_recv_info_ptr(void *instance);
void mptcp_deinit(struct module_conext *pMptcpModuleContext);
void mptcp_get_cls_cand(void *instance, u16_t **pCnt_cls_cand);
void mptcp_update_cls_cand_list_elem(void *instance, u16_t index, struct tcp_pcb *new_pcb);
struct tcp_pcb *mptcp_get_cls_cand_list_elem(void *instance, u16_t index);
void mptcp_set_rto(struct tcp_pcb *meta_pcb);


#define MPTCP_VERSION_0 0
#define MPTCP_VERSION_1 1

#define MPTCP_DSS_CSUM_WANTED 1

#define MPTCP_SUB_CAPABLE    0
#define MPTCP_SUB_LEN_CAPABLE_SYN    12
#define MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN    12
#define MPTCP_SUB_LEN_CAPABLE_SYN_ACK 12
#define MPTCP_SUB_LEN_CAPABLE_SYN_ACK_ALIGN 12
#define MPTCP_SUB_LEN_CAPABLE_ACK    20
#define MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN    20

#define MPTCP_SUB_JOIN    1
#define MPTCP_SUB_LEN_JOIN_SYN    12
#define MPTCP_SUB_LEN_JOIN_SYN_ALIGN    12
#define MPTCP_SUB_LEN_JOIN_SYN_ACK    16
#define MPTCP_SUB_LEN_JOIN_SYN_ACK_ALIGN    16
#define MPTCP_SUB_LEN_JOIN_ACK    24
#define MPTCP_SUB_LEN_JOIN_ACK_ALIGN    24

#define MPTCP_SUB_DSS    2
#define MPTCP_SUB_LEN_DSS    4
#define MPTCP_SUB_LEN_DSS_ALIGN    4
#define MPTCP_SUB_LEN_ACK_DSS    8

/* Lengths for seq and ack are the ones without the generic MPTCP-option header,
 * as they are part of the DSS-option.
 * To get the total length, just add the different options together.
 */
#define MPTCP_SUB_LEN_SEQ    10
#define MPTCP_SUB_LEN_SEQ_CSUM   12
#define MPTCP_SUB_LEN_SEQ_ALIGN   12

#define MPTCP_SUB_LEN_SEQ_64    14
#define MPTCP_SUB_LEN_SEQ_CSUM_64    16
#define MPTCP_SUB_LEN_SEQ_64_ALIGN    16

#define MPTCP_SUB_LEN_ACK    4
#define MPTCP_SUB_LEN_ACK_ALIGN    4

#define MPTCP_SUB_LEN_ACK_64    8
#define MPTCP_SUB_LEN_ACK_64_ALIGN    8

/* Generally, the length of sender option is following  */
#define MPTCP_SUB_LEN_DSM_ALIGN  (MPTCP_SUB_LEN_DSS_ALIGN + \
        MPTCP_SUB_LEN_SEQ_ALIGN + \
        MPTCP_SUB_LEN_ACK_ALIGN)

#define MPTCP_SUB_ADD_ADDR    3
#define MPTCP_SUB_LEN_ADD_ADDR4    8
#define MPTCP_SUB_LEN_ADD_ADDR4_VER1    16
#define MPTCP_SUB_LEN_ADD_ADDR6    20
#define MPTCP_SUB_LEN_ADD_ADDR6_VER1    28
#define MPTCP_SUB_LEN_ADD_ADDR4_ALIGN    8
#define MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1    16
#define MPTCP_SUB_LEN_ADD_ADDR6_ALIGN    20
#define MPTCP_SUB_LEN_ADD_ADDR6_ALIGN_VER1    28

#define MPTCP_SUB_REMOVE_ADDR    4
#define MPTCP_SUB_LEN_REMOVE_ADDR    4

#define MPTCP_SUB_PRIO    5
#define MPTCP_SUB_LEN_PRIO    3
#define MPTCP_SUB_LEN_PRIO_ADDR    4
#define MPTCP_SUB_LEN_PRIO_ALIGN    4

#define MPTCP_SUB_FAIL    6
#define MPTCP_SUB_LEN_FAIL    12
#define MPTCP_SUB_LEN_FAIL_ALIGN    12

#define MPTCP_SUB_FCLOSE    7
#define MPTCP_SUB_LEN_FCLOSE    12
#define MPTCP_SUB_LEN_FCLOSE_ALIGN    12

#define MPTCP_SUB_SER_ADDR    8
#ifdef SACK_FOR_MPTCP_SUPPORT
#define MPTCP_SUB_LEN_SER_ADDR4    8 /* Actually need 9 octets. 1 octet resides in WindowScale option */
#define MPTCP_SUB_LEN_SER_ADDR4_ALIGN   8
#else
#define MPTCP_SUB_LEN_SER_ADDR4    12
#define MPTCP_SUB_LEN_SER_ADDR4_ALIGN   12
#endif
#define MPTCP_SUB_LEN_SER_ADDR4_VER1    16
#define MPTCP_SUB_LEN_SER_ADDR4_ALIGN_VER1    16

//This should be start from number 5(1 << 5), because the first 4 bit has been used.
#define OPTION_MP_CAPABLE        (1 << 5)
#define OPTION_ADD_ADDR          (1 << 6)
#define OPTION_MP_JOIN           (1 << 7)
#define OPTION_MP_FAIL           (1 << 8)
#define OPTION_MP_FCLOSE         (1 << 9)
#define OPTION_REMOVE_ADDR       (1 << 10)
#define OPTION_MP_PRIO           (1 << 11)
#define OPTION_TYPE_SYN          (1 << 12)
#define OPTION_TYPE_ACK          (1 << 13)
#endif
#ifdef __cplusplus
}
#endif
#endif

