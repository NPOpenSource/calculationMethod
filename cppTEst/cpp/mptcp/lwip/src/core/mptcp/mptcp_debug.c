/*===========================================================================

                         mptcp_debug.c

DESCRIPTION

MPTCP debug file use to show all the bit feild in tcp option

Copyright (c) 2017.04 - 2017.05 Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/

#include "lwip/mptcp/mptcp_debug.h"
#include"lwip/mptcp/mptcp_state.h" /*Include  mptcp_tcp.h*/

#if LWIP_MPTCP_SUPPORT

/**
 * List current state in string.
 *
 * @Parameter state - int
 */
void list_state(int state) {
    switch(state) {
        case MPTCP_MP_CAPABLE_SYN_SEND:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_CAPABLE_SYN_SEND"));
            break;
        case MPTCP_MP_CAPABLE_SYN_ACK_RCV:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_CAPABLE_SYN_ACK_RCV"));
            break;
        case MPTCP_MP_CAPABLE_ACK_SEND:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_CAPABLE_ACK_SEND"));
            break;
        case MPTCP_MP_JOIN_SYN_SEND:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_JOIN_SYN_SEND"));
            break;
        case MPTCP_MP_JOIN_ACK_SEND:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_JOIN_ACK_SEND"));
            break;
        case MPTCP_MP_ESTABLISHED:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_ESTABLISHED"));
            break;
        case MPTCP_MP_ADD_ADDR_RCV:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_ADD_ADDR_RCV"));
            break;
        case MPTCP_MP_REMOVE_ADDR_RCV:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_REMOVE_ADDR_RCV"));
            break;
        case MPTCP_MP_ADD_ADDR_SND:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_ADD_ADDR_SEND"));
            break;
        case MPTCP_MP_REMOVE_ADDR_SND:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_REMOVE_ADDR_SEND"));
            break;
        case MPTCP_MP_FASTCLOSE_SENT:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_FASTCLOSE_SENT"));
            break;
        case MPTCP_MP_FAIL_RCV:
            LWIP_DEBUGF(API_MSG_DEBUG, ("current state :MPTCP_MP_FAIL_RCV"));
            break;
        default:
            LWIP_DEBUGF(API_MSG_DEBUG, ("unknown state"));
            break;
    }
}

/**
 * List mptcp option 'kind' in string.
 *
 * @Parameter kind - int
 */
void list_kind(int kind) {
    switch (kind) {
        case MPTCP_SUB_CAPABLE:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_CAPABLE"));
            break;
        case MPTCP_SUB_JOIN:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_JOIN"));
            break;
        case MPTCP_SUB_DSS:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_DSS"));
            break;
        case MPTCP_SUB_ADD_ADDR:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_ADD_ADDR"));
            break;
        case MPTCP_SUB_REMOVE_ADDR:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_REMOVE_ADDR"));
            break;
        case MPTCP_SUB_PRIO:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_PRIO"));
            break;
        case MPTCP_SUB_FAIL:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_FAIL"));
            break;
        case MPTCP_SUB_FCLOSE:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :MPTCP_SUB_FCLOSE"));
            break;
        default:
            LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt kind: :unknown"));
            break;
    }
}

/**
 * List all the details of options for mp_capable.
 *
 *@Parameter mp - struct mp_capable
 */
void list_mp_capable(const struct mp_capable* mp) {
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt len: %d", mp->len));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt ver: %d", mp->ver));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt a: %d", mp->a));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt b: %d", mp->b));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt rsv: %d", mp->rsv));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt sender key: %d", mp->sender_key));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt receiver key: %d", mp->receiver_key));
}

/**
 * List all the details of options for mp_join.
 *
 *@Parameter mp - struct mp_join
 */
void list_mp_join(const struct mp_join* mp) {
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt len: %d", mp->len));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt addr_id: %d", mp->addr_id));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt b: %d", mp->b));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt rsv: %d", mp->rsv));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt mac: %d", mp->u.synack.mac));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt nonce: %d", mp->u.synack.nonce));
}

/**
 * List all the details of options for mp_dss.
 *
 *@Parameter mp - struct mp_dss
 */
void list_mp_dss(const struct mp_dss* mp) {
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt len: %d", mp->len));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt a: %d", mp->a));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt A: %d", mp->A));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt m: %d", mp->m));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt M: %d", mp->M));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt F: %d", mp->F));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt rsv1: %d", mp->rsv1));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt rsv2: %d", mp->rsv2));
}

/**
 * List all the details of options for mp_add_addr.
 *
 *@Parameter mp - struct mp_add_addr
 */
void list_mp_add(const struct mp_add_addr* mp) {
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt len: %d", mp->len));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt ipver: %d", mp->ipver));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt sub: %d", mp->sub));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt addr_id: %d", mp->addr_id));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt addr: %d", mp->addr.addr));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt port: %d", mp->addr.port));
}

/**
 * List all the details of options for mp_remove_addr.
 *
 *@Parameter mp - struct mp_remove_addr
 */
void list_mp_remove(const struct mp_remove_addr* mp) {
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt len: %d", mp->len));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt rsv: %d", mp->rsv));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt sub: %d", mp->sub));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt addr_id: %d", mp->addrs_id));
}

/**
 * List all the details of options for mp_fclose.
 *
 *@Parameter mp - struct mp_fclose
 */
void list_mp_fclose(const struct mp_fclose* mp) {
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("receive opt len: %d", mp->len));
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("receive opt rsv1: %d", mp->rsv1));
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("receive opt sub: %d", mp->sub));
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("receive opt rsv2: %d", mp->rsv2));
    LWIP_DEBUGF(MPTCP_FIN_DEBUG, ("receive opt key: %d", mp->key));
}

#ifndef SACK_FOR_MPTCP_SUPPORT
/**
 * List all the details of options for mp_server_addr.
 *
 *@Parameter mp - struct mp_server_addr
 */
void list_mp_server_addr(const struct mp_server_addr* mp) {
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt len: %d", mp->len));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt ipver: %d", mp->ipver));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt sub: %d", mp->sub));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt addr_id: %d", mp->addr_id));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt addr: %d", mp->v4.addr));
    LWIP_DEBUGF(API_MSG_DEBUG, ("receive opt port: %d", mp->v4.port));
}
#endif
#endif