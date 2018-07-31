/*
 *      MPTCP implementation - MPTCP-control
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <lwip/sys.h>
#include <lwip/mptcp/mptcp.h>
#include <lwip/mptcp/random.h>
#include <netif/ppp/polarssl/sha1.h>
#include <lwip/mptcp/mptcp_ipv4.h>
#include "lwip/mptcp/mptcp_session.h"
#include "lwip/mptcp/mptcp_state.h"
#include "lwip/mptcp/mptcp_debug.h"
#include "lwip/timeouts.h"
#include "../../../../../tools/irandom.h"

extern unsigned long read_random();

#if LWIP_MPTCP_SUPPORT

/* "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define MPTCP_LOCAL_PORT_RANGE_START        0xc000

static int max_mptcp_version = MPTCP_VERSION_1;

/* last local MPTCP port */
/*static u16_t mptcp_port = MPTCP_LOCAL_PORT_RANGE_START;*/

void mptcp_hmac_sha1(u8_t *key_1, u8_t *key_2, u32_t *hash_out, int arg_num, ...)
{
	u32_t workspace[SHA_WORKSPACE_WORDS];
	u8_t input[128]; /* 2 512-bit blocks */
	int i;
	int index;
	int length;
	u8_t *msg;
	va_list list;

	memset(workspace, 0, sizeof(workspace));

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	va_start(list, arg_num);
	index = 64;
	for (i = 0; i < arg_num; i++) {
		length = va_arg(list, int);
		msg = va_arg(list, u8_t*);
		//BUG_ON(index + length > 125); /* Message is too long */
		memcpy(&input[index], msg, length);
		index += length;
	}
	va_end(list);

	input[index] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[index + 1], 0, (126 - index));

	/* Padding: Length of the message = 512 + message length (bits) */
	input[126] = 0x02;
	input[127] = ((index - 64) * 8); /* Message length (bits) */

	sha_init(hash_out);
	sha_transform(hash_out, (const char *)input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, (const char *)&input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	for (i = 0; i < 5; i++)
	        hash_out[i] = lwip_htonl(hash_out[i]);

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_init(hash_out);
	sha_transform(hash_out, (const char *)input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, (const char *)&input[64], workspace);

        for (i = 0; i < 5; i++)
                hash_out[i] = lwip_htonl(hash_out[i]);
}

err_t lwip_mptcp_connected(void *arg, struct tcp_pcb *pcb, err_t err) {
    return ERR_OK;
}

/*
 * Start a new subflow when master connection is established.
 *
 * @parameter struct tcp_pcb - pcb
 */
void start_new_subflow(struct tcp_pcb *meta_pcb, struct mp_add_addr *mpadd) {
    struct tcp_pcb * subflow_pcb  = NULL;
    u16_t port = 0;

    if(meta_pcb == NULL)
    {
        return;
    }
	subflow_pcb  = mptcp_create_subflow_pcb(meta_pcb, mpadd);
    port = (mpadd->len == MPTCP_SUB_LEN_ADD_ADDR4 ? meta_pcb->remote_port : mpadd->addr.port);
    in_addr_t s_addr = mpadd->addr.addr.s_addr;
    tcp_connect(subflow_pcb, (const ip_addr_t *)&s_addr,
        port, lwip_mptcp_connected);
}

void mptcp_key_sha1(u64_t key, u32_t *token, u64_t *idsn)
{
    u32_t workspace[SHA_WORKSPACE_WORDS];
    u32_t mptcp_hashed_key[SHA_DIGEST_WORDS];
    u8_t input[64];
    int i;

    memset(workspace, 0, sizeof(workspace));

    /* Initialize input with appropriate padding */
    memset(&input[9], 0, sizeof(input) - 10); /* -10, because the last byte
						   * is explicitly set too
						   */
    memcpy(input, &key, sizeof(key)); /* Copy key to the msg beginning */
    input[8] = 0x80; /* Padding: First bit after message = 1 */
    input[63] = 0x40; /* Padding: Length of the message = 64 bits */

    sha_init(mptcp_hashed_key);
    sha_transform(mptcp_hashed_key, (const char *)input, workspace);

    for (i = 0; i < 5; i++)
        mptcp_hashed_key[i] = lwip_htonl(mptcp_hashed_key[i]);

    if (token)
        *token = mptcp_hashed_key[0];
    if (idsn)
        *idsn = *((u64_t *)&mptcp_hashed_key[3]);
}

/*
u32_t mptcp_secret[MD5_MESSAGE_BYTES / 4];
u32_t mptcp_seed = 0;
*/
struct mptcp_context {
	u32_t mptcp_secret[MD5_MESSAGE_BYTES / 4];
    u32_t mptcp_seed;
	void *recv_info;
	u16_t mptcp_port;
	u16_t cnt_cls_cand;
	struct tcp_pcb *cls_cand_list[CLS_CAND_LIST_SIZE];
};

void mptcp_init(struct module_conext *pMptcpModuleContext)
{
    int i;

    struct mptcp_context *pMptcpContext;

    pMptcpModuleContext->pCcontext = malloc(sizeof(struct mptcp_context));
    memset(pMptcpModuleContext->pCcontext, 0x0,sizeof(struct mptcp_context));
    pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

	pMptcpContext->mptcp_seed = 0;
	pMptcpContext->cnt_cls_cand = 0;

#ifdef LWIP_RAND
    pMptcpContext->mptcp_port = TCP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());
#endif /* LWIP_RAND */

    get_random_bytes(pMptcpContext->mptcp_secret, sizeof(pMptcpContext->mptcp_secret));

    pMptcpContext->mptcp_seed = (u32_t)read_random();

	mptcp_recv_info_init(&pMptcpContext->recv_info);
}

void mptcp_connect_init(struct tcp_pcb *pcb)
{
    struct mptcp_cb *mp_conn_pcb;
	u32_t *pMptcp_seed;

    mp_conn_pcb = (struct mptcp_cb *)memp_malloc(MEMP_MPTCP_MPCB);
    if (NULL == mp_conn_pcb)
        return;
    (void)memset(mp_conn_pcb, 0 ,sizeof(struct mptcp_cb));

    // Init the mptcp parameter used for write options.
    pcb->mptcp_enabled = 1;
    pcb->mptcp_ver = MPTCP_VERSION_0;

    /* Store the mptcp version agreed on initial handshake */
    mp_conn_pcb->cnt_subflows = 0;

    mp_conn_pcb->cnt_established = 0;
	mp_conn_pcb->instance = pcb->instance;
	mp_conn_pcb->min_rtt = 0xffff;

    mptcp_get_seed(pcb->instance,&pMptcp_seed);
    mp_conn_pcb->loc_key = mptcp_v4_get_key(pcb->local_ip.addr,
                                         pcb->remote_ip.addr,
                                         pcb->local_port,
                                         pcb->remote_port,
                                         *pMptcp_seed++,
                                         mptcp_get_secret(pcb->instance));
    mptcp_key_sha1(mp_conn_pcb->loc_key,
                   &mp_conn_pcb->loc_token, NULL);

    pcb->mp_conn_cb = mp_conn_pcb;
    LWIP_DEBUGF(MPTCP_DEBUG,
                ("connect meta_pcb=%p, mpcb=%p, lport=%d\n", pcb, mp_conn_pcb, pcb->local_port));
    initMptcpState(pcb);
}

struct tcp_pcb * mptcp_get_available_subflow(struct tcp_pcb *meta_pcb, int send_len){
    struct tcp_pcb *pcb, *best_pcb = NULL,*tmp = NULL;
    struct mptcp_cb *mpcb = meta_pcb->mp_conn_cb;
    u32_t wnd;
    u8_t first_round = 1, sendable;


#if UP_SEND_RTO
    u32_t rtt1 = 120,rtt2 =120;
#else
    u32_t rtt1 = 8,rtt2 =8;
#endif
    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, meta_pcb=%p, port=%d, "
        "send_len=%d, outout_via_master=%d", __FUNCTION__, __LINE__, meta_pcb,
        meta_pcb->local_port, send_len, meta_pcb->output_via_master));
    if(!mpcb)
        goto leave;
    meta_pcb->snd_cnt++;
again:
    mptcp_for_each_pcb(mpcb, pcb){
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: pcb=%p, mptcp_state=%d, "
            "is_master_pcb=%d, pre_established=%d, cnt_established=%d",
            __FUNCTION__, __LINE__, pcb, pcb->mptcp_state, pcb->is_master_pcb,
            MEMB_OF_SFL_PCB(pcb,pre_established), mpcb->cnt_established));
        if(pcb->mptcp_state != MPTCP_MP_ESTABLISHED ||
                MEMB_OF_SFL_PCB(pcb,pre_established) == 1)
            continue;
        if(MEMB_OF_SFL_PCB(pcb,low_prio) || MEMB_OF_SFL_PCB(pcb,rcv_low_prio))
            continue;
        /* sendable judgement logic should be the same as in tcp_output() */
        sendable = 0;
        wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);
        if(pcb->snd_lbb - pcb->lastack + send_len <= wnd)
            sendable = 1;
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: seq=%08x, lastack=%08x, "
            "wnd=%d, sendable=%d, snd_wnd=%d, cwnd=%d", __FUNCTION__, __LINE__,
            pcb->snd_lbb, pcb->lastack, wnd, sendable, pcb->snd_wnd,
            pcb->cwnd));
        if(pcb->is_master_pcb == meta_pcb->output_via_master){
            if(sendable){
                pcb->meta_send_pending = 0;
                best_pcb = pcb;

#if UP_SEND_RTO
                rtt1 = pcb->rto;
#else
                rtt1 = pcb->sa;
#endif

                if(meta_pcb->snd_cnt > 50){
                    meta_pcb->snd_cnt = 0;
#if 0
                    rtt2 = 0;
#else
                    if(rtt2 > rtt1)
                        rtt2 = 0;
                    else
                        rtt1 = 0;
#endif
                }
              if(rtt2 < rtt1){
                    best_pcb = tmp;
                }
                goto leave;
            }else if(first_round && mpcb->cnt_established > 1){
                first_round = 0;
                meta_pcb->output_via_master =
                    meta_pcb->output_via_master ? 0 : 1;
                LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: output_via_master "
                    "wrapped", __FUNCTION__, __LINE__));
                goto again;
            }
        }
        /* For some unexpected cases? */
        if(sendable){
            pcb->meta_send_pending = 0;
#if UP_SEND_RTO
            rtt2 = pcb->rto;
#else
            rtt2 = pcb->sa;
#endif
            best_pcb = pcb;
            tmp = pcb;
        }
    }
    if(best_pcb == NULL){
        mptcp_for_each_pcb(mpcb, pcb)
            pcb->meta_send_pending = 1;
    }
leave:
    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave, best_pcb=%p", __FUNCTION__,
        __LINE__, best_pcb));
    return best_pcb;
}

void mptcp_set_rto(struct tcp_pcb *meta_pcb){
    struct tcp_pcb *pcb, *best_pcb = NULL,*tmp = NULL;
    struct mptcp_cb *mpcb = meta_pcb->mp_conn_cb;
    u32_t wnd;
    u8_t first_round = 1, sendable;
    s16_t rto = 0;
#if 1
    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: enter, meta_pcb=%p, rto=%d, "
        "outout_via_master=%d", __FUNCTION__, __LINE__, meta_pcb,
        meta_pcb->rto,meta_pcb->output_via_master));
    if(!mpcb)
        return;

    mptcp_for_each_pcb(mpcb, pcb){
        LWIP_DEBUGF(MPTCP_TXRX_DTL_DEBUG, ("%s:%d: pcb=%p, mptcp_state=%d, "
            "is_master_pcb=%d, rto =%d",
            __FUNCTION__, __LINE__, pcb, pcb->mptcp_state, pcb->is_master_pcb,
            pcb->rto));
        if(pcb->mptcp_state != MPTCP_MP_ESTABLISHED ||
                MEMB_OF_SFL_PCB(pcb,pre_established) == 1)
            continue;

        if(MEMB_OF_SFL_PCB(pcb,low_prio) || MEMB_OF_SFL_PCB(pcb,rcv_low_prio))
            continue;

        /* sendable judgement logic should be the same as in tcp_output() */
        if(pcb->rto > rto)
        {
            rto = pcb->rto;
        }
    }

    meta_pcb->rto = rto *3;
    LWIP_DEBUGF(MPTCP_TXRX_DEBUG, ("%s:%d: leave, rto =%p", __FUNCTION__,
        __LINE__, meta_pcb->rto));
#endif
    return ;
}


void mptcp_get_seed(void *instance, u32_t **pMptcp_seed)
{
    struct lwip_instance *pLwipInstance =(struct lwip_instance *)instance;
	struct module_conext *pMptcpModuleContext = &pLwipInstance->module_conext[CONTEXT_MPTCP_TYPE];
    struct mptcp_context *pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

	*pMptcp_seed = &(pMptcpContext->mptcp_seed);
}

void mptcp_get_port(void *instance, u16_t **pPort)
{
    struct lwip_instance *pLwipInstance =(struct lwip_instance *)instance;
	struct module_conext *pMptcpModuleContext = &pLwipInstance->module_conext[CONTEXT_MPTCP_TYPE];
    struct mptcp_context *pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

	*pPort = &pMptcpContext->mptcp_port;
}

u8_t *mptcp_get_secret(void *instance)
{
    struct lwip_instance *pLwipInstance =(struct lwip_instance *)instance;
    struct module_conext *pMptcpModuleContext = &pLwipInstance->module_conext[CONTEXT_MPTCP_TYPE];
    struct mptcp_context *pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

    return (u8_t *)(&pMptcpContext->mptcp_secret[0]);

}

void mptcp_get_cls_cand(void *instance, u16_t **pCnt_cls_cand)
{
    struct lwip_instance *pLwipInstance =(struct lwip_instance *)instance;
    struct module_conext *pMptcpModuleContext = &pLwipInstance->module_conext[CONTEXT_MPTCP_TYPE];
    struct mptcp_context *pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

    *pCnt_cls_cand = &pMptcpContext->cnt_cls_cand;
}

void mptcp_update_cls_cand_list_elem(void *instance, u16_t index, struct tcp_pcb *new_pcb)
{
    struct lwip_instance *pLwipInstance =(struct lwip_instance *)instance;
    struct module_conext *pMptcpModuleContext = &pLwipInstance->module_conext[CONTEXT_MPTCP_TYPE];
    struct mptcp_context *pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

    pMptcpContext->cls_cand_list[index] = new_pcb;
}

struct tcp_pcb *mptcp_get_cls_cand_list_elem(void *instance, u16_t index)
{
    struct lwip_instance *pLwipInstance =(struct lwip_instance *)instance;
    struct module_conext *pMptcpModuleContext = &pLwipInstance->module_conext[CONTEXT_MPTCP_TYPE];
    struct mptcp_context *pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

    return pMptcpContext->cls_cand_list[index];
}



void *mptcp_get_recv_info_ptr(void *instance)
{
    struct lwip_instance *pLwipInstance =(struct lwip_instance *)instance;
    struct module_conext *pMptcpModuleContext = &pLwipInstance->module_conext[CONTEXT_MPTCP_TYPE];
    struct mptcp_context *pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;

    return pMptcpContext->recv_info;
}

void mptcp_deinit(struct module_conext *pMptcpModuleContext)
{
    struct mptcp_context *pMptcpContext;

    pMptcpContext = (struct mptcp_context *)pMptcpModuleContext->pCcontext;
    if(pMptcpContext->recv_info != NULL)
        FREE(pMptcpContext->recv_info);
    FREE(pMptcpModuleContext->pCcontext);
}

#endif
