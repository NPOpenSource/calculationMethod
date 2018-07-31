//
// Created by wyjap on 2017/10/25.
//

#ifndef MYAPPLICATION_MODULE_H
#define MYAPPLICATION_MODULE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <lwip/lwipopts.h>
#if LARGE_PACKET
#define MAX_INSTANCE_NUM 1
#else
#define MAX_INSTANCE_NUM 4

#if LWIP_TWO_TCP_STACK_ZSQ
	#define MAX_INSTANCE_NUM 4
	#define MAX_INSIDE_INSTANCE_NUM 1
#endif

#endif

enum module_conext_type {
    CONTEXT_STATS_TYPE = 0,
    CONTEXT_SYS_TYPE, /*1*/
    CONTEXT_MEM_TYPE, /*2*/
    CONTEXT_MEMP_TYPE,/*3*/
    CONTEXT_PBUF_TYPE,/*4*/
    CONTEXT_NETIF_TYPE,/*5*/
    CONTEXT_IPV4_TYPE,/*6*/
    CONTEXT_ETHARP_TYPE,/*7*/
    CONTEXT_RAW_TYPE,/*8*/
    CONTEXT_UDP_TYPE,/*9*/
    CONTEXT_TCP_TYPE,/*10*/
    CONTEXT_IGMP_TYPE,/*11*/
    CONTEXT_DNS_TYPE,/*12*/
    CONTEXT_PPP_TYPE,/*13*/
    CONTEXT_TIMER_TYPE,/*14*/
    CONTEXT_NAT_TYPE,/*15*/
    CONTEXT_MPTCP_TYPE,/*16*/
    CONTEXT_SOCKET_TYPE,/*17*/
	CONTEXT_PROXY_TYPE,/*18*/
	CONTEXT_TUNNEL_TYPE,/*19*/
    CONTEXT_MAX_TYPE
};


struct module_conext;

typedef void (*context_deinit_callback_fn)(struct module_conext *module_conext);

struct module_conext{
	unsigned long id;
    void *pCcontext;
    unsigned long context_buffer_len;
	context_deinit_callback_fn callback;
	void *pArg_deinit;
};

struct lwip_instance{
    struct module_conext  module_conext[CONTEXT_MAX_TYPE];
};

struct module_conext * get_module_context(enum module_conext_type curType, struct module_conext *pConext, enum module_conext_type destType);
void register_lwip_instance(struct lwip_instance *pstInstance);
struct lwip_instance *get_instance_context(enum module_conext_type curType, struct module_conext *pConext);
struct lwip_instance *get_instance(unsigned int i);

void global_set_thread_instance(void *pVal);

void *global_get_thread_instance(void);

void global_init_once(void);
void global_free_param(void);
int get_instance_logic_id(void *instance);


#ifdef __cplusplus
}
#endif
#endif //MYAPPLICATION_MODULE_H
