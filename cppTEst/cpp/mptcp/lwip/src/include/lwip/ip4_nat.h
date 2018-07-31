/*===========================================================================

                         ipv4_nat.h

DESCRIPTION

 MPTCP protocl stack extern function


Copyright (c) 2017.04 - 2017.05 by Thundersoft Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/


#ifndef __LWIP_NAT_H__
#define __LWIP_NAT_H__
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/module.h"

#if IP_NAT
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*extern struct netif nat_netif;*/

extern void ip4_nat_add_netif(struct module_conext *pNatContext);
void ip4_nat_init(struct module_conext *pNatContext);
void ip4_nat_deinit(struct module_conext *pNatContext);
void ip4_nat_input_pkt_from_tun(void *instance,struct pbuf *p);
u32_t ip4nat_get_context_buffer_size(void);
u32_t ip4_nat_get_netif_ip(struct module_conext *pNatContext);
int ip4_nat_debug_counter(void *instance, char *pBuffer, unsigned int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
#endif /* __LWIP_NAT_H__ */