/*===========================================================================

                         ipv4_nat.c

DESCRIPTION

 Shows how to create NAT between tun interface and an internal NIC..


Copyright (c) 2017.04 - 2017.05 by Thundersoft Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/

#include "lwip/ip4_nat.h"

#if IP_NAT
#include "lwip/lwipopts.h"
#include "lwip/ip4.h"
#include "../../../../vpn_tun/vpn_tun_if.h"
#include <lwip/mptcp/mptcp_proxy.h>
#include <lwip/tcpip.h>

/*#define __android_log_print(...) do{}while(0)*/

/** Define this to enable debug output of this module */
#ifndef NAT_DEBUG
#define NAT_DEBUG      LWIP_DBG_ON
#endif
#if LINUX_PLATFORM
#define LWIP_NAT_DEFAULT_TMU                     (1460)
#else
#define LWIP_NAT_DEFAULT_TMU                     (65000)
#endif
#define LOG_TAG "ip_NAT"
#if LINUX_PLATFORM
#define LWIP_DEBUGF_NAT(...)
#else
#define LWIP_DEBUGF_NAT(...)   __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif
/*struct netif nat_netif;*/
/*
u8_t server_addr[4] = {10, 0, 2, 254};
u8_t server_mask[4] = {255, 255, 255, 0};
u8_t server_gw[4] = {10, 0, 2, 1};
ip4_addr_t ip4_server_addr;
*/
static err_t ip4_nat_netif_init(struct netif *netif);
void ip4_nat_add_netif(struct module_conext *pNatContext);
err_t ip4_nat_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);

struct ipv4_nat_context{
	struct netif nat_netif;
	u8_t server_addr[4];
	u8_t server_mask[4];
	u8_t server_gw[4];
	ip4_addr_t ip4_server_addr;
	int vpn_nat_recv;
	int vpn_nat_send;
	int vpn_nat_err_recv;
};

/* Initialize this module */
void ip4_nat_init(struct module_conext *pNatContext)
{
  struct ipv4_nat_context *pNatIfContext;

  pNatContext->pCcontext = malloc(sizeof(struct ipv4_nat_context));
  memset(pNatContext->pCcontext, 0x0,sizeof(struct ipv4_nat_context));
  pNatIfContext = (struct ipv4_nat_context *)pNatContext->pCcontext;

  *((u32_t *)(&pNatIfContext->server_addr)) = lwip_htonl(0x0a0002fe); /*10.0.2.254*/
  *((u32_t *)(&pNatIfContext->server_mask)) = lwip_htonl(0xffffff00); /*255.255.255.0*/
  *((u32_t *)(&pNatIfContext->server_gw)) = lwip_htonl(0x0a000201); /*10.0.2.1*/
  
  /* add server netif */
  ip4_nat_add_netif(pNatContext);
}

void ip4_nat_deinit(struct module_conext *pNatContext) {
	struct ipv4_nat_context *pNatIfContext = (struct ipv4_nat_context *)pNatContext->pCcontext;
    /*
    char buf[512]={0};
	
	ip4_nat_debug_counter(get_instance_context(CONTEXT_NAT_TYPE,pNatContext), buf, 512);
	LogE("IPv4 NAT counter list:\r\n%s",buf);
	*/

    netif_set_down(&pNatIfContext->nat_netif);
    netif_set_link_down(&pNatIfContext->nat_netif);
    netif_remove(&pNatIfContext->nat_netif);
	FREE(pNatContext->pCcontext);
}

/* add netif */
void ip4_nat_add_netif(struct module_conext *pNatContext)
{
    ip4_addr_t addr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
	struct ipv4_nat_context *pNatIfContext = (struct ipv4_nat_context *)pNatContext->pCcontext;
	struct module_conext *pNetIf = get_module_context(CONTEXT_NAT_TYPE, pNatContext,  CONTEXT_NETIF_TYPE);
	

    LWIP_DEBUGF_NAT("ip4_nat_add_netif enter \n");

    IP4_ADDR(&pNatIfContext->ip4_server_addr, pNatIfContext->server_addr[0], pNatIfContext->server_addr[1], pNatIfContext->server_addr[2], pNatIfContext->server_addr[3]);
    IP4_ADDR(&netmask, pNatIfContext->server_mask[0], pNatIfContext->server_mask[1], pNatIfContext->server_mask[2], pNatIfContext->server_mask[3]);
    IP4_ADDR(&gw, pNatIfContext->server_gw[0], pNatIfContext->server_gw[1], pNatIfContext->server_gw[2], pNatIfContext->server_gw[3]);

    /*netif_add(&nat_netif, &ip4_server_addr, &netmask, &gw, &nat_netif, ip4_nat_netif_init, tcpip_input);*/
    netif_add(pNetIf, &pNatIfContext->nat_netif, &pNatIfContext->ip4_server_addr, &netmask, &gw, &pNatIfContext->nat_netif, ip4_nat_netif_init, tcpip_input);
    netif_set_up(&pNatIfContext->nat_netif);
    netif_set_link_up(&pNatIfContext->nat_netif);
}

/* netif init */
static err_t ip4_nat_netif_init(struct netif *netif)
{
  LWIP_DEBUGF_NAT("ip4_nat_netif_init enter \n");

  netif->name[0] = 'N';
  netif->name[1] = 'T';
  netif->output = ip4_nat_netif_output;
  netif->mtu        = LWIP_NAT_DEFAULT_TMU;
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
  netif->is_nat_if = 1;
#endif
  netif->hwaddr_len = 6;
  netif->hwaddr[0] = 0x00;
  netif->hwaddr[1] = 0x23;
  netif->hwaddr[2] = 0xC1;
  netif->hwaddr[3] = 0xDD;
  netif->hwaddr[4] = 0xDD;
  netif->hwaddr[5] = 0xDD;

  return ERR_OK;
}

/* receive package from tun */
void ip4_nat_input_pkt_from_tun(void *instance, struct pbuf *p)
{
  err_t err;
  struct module_conext *pNatContext;
  struct ipv4_nat_context *pNatIfContext;
  struct ip_hdr *iph;
  struct tcp_hdr *tcph;

  if(instance != NULL)
  {
      pNatContext = &(((struct lwip_instance *)instance)->module_conext[CONTEXT_NAT_TYPE]);
      pNatIfContext = (struct ipv4_nat_context *)pNatContext->pCcontext;

	  iph = (struct ip_hdr *)p->payload;
	  tcph = (struct tcp_hdr *)(iph+1);
	  LWIP_DEBUGF(LWIP_STREAM_ALL_DEBUG, ("ip4_nat_input_pkt_from_tun enter instance-%p, source port %d,length=%d,send packet=%d\n",instance, lwip_ntohs(tcph->src),p->len,pNatIfContext->vpn_nat_recv));
	  LWIP_ASSERT("p is NULL", p != NULL);

	  err = pNatIfContext->nat_netif.input(p, &pNatIfContext->nat_netif);
	  if (err != ERR_OK) {
	      LWIP_DEBUGF_NAT("ip4_nat_input_pkt_from_tun fail \n");
          pbuf_free(p);
		  pNatIfContext->vpn_nat_err_recv++;
	  }
	  else
	  {
	      pNatIfContext->vpn_nat_recv++;
	  }
  }
}
/* send the package to tun0. the package is from up layer */
err_t ip4_nat_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
	struct module_conext *pNatContext;
	struct ipv4_nat_context *pNatIfContext;
	struct dataPacket *dataPack;
	struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    struct tcp_hdr *tcph = (struct tcp_hdr *)(iph+1);

  LWIP_DEBUGF(LWIP_STREAM_ALL_DEBUG, ("current %p vpn_tun_device_write ip=%s, src port=%d len is %d",netif->instance,inet_ntoa(iph->src),lwip_ntohs(tcph->src),p->len));
  /* pass to tun0 */
  
#if !LWIP_TCP_ZEROCOPY
#if 0
  if(p->len < p->tot_len){
    u8_t *buf = (u8_t *)malloc(p->tot_len);
    if(buf == NULL)
      return ERR_MEM;
    if(pbuf_copy_partial(p, buf, p->tot_len, 0) < p->tot_len){
      free(buf);
      return ERR_MEM;
    }else{
      vpn_tun_device_write(buf, p->tot_len);
      free(buf);
    }
  }else
    vpn_tun_device_write((u8_t *)p->payload, p->len);
#else
    //LogE("%s:%d p->ref:%d instance:%p",__func__,__LINE__,p->ref,p->instance);
    pbuf_ref(p);
    //LogE("%s:%d p->ref:%d instance:%p",__func__,__LINE__,p->ref,p->instance);
    vpn_tun_write_pubf(p);
#endif
#else
    /*data is in unsent queue,other is free*/	
    if(p->flags & PBUF_FLAG_UNACKED){
       vpn_tun_device_write_pbuf(p);
    }
	else
	{
		struct pbuf *pTbuf = pbuf_alloc(netif->instance,PBUF_RAW, p->tot_len, PBUF_POOL);
		if(pTbuf == NULL)
		  return ERR_MEM;
		if(pbuf_copy_partial(p, pTbuf->payload, p->tot_len, 0) < p->tot_len){
		  pbuf_free(pTbuf);
		  return ERR_MEM;
		}else{
		  pTbuf->len = p->tot_len;
		  vpn_tun_device_write_pbuf(pTbuf);
		}
	}
#endif

  if(netif->instance != NULL){
     pNatContext = &(((struct lwip_instance *)netif->instance)->module_conext[CONTEXT_NAT_TYPE]);
     pNatIfContext = (struct ipv4_nat_context *)pNatContext->pCcontext;
     pNatIfContext->vpn_nat_send++;
  }
  return ERR_OK;
}

u32_t ip4nat_get_context_buffer_size(void)
{
	return sizeof(struct ipv4_nat_context);
}

u32_t ip4_nat_get_netif_ip(struct module_conext *pNatContext){
	struct ipv4_nat_context *pNatIfContext = (struct ipv4_nat_context *)pNatContext->pCcontext;

	return pNatIfContext->nat_netif.ip_addr.addr;
}

int ip4_nat_debug_counter(void *instance, char *pBuffer, unsigned int len)
{
	struct module_conext *pNatContext;
	struct ipv4_nat_context *pNatIfContext;
	int nPos = 0,offset=0;

	if(instance != NULL){
	   pNatContext = &(((struct lwip_instance *)instance)->module_conext[CONTEXT_NAT_TYPE]);
	   pNatIfContext = (struct ipv4_nat_context *)pNatContext->pCcontext;

       offset = 0;
	   nPos = snprintf(pBuffer,len,"IPv4 NAT send	=	0x%08x\r\n",pNatIfContext->vpn_nat_send);
	   offset += nPos;
	   
	   nPos = snprintf(pBuffer+offset,(len - offset),"IPv4 NAT recv	=	0x%08x\r\n",pNatIfContext->vpn_nat_recv);
	   offset += nPos;
	   
	   nPos = snprintf(pBuffer+offset,(len - offset),"IPv4 NAT recv	err =	0x%08x\r\n",pNatIfContext->vpn_nat_err_recv);
	   offset += nPos;
	}

    return offset;
}
#endif
