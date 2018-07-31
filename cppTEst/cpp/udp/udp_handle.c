/******************************************************************************
NAME  =	 udp_handle.c :
FUNC  =	 handle udp packet from vpn tun device;
NOTE  =
DATE  =	 2017-04-10 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, (cuiql), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/
#include "lwip/ip.h"
#include <lwip/inet_chksum.h>
#include <lwip/inet.h>
#include "../tools/tools.h"
#include "udp_handle.h"

#include "udp_socket_manager.h"
#if LWIP_IPV4

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_UDP

static u16_t ip_id= 0;

/*===========================================================================

  FUNCTION
  DESCRIPTION
  PARAMETERS
  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
static void udp_header_print(struct ip_hdr *iphdr, struct udphdr *udphdr) {

    struct in_addr src, dst;
    src.s_addr = (u32_t) iphdr->src.addr;
    dst.s_addr = (u32_t) iphdr->dest.addr;
    LogI("IP Version/header length:%d", iphdr->_v_hl);
    LogI("Header Length:%d", ntohs(iphdr->_len));
    LogI("Protocol:%d", iphdr->_proto);
    LogI("tos:%d", iphdr->_ttl);
    LogI("ttl:%d", iphdr->_tos);
    LogI("offset:%d", lwip_ntohs(iphdr->_offset));
    LogI("ipsrc:%s", inet_ntoa(src));
    LogI("ipdst:%s", inet_ntoa(dst));
    LogI("ip id :%d", lwip_ntohs(iphdr->_id));
    LogI("ic checksum:%d   ntohs=%d", iphdr->_chksum, ntohs(iphdr->_chksum));
    LogI("portsrc:%d", ntohs(udphdr->src));
    LogI("portdst:%d", ntohs(udphdr->dest));
    LogI("udp len :%d", ntohs(udphdr->len));
    LogI("dup checksum:%d   ntohs=%d", udphdr->chksum, ntohs(udphdr->chksum));
}

/*===========================================================================

  FUNCTION
  DESCRIPTION
  PARAMETERS
  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int udp_handle_init(void *instance) {

    int ret = -1;
    ret = sm_init(instance);

    return ret;
}


/*===========================================================================

  FUNCTION
  DESCRIPTION
  PARAMETERS
  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
void udp_handle_release() {

    sm_release();
    return;
}

/*===========================================================================

  FUNCTION
  DESCRIPTION
  PARAMETERS
  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int vpn_tun_receive_udp_packet_handle(struct ip_hdr *iphdr, char *udpPacket, int udpPacketlen) {
    struct udphdr *udphdr;
    /* Check minimum length (UDP header) */
    if (udpPacketlen < UDP_HLEN) {
        /* drop short packets */
        LogE("UDP packet len error");
        return -1;
    }

    udphdr = (struct udphdr *) udpPacket;
    LogI(" ********************before checksum begin*********************");
    udp_header_print(iphdr, udphdr);
    LogI(" ********************before checksum end*********************");
    /* find a socket for sending udp packet */
    if (send_udp_packet_to_network(udpPacket + UDP_HLEN, udpPacketlen - UDP_HLEN, &iphdr->src,
                                   udphdr->src, &iphdr->dest, udphdr->dest) < 0) {
        LogE("send udp packet to network error");
        return -1;
    }
    return 0;
}


/*===========================================================================

  FUNCTION
  DESCRIPTION
  PARAMETERS
  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int vpn_tun_send_udp_packet_handle(u8_t *data, int len, const ip4_addr_p_t *src_ip, u16_t src_port,
                                   const ip4_addr_p_t *dst_ip, u16_t dst_port) {
    err_t err = ERR_OK;
    if( len > 1500 )
    {
        LogE("vpn_tun_send_udp_packet_handle: data len invalid. len =%d", len);
        return -1;
    }
    struct pbuf  *p, *q;
    /* alloc memory for ip packet*/
    p = pbuf_alloc(NULL,PBUF_IP, ((u16_t) len), PBUF_POOL);
    for (q = p; q != NULL; q = q->next) {
        MEMCPY(q->payload, data, q->len);
        data += q->len;
    }
    /* get iphdr address */
    if (pbuf_header(p, UDP_HLEN)) {
        /* allocate header in a separate new pbuf */
        q = pbuf_alloc(NULL, PBUF_IP, UDP_HLEN, PBUF_RAM);
        /* new header pbuf could not be allocated? */
        if (q == NULL) {
            LogE("vpn_tun_send_udp_packet_handle: could not allocate header\n");
            return ERR_MEM;
        }
        if (p->tot_len != 0) {
            /* chain header q in front of given pbuf p (only if p contains data) */
            pbuf_chain(q, p);
        }
        /* first pbuf q points to header pbuf */
    } else {
        /* adding space for header within p succeeded */
        /* first pbuf q equals given pbuf */
        q = p;
    }
    struct udphdr *udphdr;
    u16_t udpchksum;
    /* get udphdr address */
    udphdr = (struct udphdr *)p->payload;
    /*set upd header data*/
    /* network order */
    udphdr->src = src_port;
    /* network order */
    udphdr->dest = dst_port;
    udphdr->len = lwip_htons(p->tot_len);
    udphdr->chksum = 0;
    /* calculate udp checksum */
    udpchksum = ip_chksum_pseudo(p, IP_PROTO_UDP, p->tot_len, (ip_addr_t *)src_ip, (ip_addr_t *)dst_ip);
    /* chksum zero must become 0xffff, as zero means 'no checksum' */
    if (udpchksum == 0x0000) {
        udpchksum = 0xffff;
    }
    udphdr->chksum = udpchksum; //udpchksum is network order
    struct ip_hdr *iphdr;

    /* generate IP header */
    if (pbuf_header(p, IP_HLEN)) {
        LogE("ip4_output: not enough room for IP header in pbuf\n");
        return ERR_BUF;
    }
    /* set ip header data */
    iphdr = (struct ip_hdr *)p->payload;
    IPH_VHL_SET(iphdr, 4, IP_HLEN / 4);
    IPH_TOS_SET(iphdr, 0);
    IPH_LEN_SET(iphdr, lwip_htons(p->tot_len));
    IPH_ID_SET(iphdr, lwip_htons(ip_id));
    IPH_OFFSET_SET(iphdr, 0);
    IPH_TTL_SET(iphdr, UDP_TTL);
    IPH_PROTO_SET(iphdr, IP_PROTO_UDP);
    //++ip_id;
    ip4_addr_copy(iphdr->src, *src_ip);
    ip4_addr_copy(iphdr->dest, *dst_ip);
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));

    LogI(" ********************after checksum begin*********************");
    udp_header_print(iphdr,udphdr);
    LogI(" ********************after checksum end*********************");

#if LWIP_TCP_ZEROCOPY
    vpn_tun_device_write_pbuf(p);
#else
    /*write ip data to vpn tun device*/
    vpn_tun_device_write((u8_t *)p->payload, p->tot_len);

    /*free memory*/
    pbuf_free(p);
#endif

    return err;
}

#endif
