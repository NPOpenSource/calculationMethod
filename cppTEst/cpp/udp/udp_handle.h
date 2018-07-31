/******************************************************************************
NAME  =	 udp_handle.h :
FUNC  =	 handle udp packet from vpn tun device;
NOTE  =
DATE  =	 2017-04-10 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, (cuiql), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/
#ifndef __UDP_PACKET_H__
#define __UDP_PACKET_H__



#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/opt.h"
#include "../tools/tools.h"
#include "../vpn_tun/vpn_tun_if.h"

struct udphdr {
 u16_t src;
 u16_t dest;
 u16_t len;
 u16_t chksum;
};

#if LWIP_IPV4

/* Size of the udp header. Same as 'sizeof(struct udp_hdr)'. */
#define  UDP_HLEN 8
/* Size of the IPv4 header. Same as 'sizeof(struct ip_hdr)'. */
#define IP_HLEN 20

extern vpn_thread_data gVPN_thread_data;

/******************************************************************************
NAME  =	 udp_handle_release() ;
FUNC  =	 free all resources ;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
int udp_handle_init(void *instance);

/******************************************************************************
NAME  =	 udp_handle_release() ;
FUNC  =	 free all resources ;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
void udp_handle_release();

/******************************************************************************
NAME  =	 vpn_tun_receive_udp_packet_handle() ;
FUNC  =	 handle udp packet received from vpn tun;
INPUT =
RETU  =
DATE  =	 2009-02-18 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, (cuiql), Original ;
*******************************************************************************/
int vpn_tun_receive_udp_packet_handle(struct ip_hdr *iphdr, char* udpPacket, int udpPacketlen);

/******************************************************************************
NAME  =	 vpn_tun_send_udp_packet_handle() ;
FUNC  =	 handle udp packet received from vpn tun;
INPUT =
RETU  =
DATE  =	 2009-02-18 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, (cuiql), Original ;
*******************************************************************************/
int vpn_tun_send_udp_packet_handle(u8_t *data, int len, const ip4_addr_p_t *src_ip, u16_t src_port,
                                   const ip4_addr_p_t *dst_ip, u16_t dst_port);

#endif

#ifdef __cplusplus
}
#endif
#endif
