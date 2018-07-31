/******************************************************************************
NAME  =	 udp_socket_manager.h :
FUNC  =	 manager udp socket;
NOTE  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/
#ifndef __UDP_SOCKET_MANAGER_H__
#define __UDP_SOCKET_MANAGER_H__



#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/opt.h"
#include "lwip/ip.h"
#include "../tools/tools.h"
#include "../vpn_tun/vpn_tun_if.h"
//根据优先级获取wifi和LTE 的ip地址
#define UDP_SOCKET_CUR_IP (gMPTCP_config.wpriority > gMPTCP_config.lpriority)? gMPTCP_config.wifiIp:gMPTCP_config.lteIp

/******************************************************************************
NAME  =	 sm_init() ;
FUNC  =	 socket manager init ;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
int sm_init(void *instance);

/******************************************************************************
NAME  =	 sm_release() ;
FUNC  =	 release all socket. this function will be call when quiting ;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
void sm_release();

/******************************************************************************
NAME  =	 find_socket() ;
FUNC  =	 find a socket to send udp packet to network ;
INPUT =
RETU  =
DATE  =	 2009-02-18 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, (cuiql), Original ;
*******************************************************************************/
int find_socket(const ip4_addr_p_t *src_ip, u16_t src_port,
                const ip4_addr_p_t *dst_ip, u16_t dst_port);


/******************************************************************************
NAME  =	 send_udp_packet_to_network() ;
FUNC  =	 sending udp packet to network;
INPUT =
RETU  =
DATE  =	 2009-02-18 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, (cuiql), Original ;
*******************************************************************************/
int send_udp_packet_to_network(void* msg, int msglen, ip4_addr_p_t *src_ip, u16_t src_port,
                               ip4_addr_p_t *dstip, u16_t dstport);

/******************************************************************************
NAME  =	 receive_udp_packet_thread() ;
FUNC  =	 find a socket to send udp packet to network ;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
void* receive_udp_packet_thread(void *arg);

#ifdef __cplusplus
}
#endif
#endif
