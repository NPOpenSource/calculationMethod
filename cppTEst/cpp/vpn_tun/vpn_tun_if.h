/******************************************************************************
NAME  =	 vpn_tun_if.h :
FUNC  =	 handle udp packet from vpn tun device;
NOTE  =
DATE  =	 2017-04-11 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-11, (cuiql), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/

#ifndef MYAPPLICATION_MPTCP_H
#define MYAPPLICATION_MPTCP_H

#define  UDP_LEN (8)

#ifdef __cplusplus
extern "C" {
#endif
#if !LINUX_PLATFORM
#include <jni.h>
#endif
#include <string.h>
#if !LINUX_PLATFORM
#include <android/log.h>
#endif
#include <sys/select.h>
#include <unistd.h>
#include <pthread.h>
#include "lwip/ip.h"
#include "../tools/tools.h"
#include "lwip/opt.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "netif/etharp.h"
#include "lwip/ip.h"
#include "lwip/module.h"
#define  UDP_LEN (8)
extern int tunUp;

//defination
#define MPTCP_INVALID_FD            -1
#define MPTCP_INVALID_FD_ERR        -1
#define NULL_POINT_ERR 0
#define TAG "JNI"


typedef struct mptcp_data_init {
    //store three fd for use
    int tunnel_FD;
    //IP address for LTE tunnel
    ip4_addr_p_t lteIp;
    int wpriority;
    //port for wifi tunnel
    ip4_addr_p_t wifiIp;
    int lpriority;
    int is_mptcp_init;
} mptcp_data_init_V01;

typedef struct mptcp_tread_data {
    int vpn_tun_device_read_thread_flag;
    pthread_t vpn_tun_device_read_thread_t;
    int receive_udp_packet_thread_flag;
    pthread_t receive_udp_packet_thread_t;
} vpn_thread_data;

typedef struct ip_hdr_t {
    /* version / header length */
    u_int8_t _v_hl;
    /* type of service */
    u_int8_t _tos;
    /* total length */
    u_int16_t _len;
    /* identification */
    u_int16_t _id;
    /* fragment offset field */
    u_int16_t _offset;
    /* time to live */
    u_int8_t _ttl;
    /* protocol*/
    u_int8_t _proto;
    /* checksum */
    u_int16_t _chksum;
    /* source and destination IP addresses */
    ip4_addr_p_t src;
    ip4_addr_p_t dest;

    u_int16_t s_prot;
    u_int16_t d_prot;


}ip_head;

#if LWIP_PCAP_SUPPORT
#define LWIP_PCAP_VPN_UP_STRAM        1
#define LWIP_PCAP_VPN_DOWN_STRAM      2
#define LWIP_PCAP_TUNNEL_UP_STRAM     4
#define LWIP_PCAP_TUNNEL_DOWN_STRAM   8
/*
#define LWIP_PCAP_NAT_UP_STRAM        16
#define LWIP_PCAP_NAT_DOWN_STRAM      32
*/
extern int vpn_pcap_fd;
int tun_pcap_init(char *filename);
int tun_write_pcap(int fd, char *buf, int len, int pcap_type_direction);
int tun_pcap_close(int fd);
void tun_write_pcr_packet(void *sndBuf, int sndLen, void *rcvBuf, int rcvLen, int src_ip,u16_t src_port,int dest_ip, u16_t dest_port);
#endif


int tunif_init(mptcp_data_init_V01 *,JNIEnv *);

void tunif_end_loop(void);
void parsePacket(char* packet,int len);
/*void vpn_tun_read_data(void *instance,char* packet,int len);*/

/******************************************************************************
NAME  =	 vpn_tun_device_write() ;
FUNC  =	 write data to vpn tun device;
INPUT =
RETU  =
DATE  =	 2017-04-10 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, cuiql , Original ;
*******************************************************************************/
int vpn_tun_device_write(u8_t *wrBuff, int len);
int vpn_tun_write_pubf(struct pbuf* p);
#if LWIP_TCP_ZEROCOPY
int vpn_tun_device_write_pbuf(struct pbuf *p);
#endif


#ifdef __cplusplus
}
#endif

#endif //MYAPPLICATION_VPN_TUN_IF_H
