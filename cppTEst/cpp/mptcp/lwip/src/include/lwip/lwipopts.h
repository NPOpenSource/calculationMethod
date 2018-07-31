/*===========================================================================

                         lwipopts.h

DESCRIPTION

 MPTCP protocl stack options


Copyright (c) 2017.04 - 2017.05 by Thundersoft Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/

#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#define LWIP_DEBUG                      1
#define LWIP_DEBUG_SWITCH               LWIP_DBG_ON /* Need to be turned OFF in release version */

#if 0
#define ETHARP_DEBUG                    LWIP_DEBUG_SWITCH
#define NETIF_DEBUG                     LWIP_DEBUG_SWITCH
#define PBUF_DEBUG                      LWIP_DEBUG_SWITCH
#define API_LIB_DEBUG                   LWIP_DEBUG_SWITCH
#define API_MSG_DEBUG                   LWIP_DEBUG_SWITCH
#define SOCKETS_DEBUG                   LWIP_DEBUG_SWITCH
#define INET_DEBUG                      LWIP_DEBUG_SWITCH
#define IP_DEBUG                        LWIP_DEBUG_SWITCH
#define IP_REASS_DEBUG                  LWIP_DEBUG_SWITCH
#define RAW_DEBUG                       LWIP_DEBUG_SWITCH
#define MEM_DEBUG                       LWIP_DEBUG_SWITCH
#define MEMP_DEBUG                      LWIP_DEBUG_SWITCH
#define SYS_DEBUG                       LWIP_DEBUG_SWITCH
#define TIMERS_DEBUG                    LWIP_DEBUG_SWITCH
#define TCP_DEBUG                       LWIP_DEBUG_SWITCH
#define TCP_INPUT_DEBUG                 LWIP_DEBUG_SWITCH
#define TCP_FR_DEBUG                    LWIP_DEBUG_SWITCH
#define TCP_RTO_DEBUG                   LWIP_DEBUG_SWITCH
#define TCP_CWND_DEBUG                  LWIP_DEBUG_SWITCH
#define TCP_WND_DEBUG                   LWIP_DEBUG_SWITCH
#define TCP_OUTPUT_DEBUG                LWIP_DEBUG_SWITCH
#define TCP_RST_DEBUG                   LWIP_DEBUG_SWITCH
#define TCP_QLEN_DEBUG                  LWIP_DEBUG_SWITCH
#define TCPIP_DEBUG                     LWIP_DEBUG_SWITCH
#define MPTCP_TXRX_DEBUG                LWIP_DEBUG_SWITCH
#define MPTCP_TXRX_DTL_DEBUG            LWIP_DEBUG_SWITCH
#define MPTCP_FIN_DEBUG                 LWIP_DEBUG_SWITCH
#define ERROR_LOGGING                   LWIP_DEBUG_SWITCH
#define MPTCP_DEBUG                     LWIP_DEBUG_SWITCH
#define MPTCP_PROXY_DEBUG               LWIP_DEBUG_SWITCH
#define TCP_TWO_STACK_DEBUG             LWIP_DEBUG_SWITCH
#define TRAFFIC_DEBUG                   LWIP_DEBUG_SWITCH
#define LWIP_STREAM_ALL_DEBUG           LWIP_DEBUG_SWITCH
#define SACK_DEBUG                      LWIP_DEBUG_SWITCH
#endif

#include "common.h"

#define API_LIB_DEBUG			E_LOG_LWIP_API_LIB
#define API_MSG_DEBUG			E_LOG_LWIP_API_MSG
#define SOCKETS_DEBUG			E_LOG_LWIP_SOCKETS
#define INET_DEBUG				E_LOG_LWIP_INET
#define IP_DEBUG				E_LOG_LWIP_IP
#define IP_REASS_DEBUG			E_LOG_LWIP_IP_REASS
#define RAW_DEBUG		 		E_LOG_LWIP_RAW
#define MEM_DEBUG		 		E_LOG_LWIP_MEM
#define MEMP_DEBUG		 		E_LOG_LWIP_MEMP
#define SYS_DEBUG		 		E_LOG_LWIP_SYS
#define TIMERS_DEBUG		 	E_LOG_LWIP_TIMERS
#define TCP_DEBUG		 	 	E_LOG_LWIP_TCP
#define TCP_INPUT_DEBUG		 	E_LOG_LWIP_TCP_INPUT
#define TCP_FR_DEBUG		 	E_LOG_LWIP_TCP_FR
#define TCP_RTO_DEBUG		 	E_LOG_LWIP_TCP_RTO
#define TCP_CWND_DEBUG		 	E_LOG_LWIP_TCP_CWND
#define TCP_WND_DEBUG		 	E_LOG_LWIP_TCP_WND
#define TCP_OUTPUT_DEBUG	 	E_LOG_LWIP_TCP_OUTPUT
#define TCP_RST_DEBUG		 	E_LOG_LWIP_TCP_RST
#define TCP_QLEN_DEBUG		 	E_LOG_LWIP_TCP_QLEN
#define TCPIP_DEBUG				E_LOG_LWIP_TCPIP
#define MPTCP_TXRX_DEBUG		E_LOG_LWIP_MPTCP_TXRX
#define MPTCP_TXRX_DTL_DEBUG	E_LOG_LWIP_MPTCP_TXRX_DTL
#define MPTCP_FIN_DEBUG		 	E_LOG_LWIP_MPTCP_FIN
#define ERROR_LOGGING           E_LOG_LWIP_ERROR_LOGGING
#define MPTCP_DEBUG		 		E_LOG_LWIP_MPTCP
#define MPTCP_PROXY_DEBUG		E_LOG_LWIP_MPTCP_PROXY
#define TCP_TWO_STACK_DEBUG		E_LOG_LWIP_TCP_TWO_STACK
#define TRAFFIC_DEBUG		 	E_LOG_LWIP_TRAFFIC
#define LWIP_STREAM_ALL_DEBUG	E_LOG_LWIP_STREAM_ALL
#define SACK_DEBUG		 		E_LOG_LWIP_SACK


#define LINUX_PLATFORM                        0
#define LWIP_MPTCP_SUPPORT              1
#define MPTCP_SUB_SERVER_ADDR           1
#define MPTCP_BUF_RECV_OFO_DATA         1
#define MPTCP_TXRX_DUMP_DATA            0
#define LWIP_ICMP_SUPPORT 		0

#if LWIP_MPTCP_SUPPORT
#define SACK_FOR_MPTCP_SUPPORT         1
#endif

#define SYS_LIGHTWEIGHT_PROT            1
#define NO_SYS                          0
#define LWIP_TCPIP_CORE_LOCKING         0

#define MEM_ALIGNMENT                   8
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEMP_NUM_NETCONN                512 /* Define the number of sockets supported */
#define TCPIP_MBOX_SIZE                 163840
#define DEFAULT_TCP_RECVMBOX_SIZE       16384

#define LWIP_IPV4                       1
#define LWIP_IPV6                       0

#define LWIP_TCP                        1
#define TCP_LISTEN_BACKLOG              1


#define LWIP_TCP_TIMESTAMPS             1

#if LINUX_PLATFORM
#define TUN_TCP_MSS                     1460
#else
#define TUN_TCP_MSS                     64940
#endif
#define LWIP_WND_SCALE                  1
#ifdef LARGE_PACKET
#define TCP_RCV_SCALE                   8
#define TCP_WND                         16776960 /* 16M */
#define TCP_SND_BUF                     16776960 /* 16M */
#else
//#define TCP_RCV_SCALE                   7
//#define TCP_WND                         4194304 /* 4M */
//#define TCP_SND_BUF                     4194304 /* 4M */
#define TCP_RCV_SCALE                   8
#define TCP_WND                         16776960 /* 16M */
#define TCP_SND_BUF                     16776960 /* 16M */

#endif
#define TCP_SNDLOWAT                    56000


#define LWIP_ICMP                       0
#define LWIP_RAW                        0
#define LWIP_UDP                        0
#define LWIP_STATS                      0

#define LWIP_SOCKET_SELECT              1
#define LWIP_SINGLE_NETIF               0
#define LWIP_MPU_COMPATIBLE             1
#define LWIP_POSIX_SOCKETS_IO_NAMES     0
#define LWIP_DEBUG_TIMERNAMES           0
#define IP_NAT                              1

#define MPTCP_PROXY_MODULE                  1
#define WIFI_SWITCH_FEATURE                 1

/*For test*/
#define LWIP_PERFORMANCE_IMPROVE              1
#ifdef LARGE_PACKET
#define LWIP_PERFORMANCE_ENABLE_DELAY_ACK     0
#else
#define LWIP_PERFORMANCE_ENABLE_DELAY_ACK     1
#endif
#define LWIP_PERFORMANCE_IMPROVE_CHECKLOG     0
#define LWIP_PERFORMANCE_IMPROVE_RECV_NOWAIT  1
#define LWIP_PERFORMANCE_IMPROVE_SEND_NOWAIT  1
#define LWIP_PERFORMANCE_TEST_ENABLE_VETH0    0
#define LWIP_PERFORMANCE_ASYNC_TUN_RXTX       0
#define TEST_PROXY                            0
#define TEST_TUNNEL                           0
#define UNITE_TEST                            0
#define MCCP_TEST                             0
#define MUTP_TEST_DEBUG_OUTPUT_DATA           0
#define LWIP_ARP                              0
#define LWIP_ETHERNET                         0
#define ETHNET_ENABLE                         0
#define WLAN_ENABLE                           0
#define MCCP_MPGW_IP                          "192.168.1.111"
#define SECONDARY_GW_IP                       0x7001a8c0
#define LWIP_MULTI_INSTANCE                   1
#define LWIP_PACKET_QUEUE                     0
#define LWIP_VPNQUE_PACKET                    0
#define LWIP_GOOGLEPAD_ENABLE                 0
#define LWIP_SHELL_CONSOLE                    0
#define LWIP_TCP_ZEROCOPY                     0
#define SEND_FAST_CLOSE                       1
#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD              1
#endif
#define HEARTBEAT_SUPPORT_v02                 0
#define MPCB_CHECK                            0
/*used for compiler set the macro*/
/***************************************************************************************/
#ifndef LWIP_PCAP_SUPPORT
#define LWIP_PCAP_SUPPORT                     1
#else
#define LWIP_PCAP_SUPPORT                     1
#endif
#ifndef LWIP_UDP_THROUGH_HAG
#define LWIP_UDP_THROUGH_HAG                  1
#else
#define LWIP_UDP_THROUGH_HAG                  1
#endif
#ifndef HEARTBEAT_SUPPORT
#define HEARTBEAT_SUPPORT                     0
#else
#define HEARTBEAT_SUPPORT                     1
#endif
//æ ææ?æµå°éçäžé
#ifndef LWIP_TWO_TCP_STACK
#define LWIP_TWO_TCP_STACK                    0
#else
#define LWIP_TWO_TCP_STACK                    1
#endif
#ifndef LARGE_PACKET
#define LARGE_PACKET                    0
#else
#define LARGE_PACKET                    1
#endif
//å»ºè®®å³é­ äžçš³å®?å»ºè®®åç»­äŒå
#ifndef WIFIFD_OPT
#define WIFIFD_OPT                    1
#else
#define WIFIFD_OPT                    1
#endif
//å»ºè®®æåŒ
#ifndef MEMCPY_OPT
#define MEMCPY_OPT                    1
#else
#define MEMCPY_OPT                    1
#endif

//å»ºè®®æåŒ
#ifndef TCP_FIND
#define TCP_FIND                    1
#else
#define TCP_FIND                    1
#endif

//æ ææŸææ?
#ifndef LWIP_TWO_TCP_STACK_ZSQ
#define LWIP_TWO_TCP_STACK_ZSQ                    0
#else
#define LWIP_TWO_TCP_STACK_ZSQ                    1
#endif

//å»ºè®®æåŒ
#ifndef SEND_MSG_BATCH
#define SEND_MSG_BATCH                    1
#else
#define SEND_MSG_BATCH                    1
#endif


//å»ºè®®å³é­
#ifndef SEND_MSG_BATCH_IGNORE_ERR
#define SEND_MSG_BATCH_IGNORE_ERR                    0
#else
#define SEND_MSG_BATCH_IGNORE_ERR                    1
#endif


//å»ºè®®æåŒïŒåå°Pingæ¶å»¶
#ifndef FORWARD_DELAY_OPT
#define FORWARD_DELAY_OPT                    1
#else
#define FORWARD_DELAY_OPT                    1
#endif

//when open PROXY_UPLOAD_PROTECT,this macro no used
#ifndef UP_SOCK_BUFF
#define UP_SOCK_BUFF                    0
#else
#define UP_SOCK_BUFF                    1
#endif

//ææäžææ?
#ifndef UP_THREAD_PRIO
#define UP_THREAD_PRIO                    0
#else
#define UP_THREAD_PRIO                    1
#endif

//äžè¡éççš³å®äº?äœæ¯åœ±åPingæ¶å»¶
#ifndef UP_SEND_RTO
#define UP_SEND_RTO                    0
#else
#define UP_SEND_RTO                    1
#endif

#ifndef PREFETCH_PBUF_GCC
#define PREFETCH_PBUF_GCC                    1
#else
#define PREFETCH_PBUF_GCC                    1
#endif

#ifndef SYS_THREAD_FREE_FUNC
#define SYS_THREAD_FREE_FUNC                    1
#else
#define SYS_THREAD_FREE_FUNC                    1
#endif

#ifndef WRITE_VPN_P20
#define WRITE_VPN_P20                    1
#else
#define WRITE_VPN_P20                    1
#endif

#ifndef WRITE_VPN_BLOCK
#define WRITE_VPN_BLOCK                    0
#else
#define WRITE_VPN_BLOCK                    1
#endif

#ifndef PBUF_FREE_PROTECT
#define PBUF_FREE_PROTECT                    1
#else
#define PBUF_FREE_PROTECT                    1
#endif

#ifndef RESET_TO_FASTCLOSE
#define RESET_TO_FASTCLOSE                    0
#else
#define RESET_TO_FASTCLOSE                    1
#endif

//for speedtest upload network communication fail
#ifndef PROXY_UPLOAD_PROTECT
#define PROXY_UPLOAD_PROTECT                    1
#else
#define PROXY_UPLOAD_PROTECT                    1
#endif

/***************************************************************************************/
/*used for large packet*/
#if LARGE_PACKET
#define TCP_MSS                         19600
#elif SACK_FOR_MPTCP_SUPPORT
//å»ºè®®1380. 1240éçææäžå¥œ
#define TCP_MSS                         1380 /* 20(DSS header) + 8(MUTP header)
                                              * + 8(UDP header) + 20(IP header)
                                              * shorter than usual TCP MSS */
/* The possible minimum MTU of target
 * LTE environment is 1340 */
#else
#define TCP_MSS                         1240
#endif

#define PCA_COMPATIBLE    1

#define WIFI_LTE_SWITCH     1

#define likely(x)  __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

#ifndef FREE
#define FREE(p) do { if (p) \
						{ 	\
							free(p); \
							p = NULL;\
						} \
                   } while(0);
#endif

#endif /* __LWIPOPTS_H__ */
