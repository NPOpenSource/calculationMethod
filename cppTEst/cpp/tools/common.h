#ifndef __COMMON_H__
#define __COMMON_H__
#include "lwip/lwipopts.h"


#define Max(x, y) ((x)>(y)?(x):(y))
#define Min(x, y) ((x)<(y)?(x):(y))


extern unsigned char g_pcap_header_only;
extern const unsigned int  g_pcap_len;
#define PCAP_LEN(buf_len)   (g_pcap_header_only ? Min(g_pcap_len, buf_len): buf_len)

#define E_LOG_LEV_DEBUG 0
#define E_LOG_LEV_INFO  1
#define E_LOG_LEV_WARN  2
#define E_LOG_LEV_ERR   3
#define E_LOG_LEV_FATAL 4
#define E_LOG_LEV_MAX   5


#define LOG_MODULES \
    LOG_MOD_ITEM(E_LOG_MODULE_DEFAULT,      " MOD_MPTCP_DEF ",      "--default" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_PROXY,        " MOD_MPTCP_PROXY ",    "--proxy" /*arg*/,    0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_STACK,        " MOD_MPTCP_STACK ",    "--stack" /*arg*/,    0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_TUNNEL,       " MOD_MPTCP_TUNNEL ",   "--tunnel" /*arg*/,   0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_SDK,          " MOD_MPTCP_SDK ",      "--sdk" /*arg*/,      0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_IPERF,        " MOD_MPTCP_IPERF ",    "--iperf" /*arg*/,    0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_MCCP,         " MOD_MPTCP_MCCP ",     "--mccp" /*arg*/,     0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_UDP,          " MOD_MPTCP_UDP ",      "--udp" /*arg*/,      0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_NETIF,        " MOD_MPTCP_NETIF ",    "--netif" /*arg*/,    0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_HEARTBEAT,    " MOD_MPTCP_HEARTBEAT ","--heartbeat" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_MODULE_VPN_TUN,      " MOD_MPTCP_VPN_TUN ",  "--vpn_tun" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,1 /*ERR*/,1 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_DEFAULT,        " MOD_LWIP_DEFAULT ",   "--stk_default" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_ETHARP,         " MOD_LWIP_ETHARP ",    "--stk_etharp" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_NETIF,          " MOD_LWIP_NETIF ",     "--stk_netif" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_PBUF,           " MOD_LWIP_PBUF ",      "--stk_pbuf" /*arg*/, 0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_API_LIB,        " MOD_LWIP_API_LIB ",   "--stk_apilib" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_API_MSG,        " MOD_LWIP_API_MSG ",   "--stk_apimsg" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_SOCKETS,        " MOD_LWIP_SOCKETS ",   "--stk_socket" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_INET,           " MOD_LWIP_INET ",      "--stk_inet" /*arg*/, 0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_IP,             " MOD_LWIP_IP ",        "--stk_ip" /*arg*/,   0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_IP_REASS,       " MOD_LWIP_IP_REASS ",  "--stk_ip_reass" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_RAW,            " MOD_LWIP_RAW ",       "--stk_raw" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_MEM,            " MOD_LEIP_MEM ",       "--stk_mem" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_MEMP,           " MOD_LWIP_MEMP ",      "--stk_memp" /*arg*/, 0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_SYS,            " MOD_LWIP_SYS ",       "--stk_sys" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TIMERS,         " MOD_LWIP_TIMERS ",    "--stk_timers" /*arg*/,   0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP,            " MOD_LWIP_TCP ",       "--stk_tcp" /*arg*/,      0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_INPUT,      " MOD_LWIP_TCP_INPUT ", "--stk_tcp_input" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_FR,         " MOD_LWIP_TCP_FR ",    "--stk_fr" /*arg*/,       0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_RTO,        " MOD_LWIP_TCP_RTO ",   "--stk_tcp_rto" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_CWND,       " MOD_LWIP_TCP_CWND ",  "--stk_tcp_cwnd" /*arg*/, 0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_WND,        " MOD_LWIP_TCP_WND ",   "--stk_tcp_wnd" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_OUTPUT,     " MOD_LWIP_TCP_OUTPUT ","--stk_tcp_output" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_RST,        " MOD_LWIP_TCP_RST ",   "--stk_tcp_rst" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_QLEN,       " MOD_LWIP_TCP_QLEN ",  "--stk_tcp_qlen" /*arg*/, 0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCPIP,          " MOD_LWIP_TCPIP ",     "--stk_tcpip" /*arg*/,    0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_MPTCP_TXRX,     " MOD_LWIP_MPTCP_TXRX ","--stk_mp_txrx" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_MPTCP_FIN,      " MOD_LWIP_MPTCP_FIN ", "--stk_mp_fin" /*arg*/,   0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_MPTCP,          " MOD_LWIP_MPTCP ",     "--stk_mp" /*arg*/,       0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_ERROR_LOGGING,  " MOD_LWIP_ERROR_LOGGING ", "--stk_err_logging" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_MPTCP_TXRX_DTL, " MOD_LWIP_MPTCP_TXRX_DTL ","--stk_mp_txrx_dtl" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_MPTCP_PROXY,    " MOD_LWIP_MPTCP_PROXY ",   "--stk_mp_proxy" /*arg*/,     0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TCP_TWO_STACK,  " MOD_LWIP_TCP_TWO_STACK ", "--stk_tcp_two_stack" /*arg*/,0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_TRAFFIC,        " MOD_LWIP_TRAFFIC ",   "--stk_traffic" /*arg*/,  0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_STREAM_ALL,     " MOD_LWIP_STREAM_ALL ","--stk_stream_all" /*arg*/,   0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)  \
    LOG_MOD_ITEM(E_LOG_LWIP_SACK,           " MOD_LWIP_SACK ",      "--stk_sack" /*arg*/,     0 /*DEBUG*/, 0 /*INFO*/,0 /*WAR*/,0 /*ERR*/,0 /*FATAL*/)


enum {
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  lev,
    LOG_MODULES
#undef LOG_MOD_ITEM
    E_LOG_MODULE_MAX
};

extern const char *g_log_modules_str[E_LOG_MODULE_MAX];
extern int g_log_level_ctrl[E_LOG_LEV_MAX][E_LOG_MODULE_MAX];
extern int g_log_level_ctrl_def[E_LOG_LEV_MAX][E_LOG_MODULE_MAX];

#define LOG_MODULE_CURRENT  0

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef enum __bool {
    FALSE = 0,
    TRUE = 1
} BOOL;


#if !LINUX_PLATFORM
#include <android/log.h>

#define LogDefault(...)  	do { \
                               if (unlikely( g_log_level_ctrl[E_LOG_LEV_DEBUG][LOG_MODULE_CURRENT] )) { \
							   __android_log_print(ANDROID_LOG_DEBUG, g_log_modules_str[LOG_MODULE_CURRENT] ,__VA_ARGS__); \
                                 } \
                             } while(0);


//#define LogI(...) __android_log_print(ANDROID_LOG_DEBUG,"VpnServiceDemoNative",__VA_ARGS__)



#define LogI(...)           do { \
							   if (unlikely( g_log_level_ctrl[E_LOG_LEV_INFO][LOG_MODULE_CURRENT] )) { \
							   __android_log_print(ANDROID_LOG_INFO, g_log_modules_str[LOG_MODULE_CURRENT] ,__VA_ARGS__); \
                                 } \
                             } while(0);

#define LogD(...)           do { \
                               if (unlikely( g_log_level_ctrl[E_LOG_LEV_DEBUG][LOG_MODULE_CURRENT] )) { \
							   __android_log_print(ANDROID_LOG_DEBUG, g_log_modules_str[LOG_MODULE_CURRENT] ,__VA_ARGS__); \
                                 } \
                             } while(0);

#define LogW(...)           do { \
                               if (unlikely( g_log_level_ctrl[E_LOG_LEV_WARN][LOG_MODULE_CURRENT] )) { \
							   __android_log_print(ANDROID_LOG_WARN, g_log_modules_str[LOG_MODULE_CURRENT] ,__VA_ARGS__); \
                                 } \
                             } while(0);

#define LogE(...)           do { \
                               if (likely( g_log_level_ctrl[E_LOG_LEV_ERR][LOG_MODULE_CURRENT] )) { \
							   __android_log_print(ANDROID_LOG_ERROR, g_log_modules_str[LOG_MODULE_CURRENT] ,__VA_ARGS__); \
                                 } \
                             } while(0);

#define LogF(...)           do { \
                               if (likely( g_log_level_ctrl[E_LOG_LEV_FATAL][LOG_MODULE_CURRENT] )) { \
							   __android_log_print(ANDROID_LOG_FATAL, g_log_modules_str[LOG_MODULE_CURRENT] ,__VA_ARGS__); \
                                 } \
                             } while(0);


#define __E_LOG_LEV_DEBUG(...) __android_log_print(ANDROID_LOG_DEBUG, g_log_modules_str[E_LOG_LEV_DEBUG] ,__VA_ARGS__);
#define __E_LOG_LEV_INFO(...) __android_log_print(ANDROID_LOG_INFO, g_log_modules_str[E_LOG_LEV_INFO] ,__VA_ARGS__);
#define __E_LOG_LEV_WARN(...) __android_log_print(ANDROID_LOG_WARN, g_log_modules_str[E_LOG_LEV_WARN] ,__VA_ARGS__);
#define __E_LOG_LEV_ERR(...) __android_log_print(ANDROID_LOG_ERROR, g_log_modules_str[E_LOG_LEV_ERR] ,__VA_ARGS__);
#define __E_LOG_LEV_FATAL(...) __android_log_print(ANDROID_LOG_FATAL, g_log_modules_str[E_LOG_LEV_FATAL] ,__VA_ARGS__);

#define LogM(lev, module, message)   do { \
                                       if (likely( g_log_level_ctrl[lev][module] )) { \
                                            __##lev(message); \
                                         } \
                                     } while(0);

#define LogL(lev, message) do { \
                               if (likely( g_log_level_ctrl[lev][LOG_MODULE_CURRENT] )) { \
							        __##lev(message); \
                                 } \
                             } while(0);

#else

#ifdef printf
#undef printf
#endif


#include <syslog.h>
#include <stdio.h>

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static int log_out(char* flog, char *file, int line, char* fmt, ...)
{
    va_list arg;
	char	pre[128] = {0}, tmp[1024] = {0};
	long	clock;
    struct	tm *c_ptr;
	FILE	*fp;
	char filename[256] = {0};
	char *dir_str = NULL;
	char buff1[32]={0};
	
	time( &clock );
    c_ptr = localtime(&clock);
	sprintf( pre, "[%04d%02d%02d%02d%02d%02d_%s.%d]",
	     c_ptr->tm_year+1900, c_ptr->tm_mon+1, c_ptr->tm_mday,
	     c_ptr->tm_hour, c_ptr->tm_min, c_ptr->tm_sec, file, line );
    va_start(arg, fmt);
	vsprintf(tmp, fmt, arg);
    va_end (arg);
	//log to stdout
	if( !flog ){
		printf( "%-32.32s  %s\r\n", pre, tmp );
		return 0;
	}
	//log to file
	/*if(flog == NULL){

	   strftime(filename, sizeof(buff1), "%s/trace-%Y-%m-%d-%H%M%S.log", LOG_FILE,localtime(&clock));

	   free(dir_str);
	   flog = (char *)(&filename[0]);
	}*/
	if( !(fp = fopen( flog, "at" ) ) )	return -1;
	fprintf( fp, "%-32.32s  %s\r\n", pre, tmp );
	fclose( fp );
	
    return 0;
}



#define LOG_FILE "/home/huawei/mptcp_linux_master/log/a.log"
#define LOG_DEFAULT( fmt, ... )			log_out( LOG_FILE, __FILE__, __LINE__, fmt,##__VA_ARGS__)
#define LOG_TOXFILE( flog, fmt, ... )	log_out( flog, __FILE__, __LINE__, fmt,##__VA_ARGS__)

/*
#define LogE(format,...) syslog(LOG_ERR,format,##__VA_ARGS__)
#define LogW(format,...) syslog(LOG_ERR,format,##__VA_ARGS__)
*/

#define LogI(...)
#define LogD(...)
#define LogE LOG_DEFAULT
#define LogW LOG_DEFAULT

#endif




#endif
