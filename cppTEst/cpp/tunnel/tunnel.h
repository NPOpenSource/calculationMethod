#ifndef __TUNNNEL_H__
#define __TUNNNEL_H__

#include <pthread.h>
#include "../mccp/mccp.h"
#include "../tools/tools.h"
#include "../tools/common.h"
#include "lwip/module.h"

/* used for test*/

/* used for test*/

#define MUTP_FIX_HEADER_LEN 4
struct pbuf;
struct netif;


typedef struct __mutp_fix_header {
    UINT8 icheck:1;
    UINT8 spare:4;
    UINT8 version:3;

    UINT8 type;
    UINT16 len;
} mutp_fix_header;

typedef struct __mutp_header {
    mutp_fix_header fix_header;
    union {
        struct {
            UINT32 tunnel_id;
            UINT32 identity_check;
        } tc;
        UINT32 tunnel_id;
    } msg;
} mutp_header;

typedef enum __TRType {
    WIFI,
    LTE
} TRType;

typedef enum __DataFlowType {
	
    WIFI_UP_PACKAGE,
	WIFI_UP_BYTES,
	WIFI_DOWN_PACKAGE,
	WIFI_DOWN_BYTES,
    LTE_UP_PACKAGE,
	LTE_UP_BYTES,
	LTE_DOWN_PACKAGE,
	LTE_DOWN_BYTES,
	UDP_WIFI_UP_BYTES,
	UDP_WIFI_DOWN_BYTES,
	UDP_LTE_UP_BYTES,
	UDP_LTE_DOWN_BYTES
	
} DataFlowType;

typedef struct __mutp_data{
    UINT8 data[12];
    int len;
}mutp_data;


#ifdef __cplusplus
extern "C" {
#endif
extern int isSetWifiAddr;
extern int isSetLteAddr;
extern int iswificon;
extern int isltecon;
void testSend();
int mutp_setWifiAddr(const char *ip);
int mutp_setLteAddr(const char *ip);
int create_socket_internal(void *instance,JNIEnv* env,TRType type);
int create_wifi_socket_ext(void *instance,JNIEnv* env,int ipaddr,int port);
int create_lte_socket_ext(void *instance,JNIEnv* env,int ipaddr,int port);
int close_wifi_socket(void *instance,int ipaddr,int port);
int close_all_wifi_socket(void *instance);
int mutp_init_Info_of_server(UINT32 mpgwIp, UINT16 port, UINT32 tunnel_id);
void *mutp_recv(void *data);
int mutp_start_recv(void *instance, struct netif *pNetIf);
int icmp_start_recv(void *instance);
int mutp_encode_send(void *instance,int ipaddr,int port,struct pbuf *buf, int messageType);
/*
int mutp_decode_recv(void *instance,UINT8 *pMsg, ssize_t len,BOOL mptp_or_tun_flag,int fd);
void handle_first_version(void *instance,UINT8 *pMsg, ssize_t len, mutp_header *pHeader,BOOL mptp_or_tun_flag);
*/
int mutp_destory(void *instance);
void icmp_destroy(void *instance);
void mutp_all_instance_destory(void);
void mutp_close_wifi_or_lte(unsigned int isWiFi);

void tunnel_init(struct module_conext *pTunnelModuleContext);
void tunnel_deinit(struct module_conext *pTunnelModuleContext);

void testMainFunc(JNIEnv *env);
int tun_send_tunnel_input(void *instance, struct pbuf *buf);
void icmp_init(void *instance, JNIEnv *env);
void *icmp_recv(void *data);
int trans_mutp_init();
unsigned short cal_chksum(unsigned short *buff,int Size);
int tunnel_debug_counter(void *instance, char *pBuffer, unsigned int len);
void mutp_get_dataflow_bytype(DataFlowType eDataFlowType, int *data );
void fillMutpHeaderNormal(void *data, int messageType);
int getTunnelFd(void *instance,int isLte);
struct sockaddr_in *getTunnelDestAddr(void *instance,int isLte);
#ifdef __cplusplus
}
#endif
#endif //__TUNNNEL_H__
