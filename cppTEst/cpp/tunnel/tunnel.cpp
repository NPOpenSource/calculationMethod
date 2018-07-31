/*===========================================================================


                         tunnel.c

DESCRIPTION

 this file is used for tunnel module

EXTERNALIZED FUNCTIONS



Copyright (c) 2017.04 - 2017.05 by Thundersoft Technologies,
Incorporated.  All Rights Reserved.
===========================================================================*/

#include "tunnel.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/lwipopts.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../test/test.h"
#include "../vpn_tun/vpn_tun_if.h"
#include "../mptcp/proxy/nolock.h"
#include "../heartbeat/heartbeat.h"
#if HEARTBEAT_SUPPORT_v02
#include "../heartbeat/Heartbeat_v02.h"
#endif
#include<map>
#include<string>
#include <semaphore.h>
#include <pthread.h>
#include <lwip/prot/tcp.h>
#include <lwip/mptcp/mptcp_proxy.h>
#include "../udp/udp_handle.h"
#include "../tools/tools.h"
#include "../mptcp/lwip/src/include/lwip/timeouts.h"

#if LINUX_PLATFORM
#include "linux/linux_stub.h"
#endif

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_UDP

#define MUTP_MUTX_LOCK \
        pthread_mutex_lock(&pTunnelConext->mutp_lock);
        //LogW("enter mutp lock line:%d",__LINE__);


#define MUTP_MUTX_UNLOCK \
        pthread_mutex_unlock(&pTunnelConext->mutp_lock);
        //LogW("exit mutp lock line:%d",__LINE__);\



#define C_MUTP_LEN 8//client mutp length

//#define DEBUG_DATA

UINT32 mutp_tunnel_id;
/*pthread_mutex_t mutp_lock;*/
static mutp_data mutp_data_header;



struct sockaddr_in ser_addr;
/*
struct sockaddr_in wcli_addr;
struct sockaddr_in lcli_addr;
struct sockaddr_in icmp_ser_addr;
*/


/*
int mutp_lte_fd = 0;
int mutp_wifi_fd = 0;
*/

char mutp_lte_ip[18] = {0};
char mutp_wifi_ip[18] = {0};

int isSetWifiAddr = 0;
int isSetLteAddr = 0;

#define NO_LOCK_LIST 0
#if WIFI_LTE_SWITCH
heartbeat_header tunnel_heartbeat;
void heartbeat_tunnel_init(UINT32 tunnel_id);
void heartbeat_tunnel_sends_value(int sock_fd, UINT32 dst_ip, UINT16 dst_port);
#endif

/*
std::map<std::string,int> wifi_sock_map;
extern struct netif mptcp_proxy_client_netif;
*/
/* used for test send */
void testSend();

void *mutp_recv(void *data);
int icmp_init_env(void *instance,JNIEnv *env);
void *icmp_recv(void *data);
static void init_mutp_data();
int mutp_decode_recv(void *instance,pbuf *p, ssize_t len,BOOL mptp_or_tun_flag,int fd);
void handle_first_version(void *instance,pbuf *p, ssize_t len, mutp_header *pHeader,BOOL mptp_or_tun_flag,int fd);
extern void aprintf(const char* format, ...);
/*sem_t tunnelTransSem;*/
unsigned int debug_run_once = 0;
int lwip_debug_main(void *instance,JNIEnv* env, u16_t PORT);
static void input_pkt1(struct netif *netif, struct pbuf *p, struct tunnel_context *pTunnelConext);

struct tunnel_context {
#if NO_LOCK_LIST
    struct queue *pTiQue;
	sem_t tunnelTransSem;
#endif
	int stillRun;
	int mutp_lte_fd;
    int mutp_wifi_fd;
	int icmp_recv_flag;
	int icmp_lteSocket;
	pthread_mutex_t mutp_lock;
	struct sockaddr_in wcli_addr;
	struct sockaddr_in lcli_addr;
	sockaddr_in icmp_ser_addr;
	sockaddr_in lte_ser_addr;
	sockaddr_in wifi_ser_addr;
	int wifi_receive;
	int lte_receive;
	std::map<u64_t,int> *wifi_sock_map;
    struct netif *mptcp_proxy_client_netif;
	int sock_fd_sets[MEMP_NUM_NETCONN];
	int sock_fd_num;
	int wifi_recv_cnt;
	int wifi_send_cnt;
	int lte_recv_cnt;
	int lte_send_cnt;
	int wifi_recv_bytes;
	int wifi_send_bytes;
	int lte_recv_bytes;
	int lte_send_bytes;
	int udp_wifi_recv_bytes;
	int udp_wifi_send_bytes;
	int udp_lte_recv_bytes;
	int udp_lte_send_bytes;
       int instanceId;
#if LINUX_PLATFORM || WIFI_LTE_SWITCH
    int seed_id;
    u16_t udp_port;
	u16_t use_current_port;
#endif
    u16_t pkgcount;
    struct pbuf* start;
    struct pbuf* end;
};

void tunnel_init(struct module_conext *pTunnelModuleContext)
{
   struct tunnel_context *pTunnelContext;

   pTunnelModuleContext->pCcontext = malloc(sizeof(struct tunnel_context));
   
   memset(pTunnelModuleContext->pCcontext, 0x0, sizeof(struct tunnel_context));
   pTunnelContext = (struct tunnel_context *)pTunnelModuleContext->pCcontext;
   pTunnelContext->stillRun  = 1;
   pTunnelContext->mutp_lte_fd = -1;
   pTunnelContext->icmp_lteSocket = 0;
   pTunnelContext->mutp_wifi_fd = -1;
   pTunnelContext->icmp_recv_flag = 0;
   pTunnelContext->wifi_receive = 0;
   pTunnelContext->lte_receive = 0;

   pTunnelContext->wifi_recv_cnt = 0;
   pTunnelContext->wifi_send_cnt = 0;
   pTunnelContext->lte_recv_cnt = 0;
   pTunnelContext->lte_send_cnt = 0;
   pTunnelContext->wifi_recv_bytes= 0;
   pTunnelContext->wifi_send_bytes = 0;
   pTunnelContext->lte_recv_bytes= 0;
   pTunnelContext->lte_send_bytes= 0;

   /*pTunnelContext->mutp_lock = PTHREAD_MUTEX_INITIALIZER;*/
   pthread_mutex_init(&pTunnelContext->mutp_lock, NULL);
   
   pTunnelContext->wifi_sock_map = new std::map<u64_t ,int>();
#if NO_LOCK_LIST
   pTunnelContext->pTiQue = queueCreate((char*)"Ti",4096);
   sem_init(&pTunnelContext->tunnelTransSem,0,0);
#endif
   pTunnelContext->instanceId =get_instance_logic_id(get_instance_context(CONTEXT_TUNNEL_TYPE,pTunnelModuleContext));
   #if LINUX_PLATFORM || WIFI_LTE_SWITCH
   pTunnelContext->seed_id = get_instance_logic_id(get_instance_context(CONTEXT_TUNNEL_TYPE,pTunnelModuleContext));
   pTunnelContext->udp_port = 0;
   #endif
#if HEARTBEAT_SUPPORT_v02
   /* only in the instance 0 start heartbeat*/
   if(pTunnelContext->instanceId == 0){
       //__android_log_print(ANDROID_LOG_DEBUG,"VpnServiceDemoNative","start heart beat");
       HeartBeatInit(get_instance(0));
   }
#endif

}

void tunnel_deinit(struct module_conext *pTunnelModuleContext)
{
	struct tunnel_context *pTunnelContext = (struct tunnel_context *)pTunnelModuleContext->pCcontext;
	
//	isSetLteAddr = 0;
//	isSetWifiAddr = 0;
	debug_run_once = 0;

#if HEARTBEAT_SUPPORT	
	heartbeat_deinit();
#endif
#if NO_LOCK_LIST
	if(pTunnelContext->pTiQue != NULL)
	{
	    free(pTunnelContext->pTiQue);
		pTunnelContext->pTiQue = NULL;
	}
#endif
#if HEARTBEAT_SUPPORT_v02
        if(pTunnelContext->instanceId == 0){
            //__android_log_print(ANDROID_LOG_DEBUG,"vpn","heart beat exit");
            HeartBeatDestory();
        }
#endif

    delete pTunnelContext->wifi_sock_map;
    FREE(pTunnelModuleContext->pCcontext);
}

struct tunnel_context *get_tunnel_context(void *instance){
	struct lwip_instance *pstInstance;
	struct module_conext *pTunnelModuleContext;
	struct tunnel_context *pTcpContext;

	if(instance != NULL)
	{
		pstInstance = (struct lwip_instance *)instance;
		pTunnelModuleContext = &pstInstance->module_conext[CONTEXT_TUNNEL_TYPE];
		return (struct tunnel_context *)pTunnelModuleContext->pCcontext;
	}
	return NULL;
}

#if LINUX_PLATFORM || WIFI_LTE_SWITCH
#define TUNNEL_UDP_LOCAL_PORT_RANGE_START  9000
#define TUNNEL_UDP_LOCAL_PORT_RANGE_SIZE   2048
static u16_t ucp_new_port(void *instance)
{
  u16_t n = 0;
  struct tunnel_context *pTunnelContext = get_tunnel_context(instance);
  u16_t start_port = (TUNNEL_UDP_LOCAL_PORT_RANGE_START + (u16_t)(pTunnelContext->seed_id*TUNNEL_UDP_LOCAL_PORT_RANGE_SIZE));
  u16_t end_port = start_port + TUNNEL_UDP_LOCAL_PORT_RANGE_SIZE;
  

  if(pTunnelContext->udp_port == 0)
  	pTunnelContext->udp_port = start_port;
  if (pTunnelContext->udp_port++ == end_port) {
    pTunnelContext->udp_port = start_port;
  }

  return pTunnelContext->udp_port;
}
#endif

/*===========================================================================

  FUNCTION
  mutp_setWifiAddr

  DESCRIPTION
  get the wifi addr from java

  PARAMETERS
  char *ip the java send the ip cross the jni

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int mutp_setWifiAddr(const char *ip) {
    if (ip == NULL) {
        LogE("wifi IP error:%p", ip);
        memset(mutp_wifi_ip,0,sizeof(mutp_wifi_ip));
        return -1;
    }
    LogI("Current wifi ip is:%s", ip);
    isSetWifiAddr = 1;
    memset(mutp_wifi_ip, 0, sizeof(mutp_wifi_ip));
    if (strlen(ip) > 0 && strlen(ip) < sizeof(mutp_lte_ip)) {
        memcpy(mutp_wifi_ip, ip, strlen(ip));
    } else {
        LogE("LTE IP error:%p", ip);
        return -1;
    }
    return 0;
}

/*===========================================================================

  FUNCTION
  mutp_setLteAddr

  DESCRIPTION
  get the lte addr from java

  PARAMETERS
  char *ip the java send the ip cross the jni

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int mutp_setLteAddr(const char *ip) {
    if (ip == NULL) {
        LogE("LTE IP error %p", ip);
        memset(mutp_lte_ip,0,sizeof(mutp_lte_ip));
        return -1;
    }
    LogI("Current lte ip is :%s", ip);
    //mutp_lte_ip = (char *) ip;
    isSetLteAddr = 1;
    memset(mutp_lte_ip, 0, sizeof(mutp_lte_ip));
    if (strlen(ip) > 0 && strlen(ip) < sizeof(mutp_lte_ip)) {
        memcpy(mutp_lte_ip, ip, strlen(ip));
    } else {
        LogE("LTE IP error:%p", ip);
        return -1;
    }
    return 0;
}

/*===========================================================================

  FUNCTION
  create_wifi_socket_internal

  DESCRIPTION
  create wifi socket internal for trans data
  call this function you need to assure the wifi or lte is OK

  PARAMETERS
  JNIEnv* env      if this is the main thread,we need a env to call native method work.
  int ipaddr       ip address for subflow server
  int port         ip port for subflow server
  int flag         create wifi or lte,lte 0,wifi other

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int create_socket_internal(void *instance,JNIEnv* env,TRType type)
{
#if !LINUX_PLATFORM
    unsigned short tunnel_udp_port = 5000;
#endif
    int id,ret = 0;
#ifdef LARGE_PACKET
    int udp_buf_size = 8388480; /* 8M */
#else
    int udp_buf_size = 4194304; /* 4M */
#endif
    struct tunnel_context *pTunnelContext= get_tunnel_context(instance);
    int wifiSocket = socket(AF_INET, SOCK_DGRAM, 0);
    LogE("wifiSocket is %d", wifiSocket);
    ENTER_FUNC;

    struct sockaddr_in addr;
    if (wifiSocket < 0) {
        LogE("error create fd for subflow the data");
        return -1;
    }
    ret = protectFd(env, wifiSocket);
    if (ret != 0) {
        close(wifiSocket);
        return -1;
    }
    if(type == LTE)
    {
        LogE("LTE addr:%s",mutp_lte_ip);
        addr.sin_addr.s_addr =  inet_addr(mutp_lte_ip); //lte address
    }
    else {
        LogE("wifi addr:%s",mutp_wifi_ip);
        addr.sin_addr.s_addr = inet_addr(mutp_wifi_ip); //wifi address
    }
    addr.sin_family = AF_INET;
#if !WIFI_LTE_SWITCH
    addr.sin_port = 0;
#else
    //addr.sin_port = htons(ucp_new_port(instance));
    addr.sin_port = 0;
    LogE("udp port is %d", addr.sin_port);
#endif
    #if !LINUX_PLATFORM
    *addr.__pad = '\0';
	#else
	addr.sin_port = htons(ucp_new_port(instance));
	#endif
#if WIFI_LTE_SWITCH
    int port_reuse =1;
    if(setsockopt(wifiSocket, SOL_SOCKET, SO_REUSEPORT,&port_reuse,
                  sizeof(port_reuse)) == -1){
        LogE("%s:%d: setsockopt() port reuse failed error:%d", __func__, __LINE__, errno);
    }
#endif
    LogE("current create tunnel socket ip dest:%s, port:%d", inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
    ret = bind(wifiSocket, (struct sockaddr *) &addr, sizeof(addr));
    if (ret != 0) {
        LogE("bind fd port fails,random a port,and try again");
        close(wifiSocket);
        return -1;
    }
    LogI("bind ip %s and fd %d ", inet_ntoa(addr.sin_addr), wifiSocket);

	if(type == LTE)
	{
	    if(pTunnelContext != NULL)
			memcpy(&pTunnelContext->lcli_addr,&addr, sizeof(struct sockaddr_in));
	}
	else
	{
	    if(pTunnelContext != NULL)
		    memcpy(&pTunnelContext->wcli_addr,&addr, sizeof(struct sockaddr_in));
	}

    if(setsockopt(wifiSocket, SOL_SOCKET, SO_RCVBUF, &udp_buf_size,
                  sizeof(udp_buf_size)) == -1){
        LogE("%s:%d: setsockopt() recvbuf failed, errno=%d", __FUNCTION__, __LINE__, errno);
    }
				  
	udp_buf_size = 8388480; /* 4M */
				  
    if(setsockopt(wifiSocket, SOL_SOCKET, SO_SNDBUF, &udp_buf_size,
    			sizeof(udp_buf_size)) == -1){
      LogE("%s:%d: setsockopt() failed, errno=%d", __FUNCTION__, __LINE__, errno);
    }

    EXIT_FUNC;
    return wifiSocket;
}

/*===========================================================================

  FUNCTION
  create_wifi_socket_ext

  DESCRIPTION
  used for create subflow

  PARAMETERS
  int ipaddr    ip address of sbuflow server
  int port      port of subflow server
  JNIEnv* env   if this is the main thread,we need a env to call native method work.
                if not in main thread,it need be null to attach the jvm to create java env
  int flag      0 create with lte,other create with wifi,it's need wifi or lte open

  RETURN VALUE
  if return -1, call this function fails
  return the socket if exit,if not exsit create one to return

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int create_wifi_socket_ext(void *instance, JNIEnv* env,int ipaddr,int port)
{
#if !WIFI_LTE_SWITCH
    char tempkey[64]={0};
    int fd = -1;
    int ret = 0;
    u64_t key = 0;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);
	
    ENTER_FUNC;
    //sprintf(tempkey,"%d%d",ipaddr,port);
    key = port;
    key = ipaddr + (key << 32);
    if(isSetWifiAddr == 0)
    {
        LogW("please sure the the wifi is Open!");
        return -1;
    }
    MUTP_MUTX_LOCK;
    
	std::map<u64_t,int>::iterator it = pTunnelConext->wifi_sock_map->find(key);

    if(it == pTunnelConext->wifi_sock_map->end())
    {
        ret = bindNetworkToHandlePacketThoughtJava(0, isSetWifiAddr);
        if (ret == -1) {
            LogE("bind process fails! exit the function! FILE:%s,LINE:%d", __FILE__, __LINE__);
            pTunnelConext->wifi_sock_map->erase(key);
            goto End;
        }
        fd = create_socket_internal(instance,env,WIFI);
        if(fd > 0)
        {
            LogE("storage the wifi fd:%d",fd);
//            wifi_sock_map.insert(std::pair<std::string,int>(tempkey,fd));
//            LogE("storage the wifi fd:%d",wifi_sock_map[tempkey]);
//            wifi_sock_map.insert(std::make_pair(tempkey,fd));
//            LogE("storage the wifi fd:%d",wifi_sock_map[tempkey]);
//            wifi_sock_map.insert(std::map<std::string,int>::value_type(tempkey,fd));
//            LogE("storage the wifi fd:%d",wifi_sock_map[tempkey]);
            pTunnelConext->wifi_sock_map->insert(std::make_pair(key,fd));
        }
        else{
            pTunnelConext->wifi_sock_map->erase(key);
        }
    } else
        fd = it->second;
    End:
    MUTP_MUTX_UNLOCK;
    EXIT_FUNC;
    return fd;
#else
    int ret = 0;
    //int i = 0;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);

    ret = bindNetworkToHandlePacketThoughtJava(0, isSetWifiAddr);
    if (ret == -1) {
        LogE("bind process fails! exit the function! FILE:%s,LINE:%d", __FILE__, __LINE__);
        return 0;
    }
    if(isSetWifiAddr == 0)
    {
        LogW("please sure the the wifi is open");
        return -1;
    }
    pTunnelConext->mutp_wifi_fd = create_socket_internal(instance,env,WIFI);
    LogD("mutp_wifi_fd:%d",pTunnelConext->mutp_wifi_fd);
    LogD("heartbeat on wifi");
    //for(i=0;i<1;i++)
    //heartbeat_tunnel_sends_value(pTunnelConext->mutp_wifi_fd, ppca_s->mccp_mpgw_ip1, ppca_s->mccp_mpgw_port);

    return pTunnelConext->mutp_wifi_fd;
#endif
}

/*===========================================================================

  FUNCTION
  create_lte_socket_ext

  DESCRIPTION
  create lte socket

  PARAMETERS
  int ipaddr    ip address of master flow server
  int port      port of master server
  JNIEnv* env   if this is the main thread,we need a env to call native method work.
                if not in main thread,it need be null to attach the jvm to create java env
  int flag      0 create with lte,other create with wifi,it's need wifi or lte open

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int create_lte_socket_ext(void *instance,JNIEnv* env,int ipaddr,int port)
{
    int ret = 0;
    //int i=0;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);
	
    ret = bindNetworkToHandlePacketThoughtJava(isSetLteAddr, 0);
    if (ret == -1) {
        LogE("bind process fails! exit the function! FILE:%s,LINE:%d", __FILE__, __LINE__);
        return 0;
    }
    if(isSetLteAddr == 0)
    {
        LogW("please sure the the lte is open");
        return -1;
    }
    pTunnelConext->mutp_lte_fd = create_socket_internal(instance,env,LTE);
    LogD("mutp_lte_fd:%d",pTunnelConext->mutp_lte_fd);
#if WIFI_LTE_SWITCH
    LogD("heartbeat on lte");
    //for(i=0;i<1;i++)
    //heartbeat_tunnel_sends_value(pTunnelConext->mutp_lte_fd, ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port);
#endif
    return pTunnelConext->mutp_lte_fd;
}

/*===========================================================================

  FUNCTION
  close_wifi_socket

  DESCRIPTION
  close wifi socket by ipaddr and port

  PARAMETERS
  int ipaddr ip address need to close
  int port   ip port to need to be close

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int close_wifi_socket(void *instance,int ipaddr,int port)
{
    char tmpkey[64] = { 0 };
    int ret = -1;
    u64_t key =0;
	struct tunnel_context *pTunnelConext = get_tunnel_context(instance);
    key = ipaddr + ((u64_t)port <<32);
    //sprintf(tmpkey,"%d%d",ipaddr,port);
	std::map<u64_t ,int>::iterator it = pTunnelConext->wifi_sock_map->find(key);
    if(it != pTunnelConext->wifi_sock_map->end())
    {
        ret  = close(it->second);
    }
#if WIFIFD_OPT
    pTunnelConext->mutp_wifi_fd = -1 ;
#endif
    return ret;
}

/*===========================================================================

  FUNCTION
  close_all_wifi_socket

  DESCRIPTION
  close all wifi socket to clear the environment

  PARAMETERS

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int close_all_wifi_socket(void *instance)
{
#if !WIFI_LTE_SWITCH
    int ret = 0;
	struct tunnel_context *pTunnelConext = get_tunnel_context((struct lwip_instance *)instance);

    ENTER_FUNC;
	if(pTunnelConext == NULL)
	{
	    return 0;
	}
	
    MUTP_MUTX_LOCK;
    for(std::map<u64_t ,int>::iterator it = pTunnelConext->wifi_sock_map->begin();it!=pTunnelConext->wifi_sock_map->end();it++)
    {
        ret = close(it->second);
        if(ret != 0)
        {
            LogW("close socket:%d fails",it->second);
        } else{
            LogW("close socket:%d",it->second);
        }
    }
    pTunnelConext->wifi_sock_map->clear();
#if WIFIFD_OPT
    pTunnelConext->mutp_wifi_fd = -1;
#endif
    MUTP_MUTX_UNLOCK;
    EXIT_FUNC;
    return 0;
#else
    int ret = 0;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);

    if(pTunnelConext == NULL)
    {
        return 0;
    }
    LogD("close wifi socket:%d ",pTunnelConext->mutp_wifi_fd);
    if(pTunnelConext->mutp_wifi_fd > 0)
    {
        ret = close(pTunnelConext->mutp_wifi_fd);
        pTunnelConext->mutp_wifi_fd = -1;
    }

    LogD("close wifi socket:%d OK ",pTunnelConext->mutp_wifi_fd);
    return ret;

#endif
}

/*===========================================================================

  FUNCTION
  mutp_init_Info_of_server

  DESCRIPTION
  this function should be call when PCA is success immediately

  PARAMETERS
  UINT32 mpgwIp       mpgw IP address
  UINT16 port         mpgw port
  UINT32 tunnel_id    tunnel id

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  init the mutp server info when PCA have been accept success

  SIDE EFFECTS
  None
===========================================================================*/
int mutp_init_Info_of_server(UINT32 mpgwIp, UINT16 port, UINT32 tunnel_id) {
    int ret = 0;
    if (mpgwIp == 0 || port < 1024 || tunnel_id == 0) {
        LogE("the server info is not correct,mpgwip:%d,port:%d,tunnel_id:%d", mpgwIp, port,
             tunnel_id);
        return 0;
    }
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = mpgwIp;
    ser_addr.sin_port = htons(port);
    mutp_tunnel_id = tunnel_id;
    LogI("mpgw serip:%s", inet_ntoa(ser_addr.sin_addr));
    LogI("mutp init with port:%d", port);
    LogI("mutp init with tunnel id:0x%x or %d", tunnel_id, tunnel_id);
    init_mutp_data();
#if HEARTBEAT_SUPPORT	
	heartbeat_init_mutp_data(tunnel_id);
#endif
#if WIFI_LTE_SWITCH
    heartbeat_tunnel_init(ppca_s->mccp_tunnel_id);
#endif
    return 0;
}

/*===========================================================================

  FUNCTION
  mutp_recv

  DESCRIPTION
  this is thread function used to accpt the data from the server

  PARAMETERS
  None

  RETURN VALUE
  None

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
void *mutp_lte_recv(void *data) {
    fd_set recvSet;
    int ret = 0;
    UINT8 buf[1500];
    size_t len = sizeof(buf);
    ssize_t readLen = 0;
    socklen_t clen = 0;
    struct timeval times;
    int maxfd = -1;
	struct pbuf *p = NULL;
	void *instance = data;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);

    global_set_thread_instance(instance);
    create_lte_socket_ext(instance,NULL, ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port);
	p = pbuf_alloc(instance,PBUF_RAW, 1536, PBUF_POOL);
    while (pTunnelConext->stillRun) {
        
        FD_ZERO(&recvSet);
        if(isSetLteAddr) {
            FD_SET(pTunnelConext->mutp_lte_fd, &recvSet);
            maxfd = pTunnelConext->mutp_lte_fd;
        }
		if(pTunnelConext->icmp_recv_flag){
			FD_SET(pTunnelConext->icmp_lteSocket, &recvSet);
			if(maxfd < pTunnelConext->icmp_lteSocket){
				maxfd = pTunnelConext->icmp_lteSocket;
			}
		}
        times.tv_sec = 2;
        times.tv_usec = 0;
        LogI("reset the fd set,and wait for data");
        ret = select(maxfd+ 1, &recvSet, NULL, NULL, &times);
        switch (ret) {
            case -1:
                break;
            case 0:

                break;
            default:
                if(isSetLteAddr)
                {
                    if(FD_ISSET(pTunnelConext->mutp_lte_fd,&recvSet))
                    {
                    		        
                        /*readLen = recvfrom(mutp_lte_fd, buf, len, 0, (struct sockaddr *) &wcli_addr,
                                           &clen);*/
                        readLen = recvfrom(pTunnelConext->mutp_lte_fd, p->payload, TCP_MSS, 0, (struct sockaddr *) &pTunnelConext->wcli_addr,
                                           &clen);
                        if (readLen <= 0 ) {
                            LogE("read the mutp lte fd:%d fails", pTunnelConext->mutp_lte_fd);
                            continue;
                        }
						p->len = readLen;
						pTunnelConext->lte_recv_cnt++;
						pTunnelConext->lte_recv_bytes += readLen;
                        mutp_decode_recv(instance,p, readLen,TRUE,pTunnelConext->mutp_lte_fd);
						p = pbuf_alloc(instance,PBUF_RAW, 1536, PBUF_POOL);
						if( p == NULL){
							goto END;
						}
                    }
                }

				if(pTunnelConext->icmp_recv_flag)
				{
				    if(FD_ISSET(pTunnelConext->icmp_lteSocket,&recvSet))
					{
				        mutp_decode_recv(instance, p, readLen,FALSE,pTunnelConext->icmp_lteSocket);
						/*p pbuf reserved for next recieve*/
					}
				}
                break;
        }

    }

END:
	if(p != NULL){
		pbuf_free(p);
	}
    return NULL;
}

void *mutp_wifi_recv(void *data) {
    fd_set recvSet;
    int ret = 0;
    UINT8 buf[1500];
    size_t len = sizeof(buf);
    ssize_t readLen = 0;
    socklen_t clen = 0;
    struct timeval times;
    int maxfd = -1;
	struct pbuf *p;
	void *instance = data;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);

	global_set_thread_instance(instance);

	p = pbuf_alloc(instance,PBUF_RAW, 1536, PBUF_POOL);
    while (pTunnelConext->stillRun) {
        
        FD_ZERO(&recvSet);
        MUTP_MUTX_LOCK;
        for(std::map<u64_t,int>::iterator it= pTunnelConext->wifi_sock_map->begin();it != pTunnelConext->wifi_sock_map->end();it++) {
            //the second is the fd
            if(it->second == 0)
            {
                continue;
            }
            FD_SET(it->second,&recvSet);
            if(it->second>maxfd)
            {
                maxfd = it->second;
            }
            LogI("set recvSet fd:%d",it->second);
        }
        MUTP_MUTX_UNLOCK;
        times.tv_sec = 2;
        times.tv_usec = 0;
        LogI("reset the fd set,and wait for data");
        ret = select(maxfd+ 1, &recvSet, NULL, NULL, &times);
        switch (ret) {
            case -1:
                break;
            case 0:
                break;
            default:
                MUTP_MUTX_LOCK;
                for(std::map<u64_t,int>::iterator it = pTunnelConext->wifi_sock_map->begin();it != pTunnelConext->wifi_sock_map->end();it++)
                {
                    if(it->second == 0)
                    {
                        continue;
                    }

                    if (FD_ISSET(it->second, &recvSet)) {
                        LogI("taoning recv recvSet fd:%d",it->second);
				        
                        /*readLen = recvfrom(it->second, buf, len, 0, (struct sockaddr *) &wcli_addr,
                                           &clen);*/
                        readLen = recvfrom(it->second, p->payload, 1536, 0, (struct sockaddr *) &pTunnelConext->lcli_addr,
                                           &clen);
                        if (readLen <= 0 ) {
                            LogE("read the mutp wifi fd:%d fails", it->second);
                            continue;
                        }
						pTunnelConext->wifi_recv_cnt++;
						pTunnelConext->wifi_recv_bytes += readLen;
						p->len = readLen;
                        mutp_decode_recv(instance,p, readLen,TRUE,it->second);
						p = pbuf_alloc(instance,PBUF_RAW, 1536, PBUF_POOL);
						if( p == NULL){
							MUTP_MUTX_UNLOCK;
							goto END;
						}

                    }
                }
                MUTP_MUTX_UNLOCK;

                break;
        }

    }
END:
	if(p != NULL){
		pbuf_free(p);
	}

    return NULL;
}

void printStream(char *data,int len)
{
  char *buf = new char[len*3+1];
  for(int i = 0;i< len;i++)
  {
    sprintf(&buf[i*3],"%2x ",data[i]);
    if(data[i]>0 && data[i]<10)
      buf[i*3] = '0';
  }
  LogI("icmp mutp message:%s",buf);
  delete[] buf;
}


int tun_send_tunnel_input(void *instance, struct pbuf *buf)
{
    ssize_t ret = 0;
    socklen_t socklen;
	struct tunnel_context *pTunnelConext = get_tunnel_context(instance);

    socklen = sizeof(pTunnelConext->wifi_ser_addr);
    ret = sendto(pTunnelConext->mutp_wifi_fd, buf->payload, buf->len, 0, (struct sockaddr *) &pTunnelConext->wifi_ser_addr,socklen);
    if (ret == -1) 
	{
        LogE("tun_send_tunnel_input icmp current error:%s", strerror(errno));
    }

	LogI("icmp tun_send_tunnel_input send success.");

#if MUTP_TEST_DEBUG_OUTPUT_DATA
    printStream((char*)buf->payload,buf->len);
#endif

    return 0;
}


/*===========================================================================

  FUNCTION
  mutp_start_recv

  DESCRIPTION
  start the mutp recv thread

  PARAMETERS
  None

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
/*struct queue *pTiQue;*/
void* tunnel_input_thread(void* args);

void *lwip_start_debug(void *data) {
#if LWIP_SHELL_CONSOLE	
	if(debug_run_once > 0){
		return NULL;
	}
	lwip_debug_main(data,NULL,2222);
	debug_run_once = 1;
#endif
	return NULL;
}

int mutp_start_recv(void *instance, struct netif *pNetIf) {
    pthread_t recv_thread;
    pthread_t mutp_input_thread;
    pthread_attr_t attr;
    int i = 0;
	struct tunnel_context *pTunnelContext = get_tunnel_context(instance);

    pTunnelContext->mptcp_proxy_client_netif = pNetIf;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    /*pthread_create(&recv_thread, NULL, mutp_recv, instance);*/
	/*pthread_create(&recv_thread, NULL, mutp_lte_recv, instance);*/
	//sys_thread_new(instance,&attr,"mutp_lte_recv",(lwip_thread_fn)mutp_lte_recv,instance,2048,0);
	/*pthread_create(&recv_thread, NULL, mutp_wifi_recv, instance);*/
	//sys_thread_new(instance,&attr,"mutp_wifi_recv",(lwip_thread_fn)mutp_wifi_recv,instance,2048,0);
    sys_thread_t t =sys_thread_new(instance,&attr,"mutp_recv",(lwip_thread_fn)mutp_recv,instance,2048,0);
	upThreadPro(&t->pthread);
    /*pthread_create(&mutp_input_thread,NULL,tunnel_input_thread,instance);*/
	//sys_thread_new(instance,&attr,"tunnel_input_thread",(lwip_thread_fn)tunnel_input_thread,instance,2048,0);
#if HEARTBEAT_SUPPORT
	heartbeat_init(
	&pTunnelContext->mutp_wifi_fd,
	&pTunnelContext->mutp_lte_fd,
	&pTunnelContext->wifi_ser_addr,
	&pTunnelContext->lte_ser_addr,
	&pTunnelContext->stillRun,
	&pTunnelContext->wifi_receive,
	&pTunnelContext->lte_receive);	
#endif

#if LWIP_SHELL_CONSOLE
    sys_thread_new(instance,&attr,"lwip_debug",(lwip_thread_fn)lwip_start_debug,instance,2048,0);
#endif

    return 0;
}
/**
 * call this func after tunnel id have been inital
 */
static void init_mutp_data()
{
    mutp_header header;
    mutp_header *pHeader = &header;
    UINT8 messageType = 0;
    memset(pHeader, 0, sizeof(mutp_header));
    pHeader->fix_header.version = 0x01;
    pHeader->fix_header.icheck = 0x00;

    pHeader->fix_header.type = messageType;

    pHeader->fix_header.len = 0;

    pHeader->msg.tc.tunnel_id = htonl(mutp_tunnel_id);
    mutp_data_header.len = C_MUTP_LEN;
    memcpy(mutp_data_header.data,pHeader,C_MUTP_LEN);
}
#define MUTP_VERSION 1
void fillMutpHeaderNormal(void *data, int messageType) {
    struct pbuf *buf = (struct pbuf *)data;
    mutp_header *pHeader = (mutp_header *)buf->payload;
    pHeader->fix_header.version = MUTP_VERSION;
    pHeader->fix_header.icheck = 0x00;
    pHeader->fix_header.type = messageType;
    pHeader->fix_header.len = htons(buf->len);
    pHeader->msg.tc.tunnel_id = htonl(mutp_tunnel_id);
}

/*===========================================================================

  FUNCTION
  mutp_encode_send

  DESCRIPTION
  Encode the data to be send

  PARAMETERS
  struct pbuf *buf  the message

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int mutp_encode_send(void *instance,int ipaddr,int port,struct pbuf *buf, int messageType) {
    ssize_t ret = 0;
    socklen_t socklen;
    u64_t  key = 0;
    int fd = -1;
	struct sockaddr_in *pClient_SockAddr_in;
	struct sockaddr_in *pSockAddr_in;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);
	struct ip_hdr *ip = (struct ip_hdr *)((u8_t *)buf->payload); 

    if (pbuf_header(buf, C_MUTP_LEN)) {
        LogE("mutp_encode_send: not enough room for mutp header in pbuf\n");
        return ERR_BUF;
    }
    /*bufPtr = (unsigned char *)buf->payload - C_MUTP_LEN;
	buf->len += C_MUTP_LEN;*/
    fillMutpHeaderNormal(buf, messageType);
    /*buf->payload = (void *)bufPtr;*/
    //LogE("isSetLteAddr:%d isSetWifi:%d ipaddr:%d",isSetLteAddr,isSetWifiAddr,ipaddr);
    if(ipaddr == ppca_s->mccp_mpgw_ip)
    {
        if(likely(isSetLteAddr)){

			pSockAddr_in = &pTunnelConext->lte_ser_addr;
            pSockAddr_in->sin_addr.s_addr = ppca_s->mccp_mpgw_ip;
			pClient_SockAddr_in = &pTunnelConext->lcli_addr;
			/*ser_addr.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;*/
#if WIFI_LTE_SWITCH
            if (unlikely(pTunnelConext->mutp_lte_fd <= 0)) {
                pTunnelConext->mutp_lte_fd = create_lte_socket_ext(instance,NULL, ipaddr, port);
                if (pTunnelConext->mutp_lte_fd < 0) {
                    LogE("Create lte socket fail :%s", strerror(errno));
                    return -1;
                }
                LogI("Create new lte socket :%d", pTunnelConext->mutp_lte_fd);
            }

#endif
	   fd = pTunnelConext->mutp_lte_fd;
        }else{
            LogE("LTE have been close!");
            return -1;
        }
    }
    else
#if !WIFI_LTE_SWITCH
    {
        if(isSetWifiAddr) {
#if WIFIFD_OPT
			if (pTunnelConext->mutp_wifi_fd <= 0 )
			{
				fd = create_wifi_socket_ext(instance,NULL, ppca_s->mccp_mpgw_ip1, ppca_s->mccp_mpgw_port);
				if (fd < 0) {
					LogE("Create wifi socket fail :%s", strerror(errno));
					return -1;
				}
				pTunnelConext->mutp_wifi_fd = fd;

			}
			fd = pTunnelConext->mutp_wifi_fd;
            pSockAddr_in = &pTunnelConext->wifi_ser_addr;
			pSockAddr_in->sin_addr.s_addr = (__be32) ipaddr;
			pClient_SockAddr_in = &pTunnelConext->wcli_addr;
#if LINUX_PLATFORM
			add_datalink_dynamic_route(1,inet_ntoa(pSockAddr_in->sin_addr));
#endif

#else

            key = ppca_s->mccp_mpgw_ip1 + (ppca_s->mccp_mpgw_port << 32);
            MUTP_MUTX_LOCK;
            std::map<u64_t , int>::iterator iter = pTunnelConext->wifi_sock_map->find(key);
            if (pTunnelConext->wifi_sock_map->end() != iter) {
                fd = iter->second;
            }
            MUTP_MUTX_UNLOCK;
            LogI("find wifi map fd:%d", fd);
			pSockAddr_in = &pTunnelConext->wifi_ser_addr;
			pSockAddr_in->sin_addr.s_addr = (__be32) ipaddr;
			pClient_SockAddr_in = &pTunnelConext->wcli_addr;
			
            if (fd <= 0) {
                fd = create_wifi_socket_ext(instance,NULL, ipaddr, port);
                if (fd < 0) {
                    LogE("Create wifi socket fail :%s", strerror(errno));
                    return -1;
                }
				#if LINUX_PLATFORM
				add_datalink_dynamic_route(1,inet_ntoa(pSockAddr_in->sin_addr));
				#endif
                LogI("Create new wifi socket :%d", fd);
            }
			pTunnelConext->mutp_wifi_fd = fd;
#endif			
        }
        else{
            LogE("current WIFI have been close");
            return -1;
        }
    }
#else
    if(isSetWifiAddr){

        pSockAddr_in = &pTunnelConext->wifi_ser_addr;
        pSockAddr_in->sin_addr.s_addr = ppca_s->mccp_mpgw_ip1;
        pClient_SockAddr_in = &pTunnelConext->lcli_addr;
        /*ser_addr.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;*/
        if (unlikely(pTunnelConext->mutp_wifi_fd <= 0)) {
            pTunnelConext->mutp_wifi_fd = create_wifi_socket_ext(instance,NULL, ipaddr, port);
            if (pTunnelConext->mutp_wifi_fd < 0) {
                LogE("Create wifi socket fail :%s", strerror(errno));
                return -1;
            }
#if LINUX_PLATFORM
			add_datalink_dynamic_route(1,inet_ntoa(pSockAddr_in->sin_addr));
#endif
            LogI("Create new wifi socket :%d", pTunnelConext->mutp_wifi_fd);
        }
        fd = pTunnelConext->mutp_wifi_fd;
    }else{
        LogE("wifi have been close!");
        return -1;
    }
#endif
    pSockAddr_in->sin_port = ppca_s->mccp_mpgw_port;
#if 0
    if(messageType == 1){
        fd = pTunnelConext->mutp_lte_fd;
        pSockAddr_in = &pTunnelConext->lte_ser_addr;
        pSockAddr_in->sin_addr.s_addr = ppca_s->mccp_mpgw_ip;
        pClient_SockAddr_in = &pTunnelConext->lcli_addr;
        /*ser_addr.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;*/
        pSockAddr_in->sin_port = ppca_s->mccp_mpgw_port;
    }
#endif
    /*ser_addr.sin_port = (u16_t)port;*/
    
    //LogD("mutp_encode_send:%s current send server ip :%s, local port:%d, server port:%d, len:%d", (ipaddr == ppca_s->mccp_mpgw_ip)?"LTE":"WiFi", inet_ntoa(pSockAddr_in->sin_addr), ntohs(pClient_SockAddr_in->sin_port),ntohs(pSockAddr_in->sin_port),buf->len);

    socklen = sizeof(struct sockaddr_in);
    //LogE("mutp_encode_send fd is %d", fd);
    ret = sendto(fd, buf->payload, buf->len, 0, (struct sockaddr *)pSockAddr_in, socklen);
    if (unlikely(ret == -1)) {
        LogE("mutp encode send current error:%s", strerror(errno));
    }else
    {

		if(ipaddr == ppca_s->mccp_mpgw_ip)
		{
				if(IPH_PROTO(ip ) == IP_PROTO_TCP)
				{
				    pTunnelConext->lte_send_cnt++;
					pTunnelConext->lte_send_bytes += ret;
				}
				else  if(IPH_PROTO(ip ) == IP_PROTO_UDP)
				{
				   pTunnelConext->udp_lte_send_bytes += ret;
				}
		}
		else
		{
			 	if(IPH_PROTO(ip ) == IP_PROTO_TCP)
			 	{
			        pTunnelConext->wifi_send_cnt++;
					pTunnelConext->wifi_send_bytes += ret;
				}
				else if(IPH_PROTO(ip ) == IP_PROTO_UDP)
				{
			        pTunnelConext->udp_wifi_send_bytes += ret;
				}

		}
	}

#if MUTP_TEST_DEBUG_OUTPUT_DATA
    printStream((char*)buf->payload,buf->len);
#endif

    return 0;
}

/*===========================================================================

  FUNCTION
  mutp_decode_recv

  DESCRIPTION
  decode the recv msg.

  PARAMETERS
  UINT8 *pMsg   message
  ssize_t len

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int mutp_decode_recv(void *instance,pbuf *p, ssize_t len,BOOL mptp_or_tun_flag,int fd) {
    //mutp_header header;
    mutp_header *pmutpHeader = NULL;
    int i = 0;
	UINT8 *pMsg = (UINT8 *)p->payload;
	struct tunnel_context *pTunnelConext = get_tunnel_context((struct lwip_instance *)instance);
    ENTER_FUNC;
    if (unlikely(pMsg == NULL || len < 8)) {
        LogE("decode the mutp code message is not correct pMsg:%p,len:%d", pMsg, (int) len);
        LogE("total packet %s", pMsg);
        return -1;
    }
    //LogI("total packet %s used for debug", pMsg);
#ifdef DEBUG_DATA
    for(i = 0;i<len;i++)
    {
        LogI("recv data[%d]:%x",i,pMsg[i]);
    }
#endif
    pmutpHeader = (mutp_header *) pMsg;
    pmutpHeader->fix_header.len = ntohs(pmutpHeader->fix_header.len);
    //LogI("message[0]:%x",pMsg[0]);
    //LogI("mutp version:%d",pmutpHeader->fix_header.version);
#if (HEARTBEAT_SUPPORT || HEARTBEAT_SUPPORT_v02)
    switch(pmutpHeader->fix_header.type)
    {
        case ECHO_IND:
        case ECHO_REQUEST:
        case ECHO_RESPONSE: 
			/*mutp*/
			if(fd == pTunnelConext->mutp_lte_fd)
			{
			    /*lte*/
				pTunnelConext->lte_receive = 1;
			}
			else if(fd == pTunnelConext->mutp_wifi_fd)
			{
			    /*wifi*/
			    pTunnelConext->wifi_receive = 1; 
			}
			pbuf_free(p);
			p = NULL;
			break;
			
	  default:  
#endif
	    switch (pmutpHeader->fix_header.version) {
	        case 1:
	            handle_first_version(instance,p, len, pmutpHeader,mptp_or_tun_flag,fd);
	            break;
	        case 2:
	            LogI("current version 2 of mutp is not support!");
	            break;
	        default:
	            LogI("Are you sure you use this version! but we don't support!");
	            break;
	    }
#if (HEARTBEAT_SUPPORT ||HEARTBEAT_SUPPORT_v02)
	}
#endif
    EXIT_FUNC;
    return 0;
}

static void input_pkt1(struct netif *netif, struct pbuf *p, struct tunnel_context *pTunnelConext)
{
    err_t err;
    struct pbuf *next;
    do{
       err = netif->input(p, netif);
       if(!pTunnelConext->stillRun){
          break;
       }
    }while(likely(err!=ERR_OK));
    if (likely(err != ERR_OK)) {
#if SEND_MSG_BATCH
        while(p){
           next = p->next;
           free(p);
           p = next;
        }
#else
        pbuf_free(p);
#endif
    }
}

#if NO_LOCK_LIST
void* tunnel_input_thread(void* args){
    struct pbuf *pMsg;
    void *instance = args;
	struct tunnel_context *pTunnelConext = get_tunnel_context((struct lwip_instance *)instance);

	global_set_thread_instance(instance);
    LogE("tunnel_input_thread run");
    while(pTunnelConext->stillRun){
        if((pMsg = (struct pbuf *)Deque(pTunnelConext->pTiQue)) != NULL){
            input_pkt1(pTunnelConext->mptcp_proxy_client_netif,pMsg,pTunnelConext);
        }
    }
    sem_wait(&pTunnelConext->tunnelTransSem);
    destoryQue(pTunnelConext->pTiQue);
	pTunnelConext->pTiQue = NULL;
    sem_desotry(&pTunnelConext->tunnelTransSem);
    return NULL;
}
#endif

/*===========================================================================

  FUNCTION
  handle_first_version

  DESCRIPTION
  handle the first version of the message

  PARAMETERS
  UINT8 *pMsg,
  ssize_t len,
  mutp_header *pHeader

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
void handle_first_version(void *instance,pbuf *p, ssize_t len, mutp_header *pHeader,BOOL mptp_or_tun_flag,int fd) {
    UINT8 *pMsg = (UINT8 *)p->payload;
	struct tunnel_context *pTunnelConext = get_tunnel_context((struct lwip_instance *)instance);
	struct ip_hdr *ip = (struct ip_hdr *)((u8_t *)p->payload + C_MUTP_LEN);	
	if (unlikely(pHeader == NULL || pMsg == NULL || len < C_MUTP_LEN)) {
        LogI("current messsage is not a mutp message!");
        return;
    }
    //LogI("mutp icheck %d",pHeader->fix_header.icheck);
    if (likely(pHeader->fix_header.icheck == 0)) {

        pHeader->msg.tunnel_id = ntohl(pHeader->msg.tunnel_id);
        //LogI("tunnel id:%d",pHeader->msg.tunnel_id);
        if (likely(pHeader->msg.tunnel_id == mutp_tunnel_id)) {
            //handle this message!
            pMsg = pMsg + C_MUTP_LEN;
#if PACKET_DEBUG
            int i =0;
            for (i = 0; i < len-8;i++ )
              LogI("%x", pMsg[i]);
#endif
            if(likely(IPH_PROTO(ip ) == IP_PROTO_TCP))
                mptp_or_tun_flag = TRUE;
            else
                mptp_or_tun_flag = FALSE;

			if(likely(mptp_or_tun_flag == TRUE))
			{	
				/*mutp*/
				if(fd == pTunnelConext->mutp_lte_fd)
				{
					/*lte*/
					pTunnelConext->lte_recv_cnt++;
					pTunnelConext->lte_recv_bytes += len;

				}
				else if(fd == pTunnelConext->mutp_wifi_fd)
				{
					/*wifi*/
					pTunnelConext->wifi_recv_cnt++;
					pTunnelConext->wifi_recv_bytes += len;

				}
			
				#if 0
				struct ip_hdr *iph;
                                struct tcp_hdr *tcph;
				iph = (struct ip_hdr*)pMsg;
                                tcph = (struct tcp_hdr *)(iph+1);

				LogD("handle_first_version instance=%p, src ip=%s dst ip=%s source port=%d dest port=%d len=%d\r\n",instance,
                     ip4addr_ntoa((ip4_addr_t *)(&iph->src)),ip4addr_ntoa((ip4_addr_t *)(&iph->dest)), ntohs(tcph->src),ntohs(tcph->dest),
                     p->len - C_MUTP_LEN);

				#endif

				p->tot_len = p->len = (u16_t)len - (u16_t)C_MUTP_LEN;
				p->payload = (void *)pMsg;
				
				#if NO_LOCK_LIST
                while(!Enque(pTunnelConext->pTiQue,p)){
                    if(!pTunnelConext->stillRun){
                        sem_post(&pTunnelConext->tunnelTransSem);
                    }
                }
				#else
				
				if(likely(p->len > 40)){
			    #if LWIP_PCAP_SUPPORT
				tun_write_pcap(vpn_pcap_fd, (char *)p->payload, ((int)p->len), LWIP_PCAP_TUNNEL_DOWN_STRAM);
				#endif
				
				#if SEND_MSG_BATCH

                    if(pTunnelConext->start != NULL)
                    {
                        pTunnelConext->end->next = p;
                        pTunnelConext->end = p;
                        pTunnelConext->pkgcount++;
                    }
                    else
                    {
                        pTunnelConext->start = pTunnelConext->end = p;
                        pTunnelConext->pkgcount = 1;
                    }
	                if(pTunnelConext->pkgcount > 10){
	                    pTunnelConext->pkgcount = 0;
	                    input_pkt1(pTunnelConext->mptcp_proxy_client_netif,pTunnelConext->start, pTunnelConext);
	                    pTunnelConext->start = pTunnelConext->end = NULL;
	                }				
				#else
					input_pkt1(pTunnelConext->mptcp_proxy_client_netif,p, pTunnelConext);
				#endif
				}
				else
				{
				   pbuf_free(p);
				}
				#endif
				

			}
			else
			{
				LogI("icmp write to tun0");

				struct ip_hdr* temp;
				struct dataPacket *dataPack;
				temp = (struct ip_hdr*)pMsg;
				temp->dest.addr = inet_addr("10.0.2.0");//TUN_IP
				temp->_chksum = 0;
				temp->_chksum = cal_chksum((unsigned short *) pMsg, sizeof(struct ip_hdr));

                p->tot_len = p->len = p->tot_len - (u16_t)C_MUTP_LEN;
                p->payload = (unsigned char*)p->payload + C_MUTP_LEN;
			#if HEARTBEAT_SUPPORT

				if(ip->src.addr == ppca_s->mccp_mpgw_ip)
				{
					/*lte*/
				    if(IPH_PROTO(ip ) == IP_PROTO_UDP)
					{
						pTunnelConext->udp_lte_recv_bytes += len;
					}
				
				}
				else
				{
					/*wifi*/
					if(IPH_PROTO(ip ) == IP_PROTO_UDP)
					{
						pTunnelConext->udp_wifi_recv_bytes += len;
					}
				
				}
			#endif

#if LWIP_UDP_THROUGH_HAG
                if (IPH_PROTO(ip ) == IP_PROTO_UDP) {
                    struct udphdr *udphdr;
                    udphdr = (struct udphdr *) (pMsg + sizeof(struct ip_hdr));
                    if((ntohs(temp->_offset)&IP_OFFMASK) == 0) {
                        udphdr->chksum = 0;
                    }
                }
#endif
#if LWIP_TCP_ZEROCOPY
			    vpn_tun_device_write_pbuf(p);
#else

                //vpn_tun_device_write(pMsg, (len));
                pbuf_ref(p);
                vpn_tun_write_pubf(p);
			    pbuf_free(p);
#endif
			}
            return;
        } else {
            LogI("current msg tunnel id is not match!");
            return;
        }
    }

    //LogI("current not support to handle icheck");
    return;
}

/*===========================================================================

  FUNCTION
  close_lte_socket

  DESCRIPTION
  close lte mutp fd

  PARAMETERS
  None

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int close_lte_socket(void *instance)
{
    int ret = 0;
	struct tunnel_context *pTunnelConext = get_tunnel_context((struct lwip_instance *)instance);

	if(pTunnelConext == NULL)
	{
	    return 0;
	}
    LogD("close lte socket:%d ",pTunnelConext->mutp_lte_fd);
    if(pTunnelConext->mutp_lte_fd > 0)
    {
        ret = close(pTunnelConext->mutp_lte_fd);
        pTunnelConext->mutp_lte_fd = -1;
    }
    LogD("close lte socket:%d OK",pTunnelConext->mutp_lte_fd);
    return ret;
}

void mutp_all_instance_destory(void)
{
    struct lwip_instance *instance;
	struct tunnel_context *pTunnelContext;
	
    for(int i=0;i<MAX_INSTANCE_NUM;i++)
    {
       instance = get_instance(i);
	  
	   if(instance != NULL){
	   	 pTunnelContext = get_tunnel_context((struct lwip_instance *)instance);
		 if(pTunnelContext)
		 {
			 pTunnelContext->stillRun = 0;
		 }
		 usleep(5000);
		 
	     mutp_destory(instance);
	   }
    }
}

void mutp_close_wifi_or_lte(unsigned int isWiFi)
{
    struct lwip_instance *instance;
	
    for(int i=0;i<MAX_INSTANCE_NUM;i++)
    {
       instance = get_instance(i);
	   if(instance != NULL){
	   if(isWiFi)
	   	   close_all_wifi_socket(instance);
	   else
	       close_lte_socket(instance);
	   }
    }

}

/*===========================================================================

  FUNCTION
  mutp_destory

  DESCRIPTION
  when the app exit or exception ,call this function to close

  PARAMETERS
  None

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int mutp_destory(void *instance) {
    /*
	char buf[512]={0};
	
	tunnel_debug_counter(instance, buf, 512);
	LogE("Tunnel counter list:\r\n%s",buf);
	*/
	int ret = 0;
	struct tunnel_context *pTunnelConext = (struct tunnel_context *)get_tunnel_context((struct lwip_instance *)instance);
       isSetWifiAddr = 0;
       isSetLteAddr = 0;
	if(pTunnelConext)
	{
		pTunnelConext->stillRun = 0;
	    ret = close_lte_socket(instance);
	    if(ret != 0){
	         LogE("close lte socket fails");
	    }
	    ret = close_all_wifi_socket(instance);
	    if(ret != 0){
	         LogE("close wifi socket fails");
	    }
	}
    return ret;
}

int tunnel_debug_counter(void *instance, char *pBuffer, unsigned int len)
{
	struct module_conext *pModuleContext;
	struct tunnel_context *pTunnelContext;
	int nPos = 0,offset=0;

	if(instance != NULL){
	   pModuleContext = &(((struct lwip_instance *)instance)->module_conext[CONTEXT_NAT_TYPE]);
	   pTunnelContext = (struct tunnel_context *)pModuleContext->pCcontext;

       offset = 0;
	   nPos = snprintf(pBuffer,len,"Tunnel wifi send	=	0x%08x\r\n",pTunnelContext->wifi_send_cnt);
	   offset += nPos;
	   
	   nPos = snprintf(pBuffer+offset,(len - offset),"Tunnel wifi recv	=	0x%08x\r\n",pTunnelContext->wifi_recv_cnt);
	   offset += nPos;
	   
	   nPos = snprintf(pBuffer+offset,(len - offset),"Tunnel lte send	=	0x%08x\r\n",pTunnelContext->lte_send_cnt);
	   offset += nPos;

	   nPos = snprintf(pBuffer+offset,(len - offset),"Tunnel lte recv	=	0x%08x\r\n",pTunnelContext->lte_recv_cnt);
	   offset += nPos;
	}

    return offset;
}


void mutp_get_dataflow_bytype(DataFlowType eDataFlowType, int *data )
{
    struct lwip_instance *instance;
	struct tunnel_context *pTunnelContext;

	if( NULL == data)
	{
		return ;
	}
	
    for(int i=0;i<MAX_INSTANCE_NUM;i++)
    {
        instance = get_instance(i);
	  
	   if(instance != NULL)
	   	{
	   	    pTunnelContext = get_tunnel_context((struct lwip_instance *)instance);

			if( NULL != pTunnelContext)
			{
                 if( eDataFlowType ==  WIFI_UP_PACKAGE)
             	 {
                    *data += pTunnelContext->wifi_send_cnt;
				 }
				 else if( eDataFlowType ==  WIFI_UP_BYTES)
             	 {
                    *data += pTunnelContext->wifi_send_bytes;
				 }
				 else if( eDataFlowType ==  WIFI_DOWN_PACKAGE)
             	 {
                    *data += pTunnelContext->wifi_recv_cnt;
				 }
				 else if( eDataFlowType ==  WIFI_DOWN_BYTES)
             	 {
                    *data += pTunnelContext->wifi_recv_bytes;
				 }
				 else if( eDataFlowType ==  LTE_UP_PACKAGE)
             	 {
                    *data += pTunnelContext->lte_send_cnt;
				 }
			     else if( eDataFlowType ==  LTE_UP_BYTES)
             	 {
                    *data += pTunnelContext->lte_send_bytes;
				 }
			     else if( eDataFlowType ==  LTE_DOWN_PACKAGE)
             	 {
                    *data += pTunnelContext->lte_recv_cnt;
				 }
				 else if( eDataFlowType ==  LTE_DOWN_BYTES)
             	 {
                    *data += pTunnelContext->lte_recv_bytes;
				 }
				 else if( eDataFlowType ==  UDP_LTE_UP_BYTES)
             	 {
                    *data += pTunnelContext->udp_lte_send_bytes;
				 }
			     else if( eDataFlowType ==  UDP_LTE_DOWN_BYTES)
             	 {
                    *data += pTunnelContext->udp_lte_recv_bytes;
				 }
				 else if( eDataFlowType ==  UDP_WIFI_UP_BYTES)
             	 {
                    *data += pTunnelContext->udp_wifi_send_bytes;
				 }
			     else if( eDataFlowType ==  UDP_WIFI_DOWN_BYTES)
             	 {
                    *data += pTunnelContext->udp_wifi_recv_bytes;
				 }
				
		    }
		 		
	   }
    }
}
extern u32_t tickGet(void *instance);

void *mutp_recv(void *data) {
    fd_set recvSet;
    int ret = 0;
    ssize_t readLen = 0;
    socklen_t clen = 0;
    void *instance = data;
    pbuf *p;
    struct timeval times;
    int maxfd = -1;
    int wcont = 0;
#if HEARTBEAT_SUPPORT_v02
    long heartbeatCheckStartTime = 0;
    long heartbeatCheckEndTime = 0;
#endif
	struct sockaddr_in *cli_addr = NULL;
	int hdr_len = sizeof(struct ip_hdr)+ sizeof(struct tcp_hdr) + sizeof(mutp_header)*2;
    struct tunnel_context *pTunnelConext = get_tunnel_context(instance);
	
#if LINUX_PLATFORM
	struct sockaddr_in *pSockAddr_in = &pTunnelConext->wifi_ser_addr;
#endif
	
	#if SEND_MSG_BATCH
    pTunnelConext->pkgcount = 0;//getCTime();
	#endif
    global_set_thread_instance(instance);
#if !WIFI_LTE_SWITCH
    create_lte_socket_ext(instance,NULL, ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port);
#endif

    char name[40]={ 0 };
    sprintf(name,"mutp_recv:%d ",get_instance_logic_id(instance));
    setThreadName(name);
	
#if LARGE_PACKET
    p = pbuf_alloc(instance,PBUF_RAW, TCP_MSS+100, PBUF_RAM);
#else
    p = pbuf_alloc(instance,PBUF_RAW, TCP_MSS + 2*hdr_len, PBUF_RAM);
#endif

    while (likely(p && pTunnelConext->stillRun)) {

        FD_ZERO(&recvSet);
#if WIFI_LTE_SWITCH
		if(unlikely(isSetLteAddr && pTunnelConext->mutp_lte_fd <= 0)){
			create_lte_socket_ext(instance,NULL, ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port);
			LogD("create lte socket");
		}

		if(unlikely(isSetWifiAddr && pTunnelConext->mutp_wifi_fd <= 0 )){
			create_wifi_socket_ext(instance,NULL, ppca_s->mccp_mpgw_ip1, ppca_s->mccp_mpgw_port);
			LogD("create wifi socket");
#if LINUX_PLATFORM
			pSockAddr_in->sin_addr.s_addr = (__be32) ppca_s->mccp_mpgw_ip1;
			add_datalink_dynamic_route(1,inet_ntoa(pSockAddr_in->sin_addr));
#endif
		}
#endif
	
#if (WIFIFD_OPT || WIFI_LTE_SWITCH)
		wcont = 0;
		maxfd = 0;
		if(likely(isSetLteAddr && pTunnelConext->mutp_lte_fd > 0)) {
			FD_SET(pTunnelConext->mutp_lte_fd, &recvSet);
			maxfd = pTunnelConext->mutp_lte_fd;
			pTunnelConext->sock_fd_sets[wcont] = pTunnelConext->mutp_lte_fd;
			wcont ++;
		}
		if(likely(isSetWifiAddr && pTunnelConext->mutp_wifi_fd > 0)) {
			FD_SET(pTunnelConext->mutp_wifi_fd, &recvSet);
			maxfd = (maxfd < pTunnelConext->mutp_wifi_fd)?pTunnelConext->mutp_wifi_fd:maxfd;
			pTunnelConext->sock_fd_sets[wcont] = pTunnelConext->mutp_wifi_fd;
			wcont ++;
		}
		pTunnelConext->sock_fd_num = wcont;
#else
        MUTP_MUTX_LOCK;

		wcont = 0;
        if(isSetLteAddr) {
            if(pTunnelConext->mutp_lte_fd > 0) {
                FD_SET(pTunnelConext->mutp_lte_fd, &recvSet);
                maxfd = pTunnelConext->mutp_lte_fd;
                pTunnelConext->sock_fd_sets[wcont] = pTunnelConext->mutp_lte_fd;
                wcont++;
            }
        }

        for(std::map<u64_t ,int>::iterator it= pTunnelConext->wifi_sock_map->begin();it != pTunnelConext->wifi_sock_map->end();it++)
        {
            //the second is the fd
            if(!pTunnelConext->stillRun){
				break;
            }
            if(it->second == 0)
            {
                continue;
            }
            FD_SET(it->second,&recvSet);
			pTunnelConext->sock_fd_sets[wcont] = it->second;
			wcont++;
            if(it->second>maxfd)
            {
                maxfd = it->second;
            }
            /*LogI("set recvSet fd:%d",it->second);*/
        }

		pTunnelConext->sock_fd_num = wcont;
#endif		
        MUTP_MUTX_UNLOCK;
		#if SEND_MSG_BATCH		
        times.tv_sec = 0;
        times.tv_usec = 2000;
		#else
	    times.tv_sec = 2;
        times.tv_usec = 0;
		#endif
        LogI("mutp_recv fd set select,and wait for data");
        ret = select(maxfd+ 1, &recvSet, NULL, NULL, &times);
        switch (ret) {
            case -1:
                break;
            case 0:
#if SEND_MSG_BATCH
                if(pTunnelConext->start != NULL){
                    input_pkt1(pTunnelConext->mptcp_proxy_client_netif,pTunnelConext->start, pTunnelConext);
                    pTunnelConext->pkgcount = 0; //getCTime();
                    pTunnelConext->start = pTunnelConext->end = NULL;
                }
#endif
#if HEARTBEAT_SUPPORT_v02
                heartbeatCheckEndTime = tickGet(instance); //getCTime();
                LogI("current no data, start HeartBeat instance id:%d",pTunnelConext->instanceId);
                if(pTunnelConext->instanceId == 0 && (heartBeatCheckTimeout(heartbeatCheckStartTime,heartbeatCheckEndTime) || heartbeatCheckEndTime == 0 )){
                    LogD("%s: start heartbeat",__func__);
                    setStartHeartBeat(1);
                    heartbeatCheckStartTime = heartbeatCheckEndTime;
                }
#endif
                break;
            default:
				for(wcont=0;wcont<pTunnelConext->sock_fd_num;wcont++)
                {
                    if(!pTunnelConext->stillRun)
                    {
				       break;
                    }
                  
                    if (FD_ISSET(pTunnelConext->sock_fd_sets[wcont], &recvSet)) {
                        /*LogE("recv recvSet fd:%d",it->second);*/
						if(pTunnelConext->mutp_wifi_fd == pTunnelConext->sock_fd_sets[wcont])
							cli_addr =  &pTunnelConext->wcli_addr;
						else
							cli_addr = &pTunnelConext->lcli_addr;
						
                        readLen = recvfrom(pTunnelConext->sock_fd_sets[wcont], p->payload, p->len, 0, (struct sockaddr *)cli_addr,
                                           &clen);
                        if (readLen <= 0 ) {
                            LogE("read the mutp wifi fd:%d fails, wcont is %d", pTunnelConext->sock_fd_sets[wcont], wcont);
                            continue;
                        }
                        /*LogE("wifi recv cnt:%d",wcont++);*/
                        p->len = (u16_t)readLen;
#if MUTP_TEST_DEBUG_OUTPUT_DATA
                        LogI("recv from wifi");
                        printStream((char*)buf,readLen);
#endif
#if TUNNEL_STAT
                        INC(tunnelStat.lte_recv);
                        INC(tunnelStat.total_recv);
#endif
#if HEARTBEAT_SUPPORT_v02
                        LogI("recv response from the Hag");
                        static int index = 0;
                        //if(index ++ < 200){
                        /*if recv packet in any instance, the heartbeat flag need to be clear*/
                        //if(pTunnelConext->instanceId == 0){
                            heartbeatCheckStartTime = tickGet(instance);
                            if(pTunnelConext->mutp_lte_fd == pTunnelConext->sock_fd_sets[wcont]){
                              //LogE("clear lte heartbeat flag");
                              setLteHeartBeat(0);
                            }else{
                              //LogI("clear wifi heartbeat flag");
                              setWifiHeartBeat(0);
                            }
                        //}
                        //}
#endif
                        mutp_decode_recv(instance, p, readLen,TRUE,pTunnelConext->sock_fd_sets[wcont]);
#if LARGE_PACKET
                        p = pbuf_alloc(instance,PBUF_RAW, TCP_MSS+100, PBUF_RAM);
#else
                        p = pbuf_alloc(instance,PBUF_RAW, TCP_MSS+2*hdr_len, PBUF_RAM);
#endif
                        if(unlikely( p == NULL)){
                            goto END;
                        }
                    }
                }
                /*memset(buf, 0, (size_t)readLen);*/

                break;
        }

    }
END:
    if(p != NULL){
        pbuf_free(p);
    }
#if SYS_THREAD_FREE_FUNC
	//extern void sys_thread_free_self();
	//sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
    return NULL;
}

#if LWIP_SHELL_CONSOLE
#define MAXRECVLEN 2048
char cmd_buffer[MAXRECVLEN];

int create_tcp_internal(void *instance,JNIEnv* env,TRType type, u16_t port)
{
    int ret = 0;
	int opt = SO_REUSEADDR;
    int wifiSocket = socket(AF_INET, SOCK_STREAM, 0);
    ENTER_FUNC;

    struct sockaddr_in addr;
    if (wifiSocket < 0) {
        LogE("error create fd for subflow the data");
        return -1;
    }
    ret = protectFd(env, wifiSocket);
    if (ret != 0) {
        close(wifiSocket);
        return -1;
    }
    if(type == LTE)
    {
        LogI("LTE addr:%s",mutp_lte_ip);
        addr.sin_addr.s_addr =  inet_addr(mutp_lte_ip); //lte address
    }
    else {
        LogI("wifi addr:%s",mutp_wifi_ip);
        addr.sin_addr.s_addr = inet_addr(mutp_wifi_ip); //wifi address
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
	#ifndef LINUX_PLATFORM
    *addr.__pad = '\0';
	#endif

    LogE("create_tcp_internal current create tunnel socket ip src:%s", inet_ntoa(addr.sin_addr));
    ret = bind(wifiSocket, (struct sockaddr *) &addr, sizeof(addr));
    if (ret != 0) {
        LogE("bind fd port fails,random a port,and try again");
        close(wifiSocket);
        return -1;
    }
    LogE("create_tcp_internal bind ip %s and fd %d ", inet_ntoa(addr.sin_addr), wifiSocket);

    if(setsockopt(wifiSocket, SOL_SOCKET, SO_REUSEADDR, &opt,
                  sizeof(opt)) == -1){
        LogE("create_tcp_internal %s:%d: setsockopt() failed, errno=%d", __FUNCTION__, __LINE__, errno);
    }

    EXIT_FUNC;
    return wifiSocket;
}

#define NEWLINE "\r\n"

static void send_client_data(const char *str, int fd)
{
	int iRet;
	int sndLen = 0;
	int len = strlen(str);
  
	do{
	  iRet = send(fd, str+sndLen, len - sndLen, 0);
	  if(iRet < 0){
	  	if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN))
			break;
	  }
	  else if(iRet == 0)
	  {
	     return;
	  }
	  else
	  {
	     sndLen += iRet;
	  }
	}while(sndLen < len);
}


#define ESUCCESS 0
#define ESYNTAX -1
#define ETOOFEW -2
#define ETOOMANY -3
#define ECLOSED -4

static void client_cmd_error(s8_t err, int fd)
{
  switch (err) {
  case ESYNTAX:
    send_client_data("## Syntax error\r\n", fd);
    break;
  case ETOOFEW:
    send_client_data("## Too few arguments to command given\r\n", fd);
    break;
  case ETOOMANY:
    send_client_data("## Too many arguments to command given\r\n", fd);
    break;
  case ECLOSED:
    send_client_data("## Connection closed\r\n", fd);
    break;
  default:
    /* unknown error, don't assert here */
    break;
  }
}



struct command {
  int fd;
  s8_t (* exec)(struct command *);
  u8_t nargs;
  char *args[10];
};


static s8_t com_help(struct command *com)
{
  send_client_data("Available commands:\r\n", com->fd);
  return ESUCCESS;
}

static s8_t com_tunnel_conter(struct command *com)
{
   int i,len,get_len;
   void *instance;
   char *buf = (char *)malloc(2048);

   len = 0;
   memset(buf, 0x0,2048);
   for(i=0;i<MAX_INSTANCE_NUM;i++)
   {
        instance = get_instance(i);
		get_len = 0;
	  
	    if(instance != NULL)
	   	{
	   	   get_len = tunnel_debug_counter(instance, buf+len, 2048 - len);
		   len += get_len;
	   	}
  }
  buf[len] = '\r';
  buf[len+1] = '\n';
  len += 2;
  send_client_data(buf, com->fd);
  free(buf);
  return ESUCCESS;
}



static s8_t parse_client_command(struct command *com, u32_t len)
{
  u16_t i;
  u16_t bufp;
  
  if (strncmp((const char *)cmd_buffer, "help", 4) == 0) {
    com->exec = com_help;
    com->nargs = 0;
  }else if (strncmp((const char *)cmd_buffer, "tcnt", 4) == 0){
    com->exec = com_tunnel_conter;
    com->nargs = 0;
  }else if (strncmp((const char *)cmd_buffer, "quit", 4) == 0) {
    LogD("quit\r\n");
    return ECLOSED;
  } else {
    return ESYNTAX;
  }

  if (com->nargs == 0) {
    return ESUCCESS;
  }
  bufp = 0;
  for(; bufp < len && cmd_buffer[bufp] != ' '; bufp++);
  for(i = 0; i < 10; i++) {
    for(; bufp < len && cmd_buffer[bufp] == ' '; bufp++);
    if (cmd_buffer[bufp] == '\r' ||
       cmd_buffer[bufp] == '\n') {
      cmd_buffer[bufp] = 0;
      if (i < com->nargs - 1) {
        return ETOOFEW;
      }
      if (i > com->nargs - 1) {
        return ETOOMANY;
      }
      break;
    }    
    if (bufp > len) {
      return ETOOFEW;
    }    
    com->args[i] = (char *)&cmd_buffer[bufp];
    for(; bufp < len && cmd_buffer[bufp] != ' ' && cmd_buffer[bufp] != '\r' &&
      cmd_buffer[bufp] != '\n'; bufp++) {
      if (cmd_buffer[bufp] == '\\') {
        cmd_buffer[bufp] = ' ';
      }
    }
    if (bufp > len) {
      return ESYNTAX;
    }
    cmd_buffer[bufp] = 0;
    bufp++;
    if (i == com->nargs - 1) {
      break;
    }

  }

  return ESUCCESS;
}

int do_command(int fd, char *buf, int size)
{
	u16_t len = 0, cur_len;
	struct command com;
	s8_t err;
	int i;
	err_t ret;

	memcpy(cmd_buffer, buf,size);
	len = (u16_t)size;
	if (((len > 0) && ((cmd_buffer[len-1] == '\r') || (cmd_buffer[len-1] == '\n'))) ||
		(len >= MAXRECVLEN)) {
	  if (cmd_buffer[0] != 0xff && 
		 cmd_buffer[1] != 0xfe) {
		err = parse_client_command(&com, len);
		if (err == ESUCCESS) {
		  com.fd = fd;
		  err = com.exec(&com);
		}
		if (err == ECLOSED) {
		  LogD("Closed\r\n");
		  send_client_data("console exit", fd);
		  return ECLOSED;
		}
		if (err != ESUCCESS) {
		  client_cmd_error(err, fd);
		}
	  } else {
		send_client_data("\r\nlwIP simple interactive shell.\r\n(c) Copyright 2017, mptcp application project.\r\nWritten by wangyongjun.\r\nFor help, try the \"help\" command.\r\n", fd);
	  }
	  if (ret == ERR_OK) {
		send_client_data("> ", fd);
	  }
	  len = 0;
	}
	return ESUCCESS;  
}

int lwip_debug_main(void *instance,JNIEnv* env, u16_t PORT)
{
    char buf[MAXRECVLEN];
	char printbuf[512];
    int listenfd, connectfd;  
    struct sockaddr_in server; 
    struct sockaddr_in client; 
    socklen_t addrlen = sizeof(struct sockaddr);
	int ret,exitflag;
	int opt,i,iret=-1;
	struct tunnel_context *pTunnelContext = get_tunnel_context((struct lwip_instance *)instance);
	
	ret = bindNetworkToHandlePacketThoughtJava(0, isSetWifiAddr);
	if (ret == -1) 
	{
		LogE("bind process fails! exit the function! FILE:%s,LINE:%d", __FILE__, __LINE__);
		return 1;
	}
	
	listenfd = create_tcp_internal(instance,env,WIFI, PORT);
    if(listen(listenfd, 5) == -1)
    {
        LogE("listen() error. \n");
		close(listenfd);
        return 2;
    }

    addrlen = sizeof(client);
	
	LogE("lwip_debug_main begin running...\r\n");

		
	memset(cmd_buffer, 0x0,sizeof(cmd_buffer));	
 
    while(pTunnelContext->stillRun)
	{
        if((connectfd = accept(listenfd,(struct sockaddr *)&client, &addrlen))==-1)
        {
            LogE("lwip_debug_main accept() error. \n");
            close(listenfd);
			return 3;
        }
        
		ret = protectFd(env, connectfd);
		if (ret != 0) {
            close(connectfd);
			LogE("lwip_debug_main protectFd() error. \n");
            continue;
        }
		LogE("lwip_debug_main accept() client socket=%d. \n",connectfd);
		opt = 1;
#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif
		//setsockopt(connectfd, IPPROTO_TCP, TCP_NODELAY, (void*)&opt, sizeof(opt));
#undef TCP_NODELAY

		send_client_data("Welcome to lwip debug console!\n\0", connectfd);
        while(pTunnelContext->stillRun)
        {
            iret = recv(connectfd, buf, MAXRECVLEN, 0);
            if(iret > 0)
            {
                exitflag = do_command(connectfd, buf, iret);
				/*if(iret > 512)
					iret = 400;
				for(i=0,opt=0;opt<iret;opt++){
					printbuf[opt] = '0'+buf[i];
					printbuf[opt+1] = ' ';
					opt += 2;
					if((opt+1)%16 == 0){
						printbuf[opt+1] = '\n';
						opt += 1;
					}
					i++;
				}
				printbuf[opt+1] = 0;
				LogE("lwip_debug_main recv data:\r\n %s",printbuf);
				*/
            }
			else if( iret == 0) 
            {
                exitflag = ECLOSED;
            }
			else
			{
			   continue;
			}
            
            if(exitflag == ECLOSED){
                close(connectfd);
				connectfd = -1;
                break;
            }

         }
		 if(connectfd != -1)
		 	close(connectfd);
    }
    close(listenfd); 
    return 0;
}
#endif

int getTunnelFd(void *instance,int isLte){
    struct lwip_instance *pInstance = (struct lwip_instance*)instance;
    struct tunnel_context *pTunnelContext = get_tunnel_context(instance);
    if(!pTunnelContext) return -1;
    return isLte ? pTunnelContext->mutp_lte_fd:pTunnelContext->mutp_wifi_fd;
}

struct sockaddr_in *getTunnelDestAddr(void *instance,int isLte){
    struct sockaddr_in * addr = NULL;
    struct lwip_instance *pInstance = (struct lwip_instance*)instance;
    struct tunnel_context *pTunnelContext = get_tunnel_context(instance);
    return isLte? &pTunnelContext->lte_ser_addr:&pTunnelContext->wifi_ser_addr;
}

#if WIFI_LTE_SWITCH
void heartbeat_tunnel_init(UINT32 tunnel_id)
{
    heartbeat_header *pHeader = &tunnel_heartbeat;

    ENTER_FUNC;

    memset(pHeader, 0, sizeof(heartbeat_header));
    pHeader->heartbeart.fix_header.version = 0x01;
    pHeader->heartbeart.fix_header.icheck = 0x00;

    pHeader->heartbeart.fix_header.type = ECHO_REQUEST;
    pHeader->heartbeart.fix_header.len =htons(sizeof(heartbeat_header));
    pHeader->heartbeart.msg.tc.tunnel_id = htonl(tunnel_id);

    LogI("%s:%d enter tunnel_id:0x%x\n\r",__FUNCTION__,__LINE__,
         pHeader->heartbeart.msg.tc.tunnel_id);

    EXIT_FUNC;
}

void heartbeat_tunnel_sends_value(int sock_fd, UINT32 dst_ip, UINT16 dst_port)
{
    ssize_t len = 0;

    if (sock_fd <= 0 || dst_ip == 0 || dst_port == 0) {
        LogE("invalid param");
        return;
    }

    struct sockaddr_in dst_addr;

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = dst_ip;
    dst_addr.sin_port = dst_port;
    LogD("heartbeat dst ip:%s", inet_ntoa(dst_addr.sin_addr));
    LogD("heartbeat dst port:%d", dst_port);

    ENTER_FUNC;

    len = sendto(sock_fd, &tunnel_heartbeat, sizeof(tunnel_heartbeat), 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_in));
    if (len <= 0) {
        LogD(" heartbeat send error!");
        return;
    }

    EXIT_FUNC;
}
#endif
