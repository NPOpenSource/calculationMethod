/*===========================================================================

                         mptcp_proxy.h

DESCRIPTION

 declaretion of mptcp proxy module


Copyright (c) 2017.04 - 2017.05 by Thundersoft Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/

#ifndef MPTCP_PROXY_H
#define MPTCP_PROXY_H


#include "lwip/err.h"
#include "lwip/tcp.h"
#include "lwip/prot/tcp.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/ip4_nat.h"


#include "../../../../../../vpn_tun/vpn_tun_if.h"
#include "lwip/module.h"

#ifdef __cplusplus
extern "C" {
#endif

/***************************** gloable variable start ***************************************/
#define MPTCP_PROXY_SERVER_PORT                 55557
#define MPTCP_PROXY_SOCK_TABLE_MAX_SIZE         256
#define MPTCP_MAX_CONNECT_TIME                  5

#define PROXY_DATA_BUF_SIZE (TCP_MSS) //(TUN_TCP_MSS + 1000) this macro too big will casue speedtest upload communication fail

#define PROXY_DATA_BUF_SIZE2 (1024*1204*1) //equal with tss

struct dataPacket {
    struct dataPacket *next;
    int sockid;
    int oid;
    int len;
    char buff[PROXY_DATA_BUF_SIZE2];
};

typedef struct sockets_table
{
    int proxy_listen_fd;
    int proxy_accept_fd;
    //add other paramter
} proxy_server_sockets_table_t;

// proxy module thread config, set XXXflag to 0, to stop thread
typedef struct thread_config
{
    int mptcp_proxy_server_accept_thread_flag;//0 for stop
    int mptcp_proxy_data_thread_flag;//0 for stop
}mptcp_proxy_thread_config_t;

//extern sys_sem_t proxy_server_sem;
/*mptcp_proxy_thread_config_t g_mptcp_proxy_thread_config;*/

/*struct netif mptcp_proxy_client_netif;*/


/***************************** gloable variable end *****************************************/


/***************************** function declare start ***************************************/

err_t mptcp_proxy_server_init(struct lwip_instance *pstInstance, struct lwip_instance *pstMptcpInstance);

err_t mptcp_proxy_client_netif_input(struct pbuf *p, struct netif *netif);

err_t mptcp_proxy_server_destroy(void* instance);
/** add for test **/
void test_mask_thread_is_ok();
/** add for test **/
/***************************** function declare end *****************************************/
struct netif *mptcp_proxy_get_netif(void *pLwIpInstance);
int mptcp_proxy_debug_counter(void *instance, char *pBuffer, unsigned int len);

#ifdef __cplusplus
}
#endif
#endif //MPTCP_PROXY_H
