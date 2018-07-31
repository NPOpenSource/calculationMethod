/*===========================================================================



DESCRIPTION




Copyright (c) 2017.04 - 2017.05 by Thundersoft Technologies, IncTEorporated.  All Rights Reserved.
===========================================================================*/
#include <semaphore.h>
#include "lwip/lwipopts.h"
#include "lwip/mptcp/mptcp_proxy.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"
#include "../../mccp/mccp.h"
#include "../../tools/tools.h"
#include "nolock.h"
#include "../../tools/threadpool.h"
#include "../../tunnel/tunnel.h"

#if LINUX_PLATFORM
#include <unistd.h>
#define gettid getpid
#define ntohs(x) lwip_ntohs(x)
#endif

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_PROXY

#define NO_LOCK_LIST 1
//extern int mutp_encode_send(void *instance,int ipaddr, int port, struct pbuf *buf);
typedef struct __mptcp_proxy_context{
    int mptcp_proxy_listen_sock;
    fd_set mptcp_proxy_server_listen_fd_set;
    struct netif mptcp_proxy_client_netif;
    struct sockaddr_in mptcp_sock;
    struct sockaddr_in mptcp_proxy_client_sock_addr;
    struct queue *pTunnelQue;
    struct packet_queue *pPacketTunnelQue;
    int gMptcpProxyThreadNumber;
    mptcp_proxy_thread_config_t  g_mptcp_proxy_thread_config;
    sem_t gMptcpExitSem;
    void *instance;
    sem_t proxydataSndSem;
    sys_sem_t proxy_server_sem;
    
    pthread_mutex_t recvDataListMutex;
    struct dataPacket *recvDataListHead;
    struct dataPacket *recvDataListEnd;
    pthread_mutex_t recvDataTcpListMutex;
    pthread_mutex_t recvDataMptcpListMutex;
    struct dataPacket *recvDataTcpListHead;
    struct dataPacket *recvDataTcpListEnd;
    struct dataPacket *recvDataMptcpListHead;
    struct dataPacket *recvDataMptcpListEnd;
    struct queue *pAsockQue;
    struct queue *pCsockQue;
    
    pthread_mutex_t gMptcpExitMutex;
    int vpn_recv_cnt;
    int vpn_send_cnt;
    int vpn_recv_err_cnt;
    int tunnel_recv_cnt;
    int tunnel_send_cnt;
    int mptcp2tcp_recv_cnt;
    int mptcp2tcp_send_cnt;
    int tcp2mptcp_recv_cnt;
    int tcp2mptcp_send_cnt;
}mptcp_proxy_context;

/*int gMptcpProxyThreadNumber = 0;*/
/*pthread_mutex_t gMptcpExitMutex;*/
int mptcp_proxy_client_netif_addr_array[4] = {192, 168, 43, 13};
int mptcp_proxy_client_netif_netmask_array[4] = {255, 255, 255, 0};
int mptcp_proxy_client_netif_gateway_array[4] = {192, 168, 43, 254};
/*
struct sockaddr_in mptcp_sock;
struct sockaddr_in mptcp_proxy_client_sock_addr;
*/
#define MAX_FETCH_LIST 5
/*
#define PROXY_DATA_BUF_SIZE 72000

#define PROXY_DATA_BUF_SIZE2 72000  //equal with tss

struct dataPacket {
    struct dataPacket *next;
    int sockid;
    int oid;
    int len;
    char buff[PROXY_DATA_BUF_SIZE2];
};
*/
struct sock_args {
    int c_socket;
    int a_socket;
    struct queue *pQue; 
    int exitFlag;
    sem_t exitWait;
    void *instance;
};

typedef int (* peer_exit_callback)(void *pArg);

struct thread_context{
   struct threadpool *pool;
   void *instance;
   struct packet_queue *pTcpQue;
   struct packet_queue *pMtcpQue;
   int sock;
   int isAsock;
   int write_weight;
   int read_weight;
   struct sockaddr_in servaddr;
   void *pArg;
   peer_exit_callback exit_callback;
   int exit_flag;
};

struct instance_context{
    void *tcp_instance;
    void *mptcp_instance;
};

struct thread_job_context{
    void *instance;
    mptcp_proxy_context  *pMptcpProxyContext;
    struct sock_args *pArgs;
};
static int mptcp_proxy_client_socket_init(void *instance, mptcp_proxy_context  *pMptcpProxyContext, struct sockaddr_in *pServaddr);

#if SYS_THREAD_FREE_FUNC
extern void sys_thread_free_self();
#endif

/*===========================================================================
  FUNCTION proxy_data_thread

  DESCRIPTION


  PARAMETERS
    none

  RETURN VALUE
    none

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/
    
#if LWIP_TWO_TCP_STACK_ZSQ
int g_load = 0;
extern struct lwip_instance *gstInstance[MAX_INSTANCE_NUM*2];
  
void proxy_data_thread(void *arg) {
    u8_t *buf = NULL;
    int a_sock;
    int c_sock;
    int cnnt = 0;
    struct timeval data_proxy_tv;
    fd_set mptcp_proxy_sock_set;
    u32_t opt;
    int ret = 0, val = 1, wrote;
    socklen_t  len;
    int send_read = 0, send_write = 0, recv_read = 0, recv_write = 0;
    struct sockaddr_in servaddr;
    u8_t was_readable = 1;
    int select_ret = 0;
    int c_sock_errno = 0;

    struct thread_context *a_pThread_context = (struct thread_context *)arg;
    struct lwip_instance *a_instance = (struct lwip_instance *)a_pThread_context->instance;
    mptcp_proxy_context *a_pMptcpProxyContext = (mptcp_proxy_context *)a_instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;

    g_load++;

    //struct thread_context *c_pThread_context = (struct thread_context *)gstInstance[MAX_INSIDE_INSTANCE_NUM + g_load %(MAX_INSTANCE_NUM-MAX_INSIDE_INSTANCE_NUM)];
    struct lwip_instance *c_instance = (struct lwip_instance *)gstInstance[MAX_INSIDE_INSTANCE_NUM + g_load %(MAX_INSTANCE_NUM-MAX_INSIDE_INSTANCE_NUM)];;
    mptcp_proxy_context *c_pMptcpProxyContext = (mptcp_proxy_context *)c_instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;

    a_sock = (int) a_pThread_context->sock;
    
    LogD("proxy_data_thread create socket");
    global_set_thread_instance(c_instance);
    c_sock = lwip_socket(AF_INET, SOCK_STREAM,
                         IPPROTO_TCP, c_instance); //use to send the mptcp server
    buf = (u8_t *) malloc(sizeof(u8_t) * PROXY_DATA_BUF_SIZE2);
    if (buf == NULL) {
        LogE("%s:%d, the space is not enough", __func__, __LINE__);
        if(c_sock>=0)
        {
            global_set_thread_instance(c_instance);
            lwip_close(c_sock);
        }
        return;
    }


    if (c_sock < 0) {
        LogE("a_sock=%d create socket is fails",a_sock);
        global_set_thread_instance(a_pThread_context->instance);
        lwip_close(a_sock);

        pthread_mutex_lock(&a_pMptcpProxyContext->gMptcpExitMutex);
        a_pMptcpProxyContext->gMptcpProxyThreadNumber--;
        pthread_mutex_unlock(&a_pMptcpProxyContext->gMptcpExitMutex);
        if (a_pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
            sem_post(&a_pMptcpProxyContext->gMptcpExitSem);
        }
        if (buf != NULL) {
            free(buf);
            buf = NULL;
        }

        if( a_pThread_context != NULL)
        {
            free(a_pThread_context);
            a_pThread_context = NULL;
        }
        return;
    }

    global_set_thread_instance(c_instance);
    if (lwip_bind(c_sock, (struct sockaddr *) &c_pMptcpProxyContext->mptcp_proxy_client_sock_addr,
                  sizeof(c_pMptcpProxyContext->mptcp_proxy_client_sock_addr)) < 0) {
        LogE("c_sock=%d bind socket is fails",c_sock);
        goto End;
    }

    len = sizeof(servaddr);

    global_set_thread_instance(a_pThread_context->instance);
    lwip_getsockname(a_sock, (struct sockaddr *) &servaddr, &len);
#if LWIP_MPTCP_SUPPORT
    global_set_thread_instance(c_instance);
    if (!lwip_add_server_addr_opts(c_sock, (struct sockaddr *)&servaddr, MPTCP_ENABLED))
    {
    
       LogE("c_sock=%d lwip_add_server_addr_opts fails",c_sock);
       goto End;
    }
#endif

    /* nonblocking */
    opt = 1;
    global_set_thread_instance(c_instance);
    lwip_ioctl(c_sock, FIONBIO, &opt);
    /* should have an error: "inprogress" */
    global_set_thread_instance(c_instance);
    if (-1 == lwip_connect(c_sock, (struct sockaddr *) &a_pMptcpProxyContext->mptcp_sock, sizeof(a_pMptcpProxyContext->mptcp_sock))) {
        if (errno == EINPROGRESS) {
            while (c_pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
                FD_ZERO(&mptcp_proxy_sock_set);
                FD_SET(c_sock, &mptcp_proxy_sock_set);
                data_proxy_tv.tv_sec = 1;
                data_proxy_tv.tv_usec = 0;
                global_set_thread_instance(c_instance);
                select_ret = lwip_select(c_sock + 1, NULL, &mptcp_proxy_sock_set, NULL,
                                         &data_proxy_tv);
                if (-1 == select_ret) {
                    LogE("proxy_data_thread connect fails: %s", strerror(errno));
                    goto End;
                } else if (0 == select_ret) {
                    if (cnnt++ > 40) {
                        LogE("proxy_data_thread select fails: %s", strerror(errno));
                        goto End;
                    }
                    
                    LogD("proxy_data_thread line%d select continue",__LINE__);
                    continue;
                } else {
                    /*http://dongxicheng.org/network/non-block-connect-implemention/*/
                    int errNo = 0;
                    socklen_t optLen = sizeof(errNo);
                    global_set_thread_instance(c_instance);
                    if (lwip_getsockopt(c_sock, SOL_SOCKET, SO_ERROR, &errNo, &optLen) == 0) {
                        if (errNo != 0) {
                            LogE("proxy_data_thread get SOL_SOCKET return fails: %s", strerror(errno));
                            goto End;
                        }
                    } else {
                        LogE("proxy_data_thread get SOL_SOCKET fails: %s", strerror(errno));
                        goto End;
                    }
                    LogD("proxy_data_thread connect success");
                    break;
                }
            }
        } else {
            LogE("proxy_data_thread c_sock=%d lwip_connect fails: %s", c_sock,strerror(errno));
            goto End;
        }
    }
    char name[60]={ 0 };
    sprintf(name,"proxy_thread:%d",get_instance_logic_id(a_instance));
    setThreadName(name);
    opt = 0;
    global_set_thread_instance(c_instance);
    lwip_ioctl(c_sock, FIONBIO, &opt);
    val = 1;
    global_set_thread_instance(a_pThread_context->instance);
    lwip_setsockopt(a_sock, SOL_SOCKET, TCP_NODELAY, &val, sizeof(val));
    val = 1;
    global_set_thread_instance(c_instance);
    lwip_setsockopt(c_sock, SOL_SOCKET, TCP_NODELAY, &val, sizeof(val));
    opt = 1;
    lwip_ioctl(c_sock, FIONBIO, &opt);
    LogD("accept_socket=%d, net_socket=%d", a_sock, c_sock);
    LogD("mptcp client ip=%s, port=%d", inet_ntoa(a_pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_addr), ntohs(pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_port));
    while (a_pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag && 
        c_pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag  ) {
        was_readable = 0;

        global_set_thread_instance(a_pThread_context->instance);
        len = lwip_recv(a_sock, buf, PROXY_DATA_BUF_SIZE, MSG_DONTWAIT);
        if (len == -1) {
            c_sock_errno = errno;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                LogE("instance %p recv a_sock error=%s", instance,strerror(errno));
                break;
            }
        } else if (len == 0) {
            /*socket has closed,*/
            LogE("instance %p recv a_sock:%d len=0, socket has closed", instance,a_sock);
            goto End;
        } else {
            was_readable = 1;
            send_read += len;
            wrote = 0;
            
            
            LogD("c socket lwip_write data=%d,", len);
            while (wrote < len) {
                
                global_set_thread_instance(c_instance);
                ret = lwip_write(c_sock, &buf[wrote], (size_t) (len - wrote));
                if (ret < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        usleep(2000);
                        if(pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
                            continue;
                        }
                    }
                    goto End;
                } else
                    wrote += ret;
            }
            send_write += wrote;
        }

        global_set_thread_instance(c_instance);
        len = lwip_recv(c_sock, buf, PROXY_DATA_BUF_SIZE2, MSG_DONTWAIT);
        if (len == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                LogE("recv c_sock%d error=%d", c_sock,errno);
                break;
            }
        } else if (len == 0) {
            /*socket has closed*/
            LogE("recv c_sock%d len=0,socket has closed",c_sock);
            goto End;
        } else {
            was_readable = 1;
            recv_read += len;
            wrote = 0;          
            LogD("a socket lwip_write data=%d,", len);
            //if(recv_write < 1000000)
            {
                while (wrote < len)
                {
                    global_set_thread_instance(a_pThread_context->instance);
                    ret = lwip_write(a_sock, &buf[wrote], (size_t) (len - wrote));
                    if (ret < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                            usleep(2000);
                            if(pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
                                continue;
                            }
                        }
                        c_sock_errno = errno;
                        goto End;;
                    } else
                        wrote += ret;
                }
                recv_write += wrote;
            }
        }

        if (!was_readable)
            usleep(5000);
    }
    End:
    if (buf != NULL) {
        free(buf);
        buf = NULL;
    }
    
    LogE("proxy_data_thread a_socket=%d and c_sock=%d exit",a_sock,c_sock);
    LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("close accept_socket=%d and client socket=%d\n", a_sock,c_sock));
    if(a_sock >= 0)
    {
    
        global_set_thread_instance(a_pThread_context->instance);
        lwip_close(a_sock);
        LogD("close a_socket=%d", a_sock);
    }
    if(c_sock >= 0){
        if(c_sock_errno == ECONNRESET)
            {        
                global_set_thread_instance(c_instance);
                lwip_error_close(c_sock);
            }
        else{
            global_set_thread_instance(c_instance);
            lwip_close(c_sock);
        }
        LogE("close c_socket=%d", c_sock);
    }
    if( a_pThread_context != NULL)
    {
        free(a_pThread_context);
        a_pThread_context = NULL;
    }
    pthread_mutex_lock(&a_pMptcpProxyContext->gMptcpExitMutex);
    a_pMptcpProxyContext->gMptcpProxyThreadNumber--;
    pthread_mutex_unlock(&a_pMptcpProxyContext->gMptcpExitMutex);
    if (a_pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
        sem_post(&a_pMptcpProxyContext->gMptcpExitSem);
    }
#if SYS_THREAD_FREE_FUNC
	sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
    EXIT_FUNC;
    return;
}
#else

void* proxy_data_thread(void *arg) {
    u8_t *a_buf = NULL;
    u8_t *c_buf = NULL;
    int a_sock = -1;
    int c_sock = -1;
    int cnnt = 0;
    struct timeval data_proxy_tv;
    fd_set mptcp_proxy_sock_set;
    u32_t opt;
    int ret = 0, val = 1, a_wrote = 0, c_wrote = 0;
    socklen_t  a_len = 0,c_len = 0, len = 0;
    int send_read = 0, send_write = 0, recv_read = 0, recv_write = 0;
	int a_writefail = 0,c_writefail = 0;
    struct sockaddr_in servaddr;
    u8_t was_readable = 1;
    int select_ret = 0;
    int c_sock_errno = 0;
    char name[60]={ 0 };
	
    struct thread_context *pThread_context = (struct thread_context *)arg;
    struct lwip_instance *instance = (struct lwip_instance *)pThread_context->instance;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    sprintf(name,"proxy_thread:%d",get_instance_logic_id(instance));
    setThreadName(name);

    global_set_thread_instance(pThread_context->instance);
    a_sock = (int) pThread_context->sock;


	len = sizeof(servaddr);
	lwip_getsockname(a_sock, (struct sockaddr *) &servaddr, &len);
    LogD("%s:%d,connect to ip=%s, port = %d", __func__, __LINE__, inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));
    LogD("%s:%d, create socket", __func__, __LINE__);

    c_sock = lwip_socket(AF_INET, SOCK_STREAM,
                         IPPROTO_TCP, pThread_context->instance); //use to send the mptcp server

	if (c_sock < 0) {
		LogE("%s:%d,c_sock %d create fails", __func__, __LINE__,c_sock);
		goto End;
	}
    a_buf = (u8_t *) malloc(sizeof(u8_t) * PROXY_DATA_BUF_SIZE);
    if (a_buf == NULL) {
        LogE("%s:%d, the space is not enough", __func__, __LINE__);
		goto End;;
    }
	
    c_buf = (u8_t *) malloc(sizeof(u8_t) * PROXY_DATA_BUF_SIZE2);
    if (c_buf == NULL) {
        LogE("%s:%d, the space is not enough", __func__, __LINE__);
        goto End;
    }	
#if WIFI_LTE_SWITCH
    if(isSetLteAddr) {
        pMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;
        LogD("%s:%d,connect socket mccp_mpgw_ip:%x", __func__, __LINE__,ppca_s->mccp_mpgw_ip);
    }else if(isSetWifiAddr && !isSetLteAddr) {
        pMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip1;
        LogD("%s:%d,connect socket mccp_mpgw_ip1:%x", __func__, __LINE__,ppca_s->mccp_mpgw_ip);
    }
#endif

    if (lwip_bind(c_sock, (struct sockaddr *) &pMptcpProxyContext->mptcp_proxy_client_sock_addr,
                  sizeof(pMptcpProxyContext->mptcp_proxy_client_sock_addr)) < 0) {
        LogE("%s:%d,c_sock=%d bind socket is fails", __func__, __LINE__,c_sock);
        goto End;
    }
#if LWIP_MPTCP_SUPPORT
    if (!lwip_add_server_addr_opts(c_sock, (struct sockaddr *)&servaddr, MPTCP_ENABLED))
    {
		LogE("%s:%d,a_sock=%d lwip_add_server_addr_opts fails", __func__, __LINE__,a_sock);
       goto End;
    }
#endif

    /* nonblocking */
    opt = 1;
    lwip_ioctl(c_sock, FIONBIO, &opt);
    /* should have an error: "inprogress" */
    if (-1 == lwip_connect(c_sock, (struct sockaddr *) &pMptcpProxyContext->mptcp_sock, sizeof(pMptcpProxyContext->mptcp_sock))) {
        if (errno == EINPROGRESS) {
            while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
                FD_ZERO(&mptcp_proxy_sock_set);
                FD_SET(c_sock, &mptcp_proxy_sock_set);
                data_proxy_tv.tv_sec = 1;
                data_proxy_tv.tv_usec = 0;
                select_ret = lwip_select(c_sock + 1, NULL, &mptcp_proxy_sock_set, NULL,
                                         &data_proxy_tv);
                if (-1 == select_ret) {
                    LogE("%s:%d ,connect to ip=%s, port = %d fails: %s", __func__, __LINE__,inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), strerror(errno));
                    goto End;
                } else if (0 == select_ret) {
                    if (cnnt++ > 40) {
                        LogE("%s:%d,connect to ip=%s, port = %d select fails: %s", __func__, __LINE__,inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), strerror(errno));
                        goto End;
                    }
                    LogD("%s:%d, select continue", __func__, __LINE__);
                    continue;
                } else {
                    /*http://dongxicheng.org/network/non-block-connect-implemention/*/
                    int errNo = 0;
                    socklen_t optLen = sizeof(errNo);
                    if (lwip_getsockopt(c_sock, SOL_SOCKET, SO_ERROR, &errNo, &optLen) == 0) {
                        if (errNo != 0) {
                            LogE("%s:%d, connect to ip=%s, port = %d get SOL_SOCKET return errno fails: %s , last error is %s", __func__, __LINE__,inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), strerror(errNo),strerror(errno));
                            goto End;
                        }
                    } else {
                        LogE("%s:%d, connect to ip=%s, port = %d get SOL_SOCKET fails: %s", __func__, __LINE__,inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), strerror(errno));
                        goto End;
                    }
                    LogD("%s:%d, connect to ip=%s, port = %d success", __func__, __LINE__,inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));
                    break;
                }
            }
        } else {
            LogE("%s:%d, c_sock=%d ,connect to ip=%s, port = %d fails ,not on going: %s", __func__, __LINE__, c_sock,inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port),strerror(errno));
            goto End;
        }
    }
    opt = 0;
    lwip_ioctl(c_sock, FIONBIO, &opt);
    val = 1;
    lwip_setsockopt(a_sock, SOL_SOCKET, TCP_NODELAY, &val, sizeof(val));
#if UP_SOCK_BUFF
    val = 65535*10;
    //lwip_setsockopt(a_sock, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
#endif
    val = 1;
    lwip_setsockopt(c_sock, SOL_SOCKET, TCP_NODELAY, &val, sizeof(val));
#if UP_SOCK_BUFF
//	val = 65535*10;
//    lwip_setsockopt(c_sock, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
#endif	
    opt = 1;
    lwip_ioctl(c_sock, FIONBIO, &opt);
    LogD("%s:%d,accept_socket=%d, net_socket=%d", __func__, __LINE__, a_sock, c_sock);
    LogD("%s:%d,mptcp client ip=%s, port=%d", __func__, __LINE__, inet_ntoa(pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_addr), ntohs(pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_port));
    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
        was_readable = 0; //to sleep
		
#if PROXY_UPLOAD_PROTECT
		if(c_wrote == a_len)
		{
#endif
		c_wrote = 0;

        a_len = lwip_recv(a_sock, a_buf, PROXY_DATA_BUF_SIZE, MSG_DONTWAIT);
		
#if PROXY_UPLOAD_PROTECT
		}
#endif		
        if (a_len == -1) {
            c_sock_errno = errno;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                LogD("%s:%d,instance %p recv a_sock %d error=%s", __func__, __LINE__, instance,a_sock,strerror(errno));
                break;
            }
			a_len = 0;
        } else if (a_len == 0) {
            /*socket has closed,*/
            LogD("%s:%d,instance %p recv a_sock:%d len=0, socket has closed", __func__, __LINE__, instance,a_sock);
            goto End;
        } else {
			was_readable = 1; //to not sleep
			if(0 == c_wrote)
			{
				//LogD("%s:%d instance %p write c_sock:%d 00 ", __func__, __LINE__, instance,c_sock);
	            send_read += a_len;
			}
            
            LogD("%s:%d need write c_sock:%d a_len=%d,send_read = %d,send_write = %d", __func__, __LINE__,c_sock, a_len,send_read,send_write);

#if !PROXY_UPLOAD_PROTECT
            while (c_wrote < a_len)
#else
            if(c_wrote < a_len)
#endif
			{
                ret = lwip_write(c_sock, &a_buf[c_wrote], (size_t) (a_len - c_wrote));
                if (ret < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    {
						LogD("%s:%d instance %p write c_sock:%d len=%d, EAGAIN,c_wrote = %d c_writefail = %d send_write=%ld ", __func__, __LINE__, instance,c_sock,a_len,c_wrote,c_writefail,send_write);
                        if(likely(pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag))
						{
							usleep(2000);
#if !PROXY_UPLOAD_PROTECT
	                        continue;
#else
							//LogD("%s:%d instance %p write c_sock:%d sleep add1 ", __func__, __LINE__, instance,c_sock);
							c_writefail++;
#endif
                        }else
	                        goto End;
                    } else
                    {
                        goto End;
                    }
                }else if (ret == 0) {
		            /*socket has closed,*/
		            LogD("instance %p write c_sock:%d len=0, socket has closed", instance,c_sock);
		            goto End;
                }else
                {
                    c_wrote += ret;
#if  PROXY_UPLOAD_PROTECT
					if(c_wrote == a_len)
					{
						//LogD("%s:%d instance %p write c_sock:%d c_wrote = %d a_len = %d clear", __func__, __LINE__, instance,c_sock,c_wrote,a_len);
						c_writefail = 0;
                	}else
            		{
						//LogD("%s:%d instance %p write c_sock:%d c_wrote = %d a_len = %d sleep add2", __func__, __LINE__, instance,c_sock,c_wrote,a_len);
						usleep(2000);
						c_writefail++;
            		}
#endif
					send_write += ret;
                }
            }
			
        }

		a_wrote = 0;
		c_len = lwip_recv(c_sock, c_buf, PROXY_DATA_BUF_SIZE2, MSG_DONTWAIT);
        if (c_len == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                LogD("%s:%d,recv c_sock:%d error=%d", __func__, __LINE__, c_sock,errno);
                break;
            }
			c_len = 0;
        } else if (c_len == 0) {
            /*socket has closed*/
            LogD("%s:%d,recv c_sock:%d len=0,socket has closed", __func__, __LINE__,c_sock);
            goto End;
        } else {
            was_readable = 1;
            recv_read += c_len;
			
            LogD("%s:%d need write a_sock:%d c_len=%d recv_read=%d recv_write=%d", __func__, __LINE__, a_sock,c_len,recv_read,recv_write);

            //if(recv_write < 1000000)
			while (a_wrote < c_len)
            {
                ret = lwip_write(a_sock, &c_buf[a_wrote], (size_t) (c_len - a_wrote));
                    if (ret < 0) {
					c_sock_errno = errno;
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
						usleep(2000);
                        if(likely(pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag)) 
						{
							continue;
                    	}else
                        	goto End;
                    }else {
                        goto End;
                    }
                }else if (ret == 0) {
	            /*socket has closed,*/
	            LogD("instance %p write a_sock:%d len=0, socket has closed", instance,a_sock);
	            goto End;
                }
				else
                {
                    a_wrote += ret;
                }
            }
            recv_write += a_wrote;
        }

        if (!was_readable)
    	{
        	if(recv_write < 20000 && send_write < 20000)
    		{
				usleep(2000);
    		}else
    		{
	            usleep(5000);
			}
    	}
#if PROXY_UPLOAD_PROTECT  //if has no this branch ,rate will be low,and maybe fail
		if ( c_writefail >= 4 )
		{
			usleep(5000);
		}
#endif
    }
    End:
    if (a_buf != NULL) {
        free(a_buf);
        a_buf = NULL;
    }
    if (c_buf != NULL) {
        free(c_buf);
        c_buf = NULL;
    }

    LogD("%s:%d,proxy_data_thread a_sock=%d and c_sock=%d send_read = %d,send_write = %d ,recv_read=%d ,recv_write=%d exit", __func__, __LINE__,a_sock,c_sock,send_read,send_write,recv_read,recv_write);
    LogD("%s:%d,close accept_socket=%d and client socket=%d", __func__, __LINE__, a_sock,c_sock);
    if(a_sock >= 0)
    {
        lwip_close(a_sock);
        LogD("%s:%d,close a_socket=%d", __func__, __LINE__, a_sock);
    }
    if(c_sock >= 0){
        if(c_sock_errno == ECONNRESET)
        {
			LogD("%s:%d,lwip_close c_socket=%d", __func__, __LINE__, c_sock);
#if RESET_TO_FASTCLOSE
            lwip_error_close(c_sock);
#else
            lwip_close(c_sock);
#endif
        }
        else{
            lwip_close(c_sock);
			LogD("%s:%d,lwip_close c_socket=%d", __func__, __LINE__, c_sock);
        }
    }
#if SYS_THREAD_FREE_FUNC
    sys_thread_free_self();
#endif
	
    if( pThread_context != NULL)
    {
        free(pThread_context);
        pThread_context = NULL;
    }
    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber--;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
    if (pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
        sem_post(&pMptcpProxyContext->gMptcpExitSem);
    }

    pthread_detach(pthread_self());  //to avoid thread resource leak
    
    EXIT_FUNC;
    return NULL;
}
#endif



void transfer_data_thread(void *arg) {
#if LWIP_PACKET_QUEUE
    socklen_t  len;
    struct dataPacket *pMptcpPacket = NULL,*pTcpPacket = NULL;
    struct dataPacket *pMptcpPacketList[MAX_FETCH_LIST];
    int sock = -1;
    int ret = 0, wrote,cnt,i,j;
    u8_t was_readable = 1;
    struct thread_context *pThread_context = (struct thread_context *)arg;
    struct lwip_instance *instance = (struct lwip_instance *)pThread_context->instance;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    struct packet_queue *pSendQue = pThread_context->pMtcpQue;
    struct packet_queue *pReceiveQue = pThread_context->pTcpQue;
    int weight_wrt,weight_rd;
    int peer_exit_flag = 0;

    global_set_thread_instance(pThread_context->instance);

    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber++;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);

    LogE("transfer_data_thread for %s socket thread create in the %p instance!", pThread_context->isAsock ? "accept":"mptcp",pThread_context->instance);
    if(pThread_context->isAsock == 0)
    {
        pThread_context->sock = mptcp_proxy_client_socket_init(pThread_context->instance, pMptcpProxyContext,&pThread_context->servaddr);
        if(pThread_context->sock < 0)
        {
            LogE("transfer_data_thread create c_sock error=%s in the %p instance", strerror(errno),pThread_context->instance);
            goto End;
        }
        
        pSendQue = pThread_context->pTcpQue;
        pReceiveQue = pThread_context->pMtcpQue;
    }
    sock = (int) pThread_context->sock;
    pTcpPacket = (struct dataPacket *)malloc(sizeof(struct dataPacket));
    weight_wrt = 0;
    weight_rd  = 0;

    LogE("transfer_data_thread for %s socket thread enter mainloop in the %p instance!", pThread_context->isAsock ? "accept":"mptcp",pThread_context->instance);
    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
        was_readable = 0;
        peer_exit_flag = 1;     
        
        len = lwip_recv(sock, pTcpPacket->buff, PROXY_DATA_BUF_SIZE, MSG_DONTWAIT);
        if (len == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                LogE("transfer_data_thread instance %p recv a_sock error=%s", instance, strerror(errno));
                goto End;
            }
        } else if (len == 0) {
            /*socket has closed,*/
            LogE("transfer_data_thread instance %p recv %s sock:%d len=0, socket has closed",instance, (pThread_context->isAsock ? "accept":"mptcp client"),sock);
            goto End;
        } else {
             was_readable = 1;
             pTcpPacket->len = len;
             /*peer is ok*/
             packet_queue_try_enque(pSendQue,(void *)pTcpPacket);
             pTcpPacket = NULL;
        }

peer_exit_empty_send_buffer:
        cnt = packet_queue_try_deque_list(pReceiveQue, MAX_FETCH_LIST, (void **)(pMptcpPacketList));
        if(cnt > 0){
            for(i=0; i< cnt;i++)
            {
                pMptcpPacket = pMptcpPacketList[i];
                if(pMptcpPacket != NULL){
                    was_readable = 1;
                    wrote = 0;
                    while (wrote < pMptcpPacket->len) {
                        ret = lwip_write(sock, &pMptcpPacket->buff[wrote], (size_t) (pMptcpPacket->len - wrote));
                        if (ret < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                                usleep(200);
                                continue;
                            }
                            if(i<cnt){
                                for(j=i;j<cnt;j++){
                                    free((void *)pMptcpPacketList[j]);
                                }
                                pMptcpPacket = NULL;
                            }
                            goto End;
                        } else
                            wrote += ret;
                    }
                    if(i < (cnt -1)){
                        free((void *)pMptcpPacket);
                    }
                    else if(pTcpPacket != NULL){
                        pTcpPacket = pMptcpPacket;
                    }
                    pMptcpPacket = NULL;
                    pMptcpPacketList[i] = NULL;
                }
            }
        }
        else
        {
            /*queue is empty*/
            was_readable = 0;
            if(pThread_context->exit_callback != NULL)
                peer_exit_flag = pThread_context->exit_callback(pThread_context->pArg);
            if(peer_exit_flag == 0){
                goto End;
            }
        }

        
        if(pThread_context->exit_callback != NULL)
            peer_exit_flag = pThread_context->exit_callback(pThread_context->pArg);
        
        if( peer_exit_flag == 0)
        {
           goto peer_exit_empty_send_buffer;
        }
        
        if(pTcpPacket == NULL){
           pTcpPacket = (struct dataPacket *)malloc(sizeof(struct dataPacket));
           if(pTcpPacket == NULL){
              LogE("transfer_data_thread recv %s sock=%d malloc fail:%s",(pThread_context->isAsock ? "accept":"mptcp client"),sock, strerror(errno));
              goto End;
           }
        }

        if (!was_readable)
            usleep(10000);
    }
    End:
    LogE("transfer_data_thread close %s socket=%d", (pThread_context->isAsock ? "accept":"mptcp client"),sock);
    LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("close %s socket=%d\n", (pThread_context->isAsock ? "accept":"mptcp client"),sock));

    if(sock >= 0){
        lwip_close(sock);

        ret = 1;
        do{
            pThread_context->exit_flag = 0;
            usleep(1000);
            if(pThread_context->exit_callback != NULL)
                ret = pThread_context->exit_callback(pThread_context->pArg);
        }while(ret == 1);
    }
    
    if(pThread_context->isAsock)
        packet_queue_free(pThread_context->pTcpQue);
    else
        packet_queue_free(pThread_context->pMtcpQue);
    

    if(pTcpPacket != NULL)
        free((void *)pTcpPacket);
    if(pMptcpPacket != NULL)
        free((void *)pMptcpPacket);

    if(pThread_context != NULL)
        free((void *)pThread_context);

    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber--;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
    if (pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
         sem_post(&pMptcpProxyContext->gMptcpExitSem);
    }
#if SYS_THREAD_FREE_FUNC
	sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
    EXIT_FUNC;
#endif
    return;
}

void proxy_send_two_data_thread(void *arg) {
    int ret = 0, len, wrote = 0;
    struct sock_args *args = (struct sock_args *)arg;
    struct queue* pQue = args->pQue;
    int a_sock = args->a_socket,c_sock = args->c_socket;
    struct dataPacket *dataPack,*tempPack;
    struct dataPacket *dataArray[2]={NULL,NULL};
    int cnt[2] ={0,0};
    int t = 0;
    struct lwip_instance *instance = (struct lwip_instance *)args->instance;
    mptcp_proxy_context* pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;

    global_set_thread_instance(args->instance);
    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber++;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);

    
    LogE("%s:%d pQue:%s:%p",__func__,__LINE__,pQue->name,pQue);
    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag && !args->exitFlag) {
        do{
            dataPack = (struct dataPacket *)Deque(pQue);
            if(dataPack == NULL || !pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag || args->exitFlag)
                break;
            if(dataPack->sockid == c_sock){
                t =0;
            }else{
                t = 1;
            }
            cnt[t] ++;
            if(dataArray[t] == NULL){
                dataArray[t] = dataPack;
            }
            else{
                if(PROXY_DATA_BUF_SIZE2 - dataArray[t]->len > dataPack->len){
                    memcpy(dataArray[t]->buff,dataPack->buff,(size_t)dataPack->len);
                    dataArray[t]->len += dataPack->len;
                }
                else{
                    dataArray[t]->next = dataPack;
                    break;
                }
                if(cnt[t] > 20)
                    break;
            }
        }while(dataPack != NULL);
        t = 0;

        while(t<2){
            dataPack = dataArray[t];

            while (dataPack != NULL && !args->exitFlag) {
                len = dataPack->len;
                wrote = 0;
                while (wrote < len && !args->exitFlag) {
                    ret = lwip_write(dataPack->sockid, dataPack->buff + wrote, (size_t) (len - wrote));
                    if (ret < 0) {
                        if (errno == EAGAIN || errno == EINTR) {
                            LogE("%s:%d error msg:%s",__func__,__LINE__,strerror(errno));
                            usleep(5000);
                            continue;
                        } else
                            args->exitFlag = 1;
                        break;
                    } else {
                        wrote += ret;
                    }
                }
                tempPack = dataPack->next;
                //opt = 0;
                //lwip_ioctl(dataPack->sockid, FIONBIO, &opt);
                if(dataPack->sockid == args->a_socket)
                  {
                    pMptcpProxyContext->mptcp2tcp_send_cnt++;
                  }
                else
                  {
                    pMptcpProxyContext->tcp2mptcp_send_cnt++;
                  }
                free(dataPack);
                dataPack = tempPack;
            }
            dataArray[t] = NULL;
            cnt[t] = 0;
            t++;
            
        }
    }
    args->exitFlag = 1;
    LogE("%s:%d getid:%d exit", __func__, __LINE__, gettid());
    sem_post(&args->exitWait);
    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber--;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
    if (pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
        sem_post(&pMptcpProxyContext->gMptcpExitSem);
    }
#if SYS_THREAD_FREE_FUNC
	sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
    EXIT_FUNC;
    return;
}

void proxy_recv_two_data_thread(void *arg) {
    int a_sock;
    int c_sock;
    int i,cnnt = 0;
    struct timeval data_proxy_tv;
    int sc_set_in[2],sc_set_out[2];
    fd_set mptcp_proxy_sock_set;
    u32_t opt;
    int val;
    socklen_t len;
    struct sockaddr_in servaddr;
    u8_t was_readable = 1;
    int select_ret = 0;
    int ret = 0;
    struct thread_context *pThread_context = (struct thread_context *)arg;
    struct lwip_instance* instance = (struct lwip_instance*)pThread_context->instance;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    struct sock_args *args  = (struct sock_args *)malloc(sizeof(struct sock_args));
    struct queue *pQue;
    char name[16];
    struct dataPacket *dataPack,*tmpPack;
    struct dataPacket *list[2]={NULL,NULL};
    struct dataPacket *dataArray[2] ={NULL,NULL};
    uint8_t empyt_flag[2]={0,0};

    a_sock = (int) pThread_context->sock;
    global_set_thread_instance(pThread_context->instance);
    sprintf(name,"a_sock:%d",a_sock);
    pQue = queueCreate(name,8192);
    args->pQue = pQue;
    args->instance = pThread_context->instance;
    
    c_sock = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, pThread_context->instance);
    if (c_sock < 0) {
        LogE("create socket is fails");
        lwip_close(a_sock);
        pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
        pMptcpProxyContext->gMptcpProxyThreadNumber--;
        pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
        if (pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
            sem_post(&pMptcpProxyContext->gMptcpExitSem);
        }

        if( pThread_context != NULL)
        {
            free(pThread_context);
            pThread_context = NULL;
        }
#if SYS_THREAD_FREE_FUNC
		sys_thread_free_self();
#endif
		pthread_detach(pthread_self());  //to avoid thread resource leak
        return;
    }

    if (lwip_bind(c_sock, (struct sockaddr *) &pMptcpProxyContext->mptcp_proxy_client_sock_addr,
                  sizeof(pMptcpProxyContext->mptcp_proxy_client_sock_addr)) < 0) {
        LogE("bind socket is fails");
        goto End;
    }

    len = sizeof(servaddr);
    lwip_getsockname(a_sock, (struct sockaddr *) &servaddr, &len);
#if LWIP_MPTCP_SUPPORT
    if (!lwip_add_server_addr_opts(c_sock, (struct sockaddr *)&servaddr, MPTCP_ENABLED))
    {
        goto End;
    }
#endif

    /* nonblocking */
    opt = 1;
    lwip_ioctl(c_sock, FIONBIO, &opt);
    /* should have an error: "inprogress" */
/*#if LWIP_PERFORMANCE_TEST_ENABLE_VETH0
    if (-1 == lwip_connect(c_sock, (struct sockaddr *) &servaddr, sizeof(servaddr))) {
#else*/
    if (-1 == lwip_connect(c_sock, (struct sockaddr *) &pMptcpProxyContext->mptcp_sock, sizeof(pMptcpProxyContext->mptcp_sock))) {
/*#endif*/
        if (errno == EINPROGRESS) {
            while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
                FD_ZERO(&mptcp_proxy_sock_set);
                FD_SET(c_sock, &mptcp_proxy_sock_set);
                data_proxy_tv.tv_sec = 1;
                data_proxy_tv.tv_usec = 0;
                select_ret = lwip_select(c_sock + 1, NULL, &mptcp_proxy_sock_set, NULL,
                                         &data_proxy_tv);
                if (-1 == select_ret) {
                    LogE("proxy_recv_data_thread connect fails: %s", strerror(errno));
                    goto End;
                } else if (0 == select_ret) {
                    if (cnnt++ > 40) {
                        LogE("proxy_recv_data_thread connect fails");
                        goto End;
                    }
                    continue;
                } else {
                    int errNo = 0;
                    socklen_t optLen = sizeof(errNo);
                    if (lwip_getsockopt(c_sock, SOL_SOCKET, SO_ERROR, &errNo, &optLen) == 0) {
                        if (errNo != 0) {
                            LogE("proxy_recv_data_thread connect fails");
                            goto End;
                        }
                    } else {
                        LogE("proxy_recv_data_thread connect fails");
                        goto End;
                    }
                    LogD("proxy_recv_data_thread connect success");
                    break;
                }
            }
        } else {
            LogE("proxy_recv_data_thread connect fails");
            goto End;
        }
    }
    LogE("pQue:%s:%p",pQue->name,pQue);
    args->a_socket = a_sock;
    args->c_socket = c_sock;
    args->pQue = pQue;
    args->exitFlag = 0;
    args->instance = pThread_context->instance;
    sem_init(&args->exitWait,0,0);
    LogE("recv thread:a_sock %d c_sock %d pQue %p",a_sock,c_sock,pQue);

    opt = 1;
    lwip_ioctl(c_sock, FIONBIO, &opt);

    opt = 1;
    lwip_ioctl(a_sock, FIONBIO, &opt);
#if !NO_LOCK_LIST
    /* set args and create a new thread */
    sys_thread_t thread = sys_thread_new(pThread_context->instance,NULL,"proxy_recv_data_thread_tcpServer",
                                         proxy_send_two_data_thread,
                                         (void *) args, 1024,
                                         0);
#endif
    /*
    opt = 0;
    lwip_ioctl(c_sock, FIONBIO, &opt);

    */
    
    val = 1;
    lwip_setsockopt(a_sock, SOL_SOCKET, TCP_NODELAY, &val, sizeof(val));
    val = 1;
    lwip_setsockopt(c_sock, SOL_SOCKET, TCP_NODELAY, &val, sizeof(val));
    LogD("accept_socket=%d, net_socket=%d", a_sock, c_sock);
    sc_set_in[0] = a_sock;
    sc_set_in[1] = c_sock;

    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag && !args->exitFlag) {

        data_proxy_tv.tv_sec = 1;
        data_proxy_tv.tv_usec = 0;
        was_readable = 0;
        select_ret = lwip_select_ext(2, sc_set_in, sc_set_out, 0, &data_proxy_tv);
        switch(select_ret){
            case 0:
                continue;
                break;
            case -1:
                if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR){
                    LogE("%s:%d error msg:%s", __func__, __LINE__, strerror(errno));
                    args->exitFlag = 1;
                    goto End;
                }
                break;
            default:                
                for (i = 0; i < select_ret; i++) {
#if !NO_LOCK_LIST
                    dataPack = dataArray[i];
                    empyt_flag[i]++;

                    if(dataPack == NULL) {
                        dataArray[i] = malloc(sizeof(struct dataPacket));
                        dataPack = dataArray[i];
                        dataPack->len = 0;
                    }
#else
                    dataPack = (struct dataPacket *)malloc(sizeof(struct dataPacket));
                    dataPack->len = 0;
#endif

                    len = lwip_recv(sc_set_out[i], dataPack->buff + dataPack->len, PROXY_DATA_BUF_SIZE2- dataPack->len, MSG_DONTWAIT);
                    if (len == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            LogE("%s:%d recv a_sock error: %s", __func__, __LINE__, strerror(errno));
                            args->exitFlag = 1;
                            break;
                        }
                    } else if (len == 0) {
                        /*socket has closed,*/
                        LogD("%s %s:%d recv a_sock len=0",(a_sock == sc_set_out[i])?"a_sock":"c_sock",__func__, __LINE__);
                        args->exitFlag = 1;
                        goto End;
                    } else {
                        LogD("%s:%d recv from socket:%d len:%d",__func__,__LINE__,sc_set_out[i],len);
                        if(a_sock == sc_set_out[i]){
                            dataPack->sockid = c_sock;
                            dataPack->oid = 0;
                            pMptcpProxyContext->tcp2mptcp_recv_cnt++;
                        }else{
                            dataPack->sockid = a_sock;
                            dataPack->oid = 1;
                            pMptcpProxyContext->mptcp2tcp_recv_cnt++;
                        }
                        dataPack->next = NULL;
                        dataPack->len += len;
#if !NO_LOCK_LIST
                        if(isNone(pQue) || dataPack->len > PROXY_DATA_BUF_SIZE2/2 || empyt_flag[i] > 20){
                            while(!Enque(pQue,dataPack) && pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag);
                            dataArray[i] = NULL;
                            empyt_flag[i] = 0;
                        }
#else
                        pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
                        if(pMptcpProxyContext->recvDataListHead != NULL){
                            pMptcpProxyContext->recvDataListEnd->next= dataPack;
                            pMptcpProxyContext->recvDataListEnd = dataPack;
                        }else{
                            LogD("%s:%d post new data from recv thread",__func__, __LINE__);
                            pMptcpProxyContext->recvDataListHead = pMptcpProxyContext->recvDataListEnd = dataPack;
                            sem_post(&pMptcpProxyContext->proxydataSndSem);
                        }
                        pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
#endif

                    }

                }
                break;
        }
    }
    End:
    LogD("close accept_socket=%d", a_sock);
    if(args != NULL){
        args->exitFlag = 1;//notify the send thread to exit
        /*wait all data send complete*/
        sem_wait(&args->exitWait);
        sem_close(&args->exitWait);
    }
    lwip_close(a_sock);
    lwip_close(c_sock);
    LogE("%s:%d getid:%d exit", __func__, __LINE__, gettid());
    if(args != NULL){
        destoryQue(args->pQue);
        free(args);
    }
    if( pThread_context != NULL)
    {
        free(pThread_context);
        pThread_context = NULL;
    }
#if SYS_THREAD_FREE_FUNC
	sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
    EXIT_FUNC;
    return;
}


static int mptcp_proxy_tcp_socket_init(int accept_sock, mptcp_proxy_context  *pMptcpProxyContext, struct sockaddr_in *pServaddr)
{
    socklen_t len;
    u32_t opt;
    int val;
    
    len = sizeof(struct sockaddr_in);
    lwip_getsockname(accept_sock, (struct sockaddr *)pServaddr, &len);
    
    opt = 1;
    lwip_ioctl(accept_sock, FIONBIO, &opt);
    
    val = 1;
    lwip_setsockopt(accept_sock, SOL_SOCKET, TCP_NODELAY, &val, sizeof(val));
    return 0;
}

static int mptcp_proxy_client_socket_init(void *instance, mptcp_proxy_context  *pMptcpProxyContext, struct sockaddr_in *pServaddr)
{
    socklen_t len;
    fd_set mptcp_proxy_sock_set;
    struct timeval data_proxy_tv;
    int cnnt = 0;
    int select_ret = 0;
    int errNo = 0;
    u32_t opt;
    int c_sock = -9;
        
    c_sock = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, instance);
    if (c_sock < 0) {
        LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("create mptcp socket is fails:%s\n", strerror(errno)));
        return -1;
    }

    if (lwip_bind(c_sock, (struct sockaddr *) &pMptcpProxyContext->mptcp_proxy_client_sock_addr,
                  sizeof(pMptcpProxyContext->mptcp_proxy_client_sock_addr)) < 0) {
        LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("bind mptcp socket is fails:%s\n", strerror(errno)));
        return -2;
    }

#if LWIP_MPTCP_SUPPORT
    if (!lwip_add_server_addr_opts(c_sock, (struct sockaddr *)pServaddr, MPTCP_ENABLED))
    {
        return -3;
    }
#endif
    
    /* nonblocking */
    opt = 1;
    lwip_ioctl(c_sock, FIONBIO, &opt);
    if (-1 == lwip_connect(c_sock, (struct sockaddr *) &pMptcpProxyContext->mptcp_sock, sizeof(pMptcpProxyContext->mptcp_sock))) 
    {
        if (errno == EINPROGRESS) 
        {
            while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag) {
                FD_ZERO(&mptcp_proxy_sock_set);
                FD_SET(c_sock, &mptcp_proxy_sock_set);
                data_proxy_tv.tv_sec = 1;
                data_proxy_tv.tv_usec = 0;
                select_ret = lwip_select(c_sock + 1, NULL, &mptcp_proxy_sock_set, NULL,
                                         &data_proxy_tv);
                if (-1 == select_ret) {
                    LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp client connect fails:%s\n", strerror(errno)));
                    return -3;
                } else if (0 == select_ret) {
                    if (cnnt++ > 40) {
                        LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp client select fails:%s\n", strerror(errno)));
                        return -4;
                    }
                    continue;
                } else {
                    
                    len = sizeof(errNo);
                    if (lwip_getsockopt(c_sock, SOL_SOCKET, SO_ERROR, &errNo, &len) == 0) {
                        if (errNo != 0) {
                            LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp client SOL_SOCKET  error fails:%s\n", strerror(errno)));
                            return -5;
                        }
                    } else {
                        LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp client SOL_SOCKET fails:%s\n", strerror(errno)));
                        return -6;
                    }
                    LogD("proxy_recv_data_thread connect success");
                    break;
                }
            }
        } else {
            LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp client connect fails:%s\n", strerror(errno)));
            return -7;
        }
    }

    opt = 1;
    lwip_ioctl(c_sock, FIONBIO, &opt);
    
    cnnt = 1;
    lwip_setsockopt(c_sock, SOL_SOCKET, TCP_NODELAY, &cnnt, sizeof(cnnt));
    
    return c_sock;
}

void *mptcp_proxy_stream_recv_job(void *arg)
{
    u8_t was_readable = 1;
    int i, select_ret = 0;
    socklen_t len;
    struct timeval data_proxy_tv;
    int sc_set_in[2],sc_set_out[2];
    struct dataPacket *dataPack,*tmpPack;
    struct dataPacket *list[2]={NULL,NULL};
    struct dataPacket *dataArray[2] ={NULL,NULL};
    uint8_t empyt_flag[2]={0,0};
    struct thread_job_context *pJob_context = (struct thread_job_context *)arg;
    void *instance = pJob_context->instance;
    mptcp_proxy_context  *pMptcpProxyContext = pJob_context->pMptcpProxyContext;
    struct sock_args *pArgs  = pJob_context->pArgs;

    global_set_thread_instance(pArgs->instance);
    sc_set_in[0] = pArgs->a_socket;
    sc_set_in[1] = pArgs->c_socket;
        
    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag && !pArgs->exitFlag) {
        data_proxy_tv.tv_sec = 1;
        data_proxy_tv.tv_usec = 0;
        was_readable = 0;
        select_ret = lwip_select_ext(2, sc_set_in, sc_set_out, 0, &data_proxy_tv);
        switch(select_ret){
            case 0:
                continue;
                break;
            case -1:
                if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR){
                    LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp stream select fail:%s\n", strerror(errno)));
                    pArgs->exitFlag = 1;
                    return NULL;
                }
                break;
            default:                
                for (i = 0; i < select_ret; i++) {

                    dataPack = dataArray[i];
                    empyt_flag[i]++;

                    if(dataPack == NULL) {
                        dataArray[i] = (struct dataPacket *)malloc(sizeof(struct dataPacket));
                        dataPack = dataArray[i];
                        dataPack->len = 0;
                    }

                    len = lwip_recv(sc_set_out[i], dataPack->buff + dataPack->len, PROXY_DATA_BUF_SIZE2- dataPack->len, MSG_DONTWAIT);
                    if (len == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp stream recv error:%s\n", strerror(errno)));
                            pArgs->exitFlag = 1;
                            break;
                        }
                    } else if (len == 0) {
                        /*socket has closed,*/                  
                        LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp stream recv %s len=0:%s\n", (pArgs->a_socket == sc_set_out[i])?"a_sock":"c_sock", strerror(errno)));
                        pArgs->exitFlag = 1;
                        return NULL;
                    } else {
                        if(pArgs->a_socket == sc_set_out[i]){
                            dataPack->sockid = pArgs->c_socket;
                        }else{
                            dataPack->sockid = pArgs->a_socket;
                        }
                        dataPack->next = NULL;
                        dataPack->len += len;
                        if(isNone(pArgs->pQue) || dataPack->len > PROXY_DATA_BUF_SIZE2/2 || empyt_flag[i] > 20){
                            while(!Enque(pArgs->pQue,dataPack) && pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag);
                            dataArray[i] = NULL;
                            empyt_flag[i] = 0;
                        }

                    }

                }
                break;
        }
    }

    if(pArgs != NULL){
        pArgs->exitFlag = 1;//notify the send thread to exit
        usleep(1000);
        /*wait all data send complete*/
        sem_wait(&pArgs->exitWait);
        sem_close(&pArgs->exitWait);
    }
    lwip_close(pArgs->a_socket);
    lwip_close(pArgs->c_socket);
    LogE("%s:%d getid:%d exit", __func__, __LINE__, gettid());
    if(pArgs != NULL){
        destoryQue(pArgs->pQue);
        free(pArgs);
    }
    return NULL;
}

void *mptcp_proxy_stream_send_job(void *arg)
{
    struct dataPacket *dataPack,*tempPack;
    struct dataPacket *dataArray[2] ={NULL,NULL};
    int ret = 0, len, wrote = 0;
    int t,cnt[2] ={0,0};
    struct thread_job_context *pJob_context = (struct thread_job_context *)arg;
    void *instance = pJob_context->instance;
    mptcp_proxy_context  *pMptcpProxyContext = pJob_context->pMptcpProxyContext;
    struct sock_args *pArgs  = pJob_context->pArgs;

    global_set_thread_instance(pArgs->instance);
    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag && !pArgs->exitFlag) {
        do{
            dataPack = (struct dataPacket *)Deque(pArgs->pQue);
            if(dataPack == NULL || !pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag || pArgs->exitFlag)
                break;
            if(dataPack->sockid == pArgs->c_socket){
                t =0;
            }else{
                t = 1;
            }
            cnt[t] ++;
            if(dataArray[t] == NULL){
                dataArray[t] = dataPack;
            }
            else{
                if(PROXY_DATA_BUF_SIZE2 - dataArray[t]->len > dataPack->len){
                    memcpy(dataArray[t]->buff,dataPack->buff,(size_t)dataPack->len);
                    dataArray[t]->len += dataPack->len;
                }
                else{
                    dataArray[t]->next = dataPack;
                    break;
                }
                if(cnt[t] > 20)
                    break;
            }
        }while(dataPack != NULL);
        t = 0;

        while(t<2){
            dataPack = dataArray[t];

            while (dataPack != NULL && !pArgs->exitFlag) {
                len = dataPack->len;
                wrote = 0;
                
                while (wrote < len && !pArgs->exitFlag) {
                    ret = lwip_write(dataPack->sockid, dataPack->buff + wrote, (size_t) (len - wrote));
                    if (ret < 0) {
                        if (errno == EAGAIN || errno == EINTR) {
                            LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp stream send %s len=0:%s\n", (pArgs->a_socket == dataPack->sockid)?"a_sock":"c_sock", strerror(errno)));
                            continue;
                        } else
                            pArgs->exitFlag = 1;
                        break;
                    } else {
                        wrote += ret;
                    }
                }
                tempPack = dataPack->next;

                free(dataPack);
                dataPack = tempPack;
            }
            dataArray[t] = NULL;
            cnt[t] = 0;
            t++;
            
        }
    }
    pArgs->exitFlag = 1;
    LogE("%s:%d getid:%d exit", __func__, __LINE__, gettid());
    sem_post(&pArgs->exitWait);
    return NULL;
}

int mptcp_proxy_stream_job_create(void *arg)
{
    struct thread_context *pThread_context = (struct thread_context *)arg;
    struct lwip_instance* instance = (struct lwip_instance*)pThread_context->instance;
    mptcp_proxy_context* pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    struct queue *pQue;
    char name[16];
    int a_sock;
    int c_sock;
    struct sockaddr_in servaddr;
    struct thread_job_context *pJob_context;
    struct sock_args *args;

    a_sock = (int) pThread_context->sock;
    global_set_thread_instance(pThread_context->instance);
  
    if(0 == mptcp_proxy_tcp_socket_init(a_sock, pMptcpProxyContext, &servaddr))
    {
       c_sock = mptcp_proxy_client_socket_init(instance, pMptcpProxyContext, &servaddr);
       if(c_sock >= 0)
       {
          sprintf(name,"a_sock:%d",a_sock);
          pQue = queueCreate(name,8192);
          args  = (struct sock_args *)malloc(sizeof(struct sock_args));
          pJob_context = (struct thread_job_context *)malloc(sizeof(struct thread_job_context));

          pJob_context->instance = instance;
          args->a_socket = a_sock;
          args->c_socket = c_sock;
          args->instance = instance;
          args->pQue = pQue;
          args->exitFlag = 0;
          
          pJob_context->pMptcpProxyContext = pMptcpProxyContext;
          pJob_context->pArgs = args;
          sem_init(&pJob_context->pArgs->exitWait,0,0);
          
          threadpool_add_job(pThread_context->pool,mptcp_proxy_stream_recv_job,(void *)pJob_context);
          threadpool_add_job(pThread_context->pool,mptcp_proxy_stream_send_job,(void *)pJob_context);
          return 0;
       }
    }

    LWIP_DEBUGF(MPTCP_PROXY_DEBUG, ("mptcp stream job create fail a_sock=%d, %s\n", a_sock, strerror(errno)));
    lwip_close(a_sock);
    lwip_close(c_sock);
    return 1;
}

/*===========================================================================
  FUNCTION proxy_server_accept_thread

  DESCRIPTION


  PARAMETERS
    none

  RETURN VALUE
    none

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/

void* proxy_server_accept_thread(void *arg) {
    struct sockaddr_in mptcp_proxy_server_addr;
    struct sockaddr mptcp_proxy_accpet_addr;
    struct timeval mptcp_proxy_listen_tv;
    socklen_t mptcp_proxy_accept_len = sizeof(mptcp_proxy_accpet_addr);
    int mptcp_proxy_listen_select_ret = 0;
    int mptcp_proxy_accept_sock;
    struct thread_context *mptcp_context;
    struct lwip_instance *pInstance = (struct lwip_instance *)arg;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)pInstance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;

    char name[40]={ 0 };
    sprintf(name,"accpet thread:%d",get_instance_logic_id(pInstance));
    setThreadName(name);
    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber++;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);

    mptcp_proxy_server_addr.sin_addr.s_addr = ip4_nat_get_netif_ip(&pInstance->module_conext[CONTEXT_NAT_TYPE]);/*nat_netif.ip_addr.addr;*/
    mptcp_proxy_server_addr.sin_family = AF_INET;
    mptcp_proxy_server_addr.sin_port = PP_HTONS(MPTCP_PROXY_SERVER_PORT+get_instance_logic_id((void *)pInstance));

    LogD("proxy_server_accept_thread entry thread");
    global_set_thread_instance((void *)pInstance);

    pMptcpProxyContext->mptcp_proxy_listen_sock = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, pInstance);
    if (pMptcpProxyContext->mptcp_proxy_listen_sock == -1) {
        LogE("mptcp_proxy_server create socket error");
        return NULL;
    }

    if (lwip_bind(pMptcpProxyContext->mptcp_proxy_listen_sock, (struct sockaddr *) (&mptcp_proxy_server_addr),
                  sizeof(mptcp_proxy_server_addr)) < 0) {
        LogE("mptcp_proxy_server bind error");
        lwip_close(pMptcpProxyContext->mptcp_proxy_listen_sock);
        goto PROXY_SERVER_ACCEPT_THREAD_END;
    }
    
    LogE("proxy_server_accept_thread:instance=%p,proxy server ip=%s, listen port=%d", pInstance, inet_ntoa(mptcp_proxy_server_addr.sin_addr), ntohs(mptcp_proxy_server_addr.sin_port));
    if (lwip_listen(pMptcpProxyContext->mptcp_proxy_listen_sock, 15) < 0) {
        LogE("mptcp_proxy_server listen error");
        lwip_close(pMptcpProxyContext->mptcp_proxy_listen_sock);
        goto PROXY_SERVER_ACCEPT_THREAD_END;
    }

    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_server_accept_thread_flag) {
        FD_ZERO(&pMptcpProxyContext->mptcp_proxy_server_listen_fd_set);
        FD_SET(pMptcpProxyContext->mptcp_proxy_listen_sock, &pMptcpProxyContext->mptcp_proxy_server_listen_fd_set);
        mptcp_proxy_listen_tv.tv_sec = 1;
        mptcp_proxy_listen_tv.tv_usec = 0;

        /*LogD("wait for connect");*/
        mptcp_proxy_listen_select_ret = lwip_select(pMptcpProxyContext->mptcp_proxy_listen_sock + 1,
                                                    &pMptcpProxyContext->mptcp_proxy_server_listen_fd_set,
                                                    NULL, NULL, &mptcp_proxy_listen_tv);
        if (-1 == mptcp_proxy_listen_select_ret) {
            LogE("mptcp_proxy_server mptcp_proxy_listen_select_ret error %s", strerror(
                    errno));
            goto PROXY_SERVER_ACCEPT_THREAD_END;
        } else if (0 == mptcp_proxy_listen_select_ret) {
            /*LogE("mptcp_proxy_server mptcp_proxy_listen_select_ret time out");*/
            
        } else {
            if (FD_ISSET(pMptcpProxyContext->mptcp_proxy_listen_sock, &pMptcpProxyContext->mptcp_proxy_server_listen_fd_set)) {
                mptcp_proxy_accept_sock = lwip_accept(pMptcpProxyContext->mptcp_proxy_listen_sock,
                                                      &mptcp_proxy_accpet_addr,
                                                      &mptcp_proxy_accept_len);
                if (mptcp_proxy_accept_sock != -1) {
#if TEST_PROXY
                    char buf[1024] ={0};
                    lwip_read(mptcp_proxy_accept_sock,buf,sizeof(buf));
                    LogD("proxy recv data:%s",buf);//read
                    memcpy(buf,"Thundersoft",sizeof("Thundersoft"));//write
                    lwip_write(mptcp_proxy_accept_sock,buf,sizeof("Thundersoft"));
#if TEST_PROXY_CLOSE
                    lwip_close(mptcp_proxy_accept_sock);
#endif
#endif
                    LogD("%s instance %p, accept socket  %d success",__func__,pInstance,mptcp_proxy_accept_sock);
                    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
                    pMptcpProxyContext->gMptcpProxyThreadNumber++;
                    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);

                    mptcp_context = (struct thread_context *)malloc( sizeof( struct thread_context));

                    if( NULL == mptcp_context)
                    {
						LogE("%s instance %p, accept socket  %d mptcp_proxy_server malloc ctxt fail",__func__,pInstance,mptcp_proxy_accept_sock);
                        lwip_close(mptcp_proxy_accept_sock);
                        pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
                        pMptcpProxyContext->gMptcpProxyThreadNumber--;
                        pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
                        continue;
                    }
                    mptcp_context->sock = mptcp_proxy_accept_sock;
                    mptcp_context->instance = pInstance;

#if NEW_CODE
                    sys_thread_t thread = sys_thread_new((void *)pInstance,NULL,"proxy_recv_two_data_thread",
                                                         proxy_recv_two_data_thread,
                                                         (void *)mptcp_context, 1024,
                                                         0);
#else
                    sys_thread_t thread = sys_thread_new((void *)pInstance,NULL,"proxy_server_accept_thread",
                                                         proxy_data_thread,
                                                         (void *)mptcp_context, 1024,
                                                         0);
#endif
                    if (thread == NULL) {
                        LogE("%s instance %p, accept socket  %d proxy_data_thread create fails",__func__,pInstance,mptcp_proxy_accept_sock);
                        lwip_close(mptcp_proxy_accept_sock);
                        pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
                        pMptcpProxyContext->gMptcpProxyThreadNumber--;
                        pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
                    }else
                	{
						upThreadPro(&thread->pthread);
                	}
                } else {
                    int errNo = 0;
                    socklen_t optLen = sizeof(errNo);
                    if (lwip_getsockopt(mptcp_proxy_accept_sock, SOL_SOCKET, SO_ERROR, &errNo,
                                        &optLen) == 0) {
                        if (errNo == ENFILE) {
							LogE("%s instance %p, accept socket  %d accept socket number arrived the maxnumber! sleep 20ms",__func__,pInstance,mptcp_proxy_accept_sock);
                            usleep(20000);
                        }
                    }
                }
            }
        }

    }
    PROXY_SERVER_ACCEPT_THREAD_END:
    LogD("mptcp_proxy_server exit thread");
    lwip_close(pMptcpProxyContext->mptcp_proxy_listen_sock);
    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber--;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
    if (pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
        sem_post(&pMptcpProxyContext->gMptcpExitSem);
    }
#if SYS_THREAD_FREE_FUNC
	sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
    return NULL;
}

int mptcp_proxy_peer_exit(void *pArg){
    struct thread_context *pThread_context = (struct thread_context *)pArg;

    if(pThread_context != NULL)
        return pThread_context->exit_flag;
    else
        return 1;
}

void proxy_server_two_stack_thread(void *arg) {
#if LWIP_PACKET_QUEUE
    struct sockaddr_in mptcp_proxy_server_addr;
    struct sockaddr mptcp_proxy_accpet_addr;
    struct timeval mptcp_proxy_listen_tv;
    socklen_t mptcp_proxy_accept_len = sizeof(mptcp_proxy_accpet_addr);
    int mptcp_proxy_listen_select_ret = 0;
    int mptcp_proxy_accept_sock,thread_fail_free = 0;
    sys_thread_t thread = NULL;
    struct thread_context *pThreadTcp_context = NULL, *pThreadMptcp_context = NULL;
    struct packet_queue *pTcpQue = NULL,*pMptcpQue = NULL;
    struct instance_context *pInstance_context = (struct instance_context *)arg;
    struct lwip_instance *pTcpInstance = (struct lwip_instance *)pInstance_context->tcp_instance;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)pTcpInstance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    struct lwip_instance *pstTempInstance = (struct lwip_instance *)(pInstance_context->mptcp_instance);
    mptcp_proxy_context *pTempMptcpProxyContext = (mptcp_proxy_context *)pstTempInstance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;

    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber++;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);

    mptcp_proxy_server_addr.sin_addr.s_addr = ip4_nat_get_netif_ip(&pTcpInstance->module_conext[CONTEXT_NAT_TYPE]);/*nat_netif.ip_addr.addr;*/
    mptcp_proxy_server_addr.sin_family = AF_INET;
    mptcp_proxy_server_addr.sin_port = PP_HTONS(MPTCP_PROXY_SERVER_PORT+get_instance_logic_id((void *)pTcpInstance));

    LogE("proxy_server_two_stack_thread entry thread");
    global_set_thread_instance((void *)pTcpInstance);

    pMptcpProxyContext->mptcp_proxy_listen_sock = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, pTcpInstance);
    if (pMptcpProxyContext->mptcp_proxy_listen_sock == -1) {
        LogE("mptcp_proxy_server create socket error");
        return;
    }

    if (lwip_bind(pMptcpProxyContext->mptcp_proxy_listen_sock, (struct sockaddr *) (&mptcp_proxy_server_addr),
                  sizeof(mptcp_proxy_server_addr)) < 0) {
        LogE("mptcp_proxy_server bind error");
        lwip_close(pMptcpProxyContext->mptcp_proxy_listen_sock);
        goto PROXY_SERVER_ACCEPT_THREAD_END;
    }
    
    LogE("proxy_server_accept_thread:instance=%p,proxy server ip=%s, listen port=%d", pTcpInstance, inet_ntoa(mptcp_proxy_server_addr.sin_addr), ntohs(mptcp_proxy_server_addr.sin_port));
    if (lwip_listen(pMptcpProxyContext->mptcp_proxy_listen_sock, 5) < 0) {
        LogE("mptcp_proxy_server listen error");
        lwip_close(pMptcpProxyContext->mptcp_proxy_listen_sock);
        goto PROXY_SERVER_ACCEPT_THREAD_END;
    }

    while (pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_server_accept_thread_flag) {
        FD_ZERO(&pMptcpProxyContext->mptcp_proxy_server_listen_fd_set);
        FD_SET(pMptcpProxyContext->mptcp_proxy_listen_sock, &pMptcpProxyContext->mptcp_proxy_server_listen_fd_set);
        mptcp_proxy_listen_tv.tv_sec = 0;
        mptcp_proxy_listen_tv.tv_usec = 500000;

        /*LogD("wait for connect");*/
        mptcp_proxy_listen_select_ret = lwip_select(pMptcpProxyContext->mptcp_proxy_listen_sock + 1,
                                                    &pMptcpProxyContext->mptcp_proxy_server_listen_fd_set,
                                                    NULL, NULL, &mptcp_proxy_listen_tv);
        if (-1 == mptcp_proxy_listen_select_ret) {
            LogE("mptcp_proxy_server mptcp_proxy_listen_select_ret error %s", strerror(
                    errno));
            goto PROXY_SERVER_ACCEPT_THREAD_END;
        } else if (0 == mptcp_proxy_listen_select_ret) {
            /*LogE("mptcp_proxy_server mptcp_proxy_listen_select_ret time out");*/
            
        } else {
            if (FD_ISSET(pMptcpProxyContext->mptcp_proxy_listen_sock, &pMptcpProxyContext->mptcp_proxy_server_listen_fd_set)) {
                mptcp_proxy_accept_sock = lwip_accept(pMptcpProxyContext->mptcp_proxy_listen_sock,
                                                      &mptcp_proxy_accpet_addr,
                                                      &mptcp_proxy_accept_len);
                if (mptcp_proxy_accept_sock != -1) {
                    LogE("instance %p, mptcp_proxy_server accept success %d",pTcpInstance,mptcp_proxy_accept_sock);
                    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
                    pMptcpProxyContext->gMptcpProxyThreadNumber++;
                    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
                    

                    pThreadTcp_context = (struct thread_context *)malloc(sizeof(struct thread_context));
                    pTcpQue = packet_queue_init("tcp",1024, (free_node_callback)&free);
                    pMptcpQue = packet_queue_init("mptcp",1024, (free_node_callback)&free);
                    if(pThreadTcp_context == NULL || pTcpQue == NULL || pMptcpQue == NULL){
                        LogE("proxy two stack thread malloc fails");
                        thread_fail_free = 1;
                        goto PROXY_SERVER_ACCEPT_THREAD_END;
                    }

                    pThreadTcp_context->instance = pTcpInstance;
                    pThreadTcp_context->isAsock = 1;
                    pThreadTcp_context->sock = mptcp_proxy_accept_sock;
                    pThreadTcp_context->pMtcpQue = pMptcpQue;
                    pThreadTcp_context->pTcpQue = pTcpQue;
                    pThreadTcp_context->exit_flag = 1;
                    pThreadTcp_context->exit_callback = NULL;
                    pThreadTcp_context->pArg = NULL;
                    
                    thread = sys_thread_new((void *)pTcpInstance,NULL,"proxy_server_accept_thread",
                                                         transfer_data_thread,
                                                         (void *)pThreadTcp_context, 2048,
                                                         0);

                    if (thread == NULL) {
                        LogE("proxy_server_accept_thread create fails");
                        lwip_close(mptcp_proxy_accept_sock);
                        pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
                        pMptcpProxyContext->gMptcpProxyThreadNumber--;
                        pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
                        thread_fail_free = 1;
                        goto PROXY_SERVER_ACCEPT_THREAD_END;
                    }

                    pThreadMptcp_context = (struct thread_context *)malloc(sizeof(struct thread_context));
                    if(pThreadMptcp_context == NULL ){
                        LogE("proxy two stack thread malloc fails");
                        thread_fail_free = 1;
                        goto PROXY_SERVER_ACCEPT_THREAD_END;
                    }
                    mptcp_proxy_tcp_socket_init(mptcp_proxy_accept_sock, pMptcpProxyContext, &pThreadMptcp_context->servaddr);
                    pThreadMptcp_context->instance = pInstance_context->mptcp_instance;
                    pThreadMptcp_context->isAsock = 0;
                    pThreadMptcp_context->sock = -1;
                    pThreadMptcp_context->pMtcpQue = pMptcpQue;
                    pThreadMptcp_context->pTcpQue = pTcpQue;
                    pThreadMptcp_context->exit_flag = 1;

                    pThreadMptcp_context->pArg = (void *)pThreadTcp_context;
                    pThreadTcp_context->pArg = (void *)pThreadMptcp_context;
                    pThreadTcp_context->exit_callback = &mptcp_proxy_peer_exit;
                    pThreadMptcp_context->exit_callback = &mptcp_proxy_peer_exit;
                    
                    thread = sys_thread_new((void *)pInstance_context->mptcp_instance,NULL,"proxy_mptcp_client_thread",
                                                         transfer_data_thread,
                                                         (void *)pThreadMptcp_context, 2048,
                                                         0);

                    if (thread == NULL) {
                        LogE("proxy_mptcp_client_thread create fails");
                        lwip_close(mptcp_proxy_accept_sock);
                        pthread_mutex_lock(&pTempMptcpProxyContext->gMptcpExitMutex);
                        pTempMptcpProxyContext->gMptcpProxyThreadNumber--;
                        pthread_mutex_unlock(&pTempMptcpProxyContext->gMptcpExitMutex);
                        thread_fail_free = 1;
                        goto PROXY_SERVER_ACCEPT_THREAD_END;
                    }
                    
                } else {
                    int errNo = 0;
                    socklen_t optLen = sizeof(errNo);
                    if (lwip_getsockopt(mptcp_proxy_accept_sock, SOL_SOCKET, SO_ERROR, &errNo,
                                        &optLen) == 0) {
                        if (errNo == ENFILE) {
                            LogE("accept socket number arrived the maxnumber! sleep 20ms");
                            usleep(20000);
                        }
                    }
                }
            }
        }

    }
    PROXY_SERVER_ACCEPT_THREAD_END:
    LogD("mptcp_proxy_server exit thread");
    if(thread_fail_free){
        if(pThreadTcp_context != NULL)
            free(pThreadTcp_context);
        if(pThreadMptcp_context != NULL)
            free(pThreadMptcp_context);
        if(pTcpQue != NULL)
            packet_queue_free(pTcpQue);
        if(pMptcpQue != NULL)
            packet_queue_free(pMptcpQue);
    }
    lwip_close(pMptcpProxyContext->mptcp_proxy_listen_sock);
    if(pInstance_context != NULL)
        free((void *)pInstance_context);
    pthread_mutex_lock(&pMptcpProxyContext->gMptcpExitMutex);
    pMptcpProxyContext->gMptcpProxyThreadNumber--;
    pthread_mutex_unlock(&pMptcpProxyContext->gMptcpExitMutex);
    if (pMptcpProxyContext->gMptcpProxyThreadNumber == 0) {
        sem_post(&pMptcpProxyContext->gMptcpExitSem);
    }
#if SYS_THREAD_FREE_FUNC
	sys_thread_free_self();
#endif
    pthread_detach(pthread_self());  //to avoid thread resource leak
#endif
    return;
}

/*===========================================================================
  FUNCTION mptcp_proxy_client_netif_output

  DESCRIPTION


  PARAMETERS
    none

  RETURN VALUE
    none

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/
err_t
mptcp_proxy_client_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    //TODO: call tunnel interface to send data to real network
#if 0
    struct lwip_instance *instance = (struct lwip_instance *)netif->instance;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    struct pbuf *nbuf;
    
    if(!pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag)
    {
       return ERR_OK;
    }
    nbuf = pbuf_alloc(netif->instance,PBUF_LINK, (u16_t)p->tot_len, PBUF_RAM);
    if(nbuf == NULL)
        return ERR_MEM;
    if(pbuf_copy_partial(p, nbuf->payload, p->tot_len, 0) < p->tot_len){
        pbuf_free(nbuf);
        return ERR_MEM;
    }
    pMptcpProxyContext->tunnel_send_cnt++;
    LWIP_DEBUGF(LWIP_STREAM_ALL_DEBUG, ("mptcp_proxy_client_netif_output %p instance ip=%s send cnt=%d ", instance,inet_ntoa(*ipaddr),pMptcpProxyContext->tunnel_send_cnt));

#if LWIP_PACKET_QUEUE
    packet_queue_try_enque(pMptcpProxyContext->pPacketTunnelQue,(void *)nbuf);
#else
    while(!Enque(pMptcpProxyContext->pTunnelQue,nbuf) ){
        if(!pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag)
        {
            pbuf_free(nbuf);
            break;
        }
    }
#endif
#else
    struct lwip_instance *instance = (struct lwip_instance *)netif->instance;
#if LWIP_PCAP_SUPPORT
    tun_write_pcap(vpn_pcap_fd, (char *)p->payload, ((int)p->len), LWIP_PCAP_TUNNEL_DOWN_STRAM);
#endif
    mutp_encode_send(instance,ipaddr->addr,0,p,1);
    #endif
    return ERR_OK;
}

void mutp_output_thread(void *args){
    struct pbuf *p = NULL;
    struct ip_hdr *temp;
    struct tcp_hdr *tcpHdr;
    void *pstInstance = args;
    #if LWIP_PACKET_QUEUE
    struct pbuf *pList[MAX_FETCH_LIST];
    int num,i;
    #endif

    global_set_thread_instance(pstInstance);
    char name[40]={ 0 };
    sprintf(name,"mutp_output_thread:%d",get_instance_logic_id(pstInstance));
    setThreadName(name);
    struct lwip_instance *instance = (struct lwip_instance *)pstInstance;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    while(pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag){
    #if LWIP_PACKET_QUEUE
        if((num = packet_queue_try_deque_list(pMptcpProxyContext->pPacketTunnelQue, MAX_FETCH_LIST, (void **)pList)) > 0)
    #else
        if((p = (struct pbuf *)Deque(pMptcpProxyContext->pTunnelQue)) != NULL)
    #endif
        {
        #if LWIP_PACKET_QUEUE
            for(i=0;i<num;i++){
            p = (struct pbuf *)pList[i];
            if(p != NULL){
        #endif
            temp = (struct ip_hdr *) p->payload;
            tcpHdr = (struct tcp_hdr *) (temp + 1);

            #if LWIP_PCAP_SUPPORT
            tun_write_pcap(vpn_pcap_fd, (char *)p->payload, ((int)p->len), LWIP_PCAP_TUNNEL_UP_STRAM);
            #endif
            mutp_encode_send(pstInstance,temp->dest.addr, tcpHdr->dest, p,1);
            pMptcpProxyContext->tunnel_recv_cnt++;
        #if LWIP_PACKET_QUEUE
                }
            }
        #endif
        }
    }
}
/*===========================================================================
  FUNCTION mptcp_proxy_client_netif_tx_func

  DESCRIPTION


  PARAMETERS
    none

  RETURN VALUE
    none

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/

static err_t mptcp_proxy_client_netif_tx_func(struct netif *netif, struct pbuf *p) {
    LogD("mptcp_proxy_client_netif_tx_func");
    return ERR_OK;
}

/*===========================================================================
  FUNCTION mptcp_proxy_client_netif_init

  DESCRIPTION


  PARAMETERS
    none

  RETURN VALUE
    none

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/

static err_t mptcp_proxy_client_netif_init(struct netif *netif) {
    if (NULL == netif)
        return ERR_ABRT;

    LogD("mptcp_proxy_client_netif_init entry");

    netif->name[0] = 'P';
    netif->name[1] = 'C';
    netif->output = mptcp_proxy_client_netif_output;
    netif->linkoutput = mptcp_proxy_client_netif_tx_func;
#if LARGE_PACKET
    netif->mtu = 19640;
#else
    netif->mtu = 1500;
#endif
#if LWIP_MPTCP_SUPPORT || LWIP_PERFORMANCE_IMPROVE
    netif->is_nat_if = 0;
#endif
    netif->flags = NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    netif->hwaddr_len = 6;
    netif->hwaddr[0] = 0x00;
    netif->hwaddr[1] = 0x23;
    
    netif->hwaddr[2] = 0xC3;
    netif->hwaddr[3] = 0xDD;
    netif->hwaddr[4] = 0xDD;
    netif->hwaddr[5] = 0xDD;

    return ERR_OK;
}

/*===========================================================================
  FUNCTION mptcp_proxy_client_netif_input

  DESCRIPTION


  PARAMETERS
    none

  RETURN VALUE
    none

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/

err_t mptcp_proxy_client_netif_input(struct pbuf *p, struct netif *netif) {
    struct lwip_instance* instance ;
    mptcp_proxy_context* pMptcpProxyContext;
    

    if (NULL == p || NULL == netif)
        return ERR_ABRT;
    instance = (struct lwip_instance *)netif->instance;
    pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;
    
    struct ip_hdr *iph = (struct ip_hdr *) p->payload;
    struct tcp_hdr *tcph = (struct tcp_hdr *)(iph+1);

    #if !LINUX_PLATFORM
    LWIP_DEBUGF(LWIP_STREAM_ALL_DEBUG, ("mptcp_proxy_client_netif_input entry instance%p dst ip=%s, src ip=%s, port=%d len=%d",
        instance,inet_ntoa(iph->dest),inet_ntoa(iph->src), ntohs(tcph->dest),p->tot_len));
    #endif
    
    if (IP_PROTO_TCP == IPH_PROTO(iph)) {
        LogI("mptcp_proxy_client_netif_input");

        if (tcpip_input(p, &pMptcpProxyContext->mptcp_proxy_client_netif) != ERR_OK){
                LogI("%s:%d: tcpip_input() failed",
                     __FUNCTION__, __LINE__);
                pMptcpProxyContext->vpn_recv_err_cnt++;
        }else{
            pMptcpProxyContext->vpn_recv_cnt++;
        }
    }

    return ERR_OK;
}

/*===========================================================================
  FUNCTION mptcp_proxy_client_add_netif

  DESCRIPTION


  PARAMETERS
    none

  RETURN VALUE
    none

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/

void mptcp_proxy_client_add_netif(struct lwip_instance *pstInstance) {
    ip4_addr_t mptcp_proxy_client_netif_addr;
    ip4_addr_t mptcp_proxy_client_netif_netmask;
    ip4_addr_t mptcp_proxy_client_netif_gateway;

    ip4_addr_t addr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    struct lwip_instance* instance ;
    mptcp_proxy_context* pMptcpProxyContext;


    IP4_ADDR(&mptcp_proxy_client_netif_addr,
             mptcp_proxy_client_netif_addr_array[0], mptcp_proxy_client_netif_addr_array[1],
             mptcp_proxy_client_netif_addr_array[2], mptcp_proxy_client_netif_addr_array[3]);
    IP4_ADDR(&mptcp_proxy_client_netif_netmask,
             mptcp_proxy_client_netif_netmask_array[0], mptcp_proxy_client_netif_netmask_array[1],
             mptcp_proxy_client_netif_netmask_array[2], mptcp_proxy_client_netif_netmask_array[3]);
    IP4_ADDR(&mptcp_proxy_client_netif_gateway,
             mptcp_proxy_client_netif_gateway_array[0], mptcp_proxy_client_netif_gateway_array[1],
             mptcp_proxy_client_netif_gateway_array[2], mptcp_proxy_client_netif_gateway_array[3]);

    LogD("mptcp_proxy_client_add_netif entry");
#if 0
    mptcp_proxy_client_netif_addr.addr = ppca_s->mccp_ue_ip;
    mptcp_proxy_client_netif_gateway.addr = (ppca_s->mccp_ue_ip & 0x01FFFFFF);
#else
#if !WIFI_LTE_SWITCH
    mptcp_proxy_client_netif_addr.addr = ppca_s->mccp_mpgw_ip;
    mptcp_proxy_client_netif_gateway.addr = (ppca_s->mccp_mpgw_ip & 0x01FFFFFF);
#else
    if(isSetLteAddr) {
        mptcp_proxy_client_netif_addr.addr = ppca_s->mccp_mpgw_ip;
        mptcp_proxy_client_netif_gateway.addr = (ppca_s->mccp_mpgw_ip & 0x01FFFFFF);
    }
    if(isSetWifiAddr && !isSetLteAddr) {
        mptcp_proxy_client_netif_addr.addr = ppca_s->mccp_mpgw_ip1;
        mptcp_proxy_client_netif_gateway.addr = (ppca_s->mccp_mpgw_ip1 & 0x01FFFFFF);
    }
#endif
#endif
#if UNITE_TEST
    mptcp_proxy_client_netif_addr.addr = inet_addr("192.168.43.25");
    mptcp_proxy_client_netif_gateway.addr = htonl(3232246553 & 0xFFFFFF01);
#endif
    instance = (struct lwip_instance *)pstInstance;
    pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;

    netif_add(&pstInstance->module_conext[CONTEXT_NETIF_TYPE], &pMptcpProxyContext->mptcp_proxy_client_netif,
              &mptcp_proxy_client_netif_addr, &mptcp_proxy_client_netif_netmask,
              &mptcp_proxy_client_netif_gateway, &pMptcpProxyContext->mptcp_proxy_client_netif,
              mptcp_proxy_client_netif_init, mptcp_proxy_client_netif_input);

#if !LWIP_PERFORMANCE_IMPROVE_CHECKLOG
    netif_set_default(&pMptcpProxyContext->mptcp_proxy_client_netif);
#endif
    netif_set_default(&pMptcpProxyContext->mptcp_proxy_client_netif);
    netif_set_up(&pMptcpProxyContext->mptcp_proxy_client_netif);

    return;
}

/*===========================================================================
  FUNCTION mptcp_proxy_server_init

  DESCRIPTION
    this function init MPTCP module, include alloc memory .eg
    we should call this when APP side click OPEN button

  PARAMETERS
    mptcp_data_init_V01

  RETURN VALUE
    err_t

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/
err_t mptcp_proxy_server_init(struct lwip_instance *pstInstance, struct lwip_instance *pstMptcpInstance) {
    mptcp_proxy_context *pMptcpProxyContext, *pTempMptcpProxyContext;
    struct module_conext* pModuleContext = &pstInstance->module_conext[CONTEXT_PROXY_TYPE];
    struct instance_context *pInstance_context = (struct instance_context *)malloc(sizeof(struct instance_context));
    struct lwip_instance *pstTempInstance;
    
    pMptcpProxyContext = (mptcp_proxy_context *)malloc(sizeof(mptcp_proxy_context));
    memset(pMptcpProxyContext,0,sizeof(mptcp_proxy_context));

    pInstance_context->tcp_instance = pstInstance;
    pInstance_context->mptcp_instance = pstMptcpInstance;
    
    pModuleContext->pCcontext = pMptcpProxyContext;
    pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_server_accept_thread_flag = 1;
    pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag = 1;
    pMptcpProxyContext->gMptcpProxyThreadNumber = 0;
    sem_init(&pMptcpProxyContext->gMptcpExitSem, 0, 0);
    sem_init(&pMptcpProxyContext->proxydataSndSem, 0, 0);
    pthread_mutex_init(&pMptcpProxyContext->gMptcpExitMutex, NULL);
    pMptcpProxyContext->recvDataListHead = pMptcpProxyContext->recvDataListEnd = NULL;
    LogD("mptcp_proxy_server_init entry");

#if LWIP_TWO_TCP_STACK
    
#if !LWIP_PERFORMANCE_TEST_ENABLE_VETH0
    mptcp_proxy_client_add_netif(pstInstance);

    pTempMptcpProxyContext = malloc(sizeof(mptcp_proxy_context));
    memset(pTempMptcpProxyContext,0,sizeof(mptcp_proxy_context));
    pstTempInstance = (struct lwip_instance *)(pInstance_context->mptcp_instance);
    pstTempInstance->module_conext[CONTEXT_PROXY_TYPE].pCcontext = pTempMptcpProxyContext;

    mptcp_proxy_client_add_netif(pInstance_context->mptcp_instance);
#endif
#if LWIP_PACKET_QUEUE
    pMptcpProxyContext->pPacketTunnelQue = packet_queue_init("Tunnel",4096,(free_node_callback)&pbuf_free);
    pTempMptcpProxyContext->pPacketTunnelQue = pMptcpProxyContext->pPacketTunnelQue;
#else
    pMptcpProxyContext->pTunnelQue = queueCreate("tunnel",4096);
    pTempMptcpProxyContext->pTunnelQue = pMptcpProxyContext->pTunnelQue;
#endif
    
    pTempMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_server_accept_thread_flag = 1;
    pTempMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag = 1;
#if 0
    LWIP_ASSERT("mutp_output_thread create failed", sys_thread_new((void *)pstInstance,NULL,
            "mutp_output_thread", mutp_output_thread, (void *) pInstance_context->mptcp_instance, 1024, 0) != NULL);
#endif
#else
#if !LWIP_PERFORMANCE_TEST_ENABLE_VETH0
    mptcp_proxy_client_add_netif(pstInstance);
#endif
    pMptcpProxyContext->pTunnelQue = queueCreate((char*)"tunnel",4096);
    /*
    LWIP_ASSERT("mutp_output_thread create failed", sys_thread_new((void *)pstInstance,NULL,
            "mutp_output_thread", mutp_output_thread, (void *) pstInstance, 1024, 0) != NULL);
    */
#endif  
    // todo for rechange the mccp_mpgw_ip
#if !WIFI_LTE_SWITCH
    pMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;
#else
    if(isSetLteAddr) {
        pMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;
    }
    if(isSetWifiAddr && !isSetLteAddr) {
        pMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip1;
    }
#endif
    pMptcpProxyContext->mptcp_sock.sin_port = ppca_s->mccp_mpgw_port;
    pMptcpProxyContext->mptcp_sock.sin_family = AF_INET;

    //mptcp client socket
#if LWIP_PERFORMANCE_TEST_ENABLE_VETH0
    //pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_addr.s_addr = p_netif_default->ip_addr.addr;
#else
    pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_addr.s_addr = ppca_s->mccp_ue_ip;
#endif
    pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_family = AF_INET;
    pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_port = 0;
#if UNITE_TEST
    pMptcpProxyContext->mptcp_sock.sin_addr.s_addr = inet_addr("192.168.43.252");
    pMptcpProxyContext->mptcp_sock.sin_port = htons(5557);
    pMptcpProxyContext->mptcp_sock.sin_family = AF_INET;

    pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_addr.s_addr = inet_addr("192.168.43.25");
    pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_family = AF_INET;
    pMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_port = 0;
#endif

#if !LWIP_TWO_TCP_STACK
    sys_thread_t thread = sys_thread_new((void *)pstInstance,NULL,"proxy_server_accept_thread", proxy_server_accept_thread,
                                         (void *)pstInstance, 1024, 0);
#else
#if !WIFI_LTE_SWITCH
    pTempMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;
#else
    if(isSetLteAddr){
        pTempMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip;
    }
    if(isSetWifiAddr && !isSetLteAddr){
        pTempMptcpProxyContext->mptcp_sock.sin_addr.s_addr = ppca_s->mccp_mpgw_ip1;
    }
#endif
    pTempMptcpProxyContext->mptcp_sock.sin_port = ppca_s->mccp_mpgw_port;
    pTempMptcpProxyContext->mptcp_sock.sin_family = AF_INET;

    pTempMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_addr.s_addr = ppca_s->mccp_ue_ip;
    pTempMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_family = AF_INET;
    pTempMptcpProxyContext->mptcp_proxy_client_sock_addr.sin_port = 0;
    
    pTempMptcpProxyContext->gMptcpProxyThreadNumber = 0;
    sem_init(&pTempMptcpProxyContext->gMptcpExitSem, 0, 0);
    sem_init(&pTempMptcpProxyContext->proxydataSndSem, 0, 0);
    pthread_mutex_init(&pTempMptcpProxyContext->gMptcpExitMutex, NULL);

    sys_thread_t thread = sys_thread_new((void *)pstInstance,NULL,"proxy_server_two_stack_thread", proxy_server_two_stack_thread,
    (void *)pInstance_context, 1024, 0);

#endif
    if (thread == NULL) {
        LogE("create accept thread fails");
    }

    return ERR_OK;
}

err_t mptcp_proxy_server_destroy(void* instance) {
    struct lwip_instance * lwipInstance = (struct lwip_instance *)instance;
    mptcp_proxy_context *pMptcpProxyContext = (mptcp_proxy_context *)lwipInstance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;


    LogD("mptcp_proxy_server_destroy entry");
    pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_server_accept_thread_flag = 0;
    pMptcpProxyContext->g_mptcp_proxy_thread_config.mptcp_proxy_data_thread_flag = 0;

    if (pMptcpProxyContext->gMptcpProxyThreadNumber > 0) {
        do {
            struct timespec ts;
            if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
                break;
            }
            LogD("wait Thread Number =%d, max wait 1s", pMptcpProxyContext->gMptcpProxyThreadNumber);
            ts.tv_sec += 1;
            while ((sem_timedwait(&pMptcpProxyContext->gMptcpExitSem, &ts)) == -1 && errno == EINTR)
                continue;       /* Restart if interrupted by handler */
        } while (0);
    }
    netif_remove(&pMptcpProxyContext->mptcp_proxy_client_netif);
    sem_destroy(&pMptcpProxyContext->gMptcpExitSem);
    sem_destroy(&pMptcpProxyContext->proxydataSndSem);
    pthread_mutex_destroy(&pMptcpProxyContext->gMptcpExitMutex);
    LogD("mptcp_proxy_server_destroy leave");
    return ERR_OK;
}

struct netif *mptcp_proxy_get_netif(void *pLwIpInstance){
    
    struct lwip_instance* instance ;
    mptcp_proxy_context* pMptcpProxyContext;
    

    if (NULL == pLwIpInstance )
        return NULL;
    instance = (struct lwip_instance *)pLwIpInstance;
    pMptcpProxyContext = (mptcp_proxy_context *)instance->module_conext[CONTEXT_PROXY_TYPE].pCcontext;

    return &pMptcpProxyContext->mptcp_proxy_client_netif;
}

int mptcp_proxy_debug_counter(void *instance, char *pBuffer, unsigned int len)
{
    struct module_conext *pModuleContext;
    mptcp_proxy_context *pMptcpProxyContext;
    int nPos = 0,offset=0;

    if(instance != NULL){
       pModuleContext = &(((struct lwip_instance *)instance)->module_conext[CONTEXT_NAT_TYPE]);
       pMptcpProxyContext = (mptcp_proxy_context *)pModuleContext->pCcontext;

       offset = 0;
       nPos = snprintf(pBuffer,len,"MPTCP Prxoy vpn recv    =   0x%08x\r\n",pMptcpProxyContext->vpn_recv_cnt);
       offset += nPos;

       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy vpn send  =   0x%08x\r\n",pMptcpProxyContext->vpn_send_cnt);
       offset += nPos;

       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy vpn recv err  =   0x%08x\r\n",pMptcpProxyContext->vpn_recv_err_cnt);
       offset += nPos;

       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy tunnel recv   =   0x%08x\r\n",pMptcpProxyContext->tunnel_recv_cnt);
       offset += nPos;

       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy tunnel send   =   0x%08x\r\n",pMptcpProxyContext->tunnel_send_cnt);
       offset += nPos;

       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy MPTCP2TCP recv=   0x%08x\r\n",pMptcpProxyContext->mptcp2tcp_recv_cnt);
       offset += nPos;

       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy MPTCP2TCP send=   0x%08x\r\n",pMptcpProxyContext->mptcp2tcp_send_cnt);
       offset += nPos;
       
       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy TCP2MPTCP recv=   0x%08x\r\n",pMptcpProxyContext->tcp2mptcp_recv_cnt);
       offset += nPos;

       nPos = snprintf(pBuffer+offset,len-offset,"MPTCP Prxoy TCP2MPTCP send=   0x%08x\r\n",pMptcpProxyContext->tcp2mptcp_send_cnt);
       offset += nPos;
    }

    return offset;
}
