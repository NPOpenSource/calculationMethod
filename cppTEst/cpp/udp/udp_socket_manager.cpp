/******************************************************************************
NAME  =	 udp_socket_manager.cpp :
FUNC  =	 manager udp socket;
NOTE  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/
#include <pthread.h>
#include <semaphore.h>
#include "udp_socket_manager.h"
#include <map>
#include "lwip/lwipopts.h"
#include "lwip/ip.h"
#include "lwip/sys.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include "udp_handle.h"
#include <string>

//#define __android_log_print(...) do{}while(0)

#define FEATURE_WIFI_OCO

#define EXPIRE_CHECK_TIME 2
#define EXPIRE_CHECK_COUNT 30

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_UDP

int g_sm_end = 0;
int g_wait_sem_flag = 0;
sem_t gSemRecv;

extern mptcp_data_init_V01 gMPTCP_config;
extern vpn_thread_data gVPN_thread_data;
#define MAX_UDP_DATA  2048
#ifdef  FEATURE_WIFI_OCO
ip4_addr_p_t curIp;
#endif
PACK_STRUCT_BEGIN
/* The IPv4 header */
struct udp_packet_net_key_pair {
    struct udp_packet_net_key_pair *next;
    /* source and destination IP addresses */
    ip4_addr_p_t src_ip;
    ip4_addr_p_t dest_ip;
    /* source and destination port number */
    u16_t src_port;
    u16_t dest_port;  /* src/dest UDP ports */
} PACK_STRUCT_STRUCT;

PACK_STRUCT_END

PACK_STRUCT_BEGIN
/* The IPv4 header */
struct udp_sock_pair {
    /* socket fd */
    int sockfd;
    /* used for count if not data transmission */
    int count;
    /* udp data(udp header + data) */
    struct udp_packet_net_key_pair *net_key_pair_list;
} PACK_STRUCT_STRUCT;

PACK_STRUCT_END

PACK_STRUCT_BEGIN
/* The IPv4 header */
struct udp_localsock_list {
    struct udp_localsock_list *next;
    int sock;
    ip4_addr_p_t src_ip;
    u16_t src_port;
} PACK_STRUCT_STRUCT;

PACK_STRUCT_END

struct udp_localsock_pair {
    struct udp_localsock_list *udp_list;
    ip4_addr_p_t dest_ip;
    u16_t dest_port;  /* src/dest UDP ports */
};

/*char* = dstip+dstport*/
/*using for store dst service address pair*/;
std::map<std::string, struct udp_localsock_pair *> udp_localsock_map;
/*using for receiving udp data from network process*/
std::map<int, struct udp_sock_pair *> udp_remotsock_map;
pthread_mutex_t localsock_mutex;
pthread_mutex_t remotesock_mutex;
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
static void free_udp_sock_pair(udp_sock_pair *sockPair) {
    char tempkey[64] = {0};
    if (sockPair != NULL) {
        LogD("udp_connect_expire_check: shutdown socket fd=%d", sockPair->sockfd);
        struct udp_packet_net_key_pair *p = sockPair->net_key_pair_list;
        struct udp_packet_net_key_pair *q = NULL;
        while (p != NULL) {
            /*free matched localsockmap items*/
            sprintf(tempkey, "%d%d", (int) (p->dest_ip.addr), p->dest_port);
            pthread_mutex_lock(&localsock_mutex);
            std::map<std::string, struct udp_localsock_pair *>::iterator iter = udp_localsock_map.find(
                    tempkey);
            if (udp_localsock_map.end() != iter) {
                struct udp_localsock_list *m = NULL;
                struct udp_localsock_list *pre = NULL;
                m = iter->second->udp_list;
                while (m != NULL) {
                    if (m->sock == sockPair->sockfd) {
                        if (m == iter->second->udp_list) {
                            iter->second->udp_list = m->next;
                        } else {
                            pre->next = m->next;
                        }
                        free(m);
                        m = NULL;
                        break;
                    }
                    pre = m;
                    m = m->next;
                }
                if (iter->second->udp_list == NULL) {
                    free(iter->second);
                    udp_localsock_map.erase(iter);
                }
            }
            pthread_mutex_unlock(&localsock_mutex);
            q = p;
            p = p->next;
            free(q);
        }
        close(sockPair->sockfd);
        free(sockPair);
    }
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
static void udp_connect_expire_check() {
    pthread_mutex_lock(&remotesock_mutex);
    for (std::map<int, udp_sock_pair *>::iterator it = udp_remotsock_map.begin();
         it != udp_remotsock_map.end();) {
        it->second->count++;
        LogI("udp socket count =%d", it->second->count);
        if (it->second->count > EXPIRE_CHECK_COUNT) {
            free_udp_sock_pair(it->second);
            udp_remotsock_map.erase(it++);
            LogD("udp_remotsock_map size:=%d",
                (int)udp_remotsock_map.size());
        } else {
            it++;
        }
    }
    pthread_mutex_unlock(&remotesock_mutex);
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
static void close_and_remove_fd_from_map() {
    LogD("clear the local and remote map");
    pthread_mutex_lock(&localsock_mutex);
    for (std::map<std::string, struct udp_localsock_pair *>::iterator it = udp_localsock_map.begin();
         it != udp_localsock_map.end();) {
        struct udp_localsock_pair *p = it->second;
        struct udp_localsock_list *m = NULL;
        struct udp_localsock_list *n = NULL;
        m = p->udp_list;
        while (m != NULL) {
            n = m;
            m = m->next;
            free(n);
        }
        udp_localsock_map.erase(it++);
        free(p);
    }
    pthread_mutex_unlock(&localsock_mutex);
    pthread_mutex_lock(&remotesock_mutex);
    if (udp_remotsock_map.size() > 0) {
        for (std::map<int, udp_sock_pair *>::iterator it = udp_remotsock_map.begin();
             it != udp_remotsock_map.end();) {
            close(it->first);
            struct udp_packet_net_key_pair *p = it->second->net_key_pair_list;
            struct udp_packet_net_key_pair *q = NULL;
            while (p != NULL) {
                q = p;
                p = p->next;
                free(q);
            }
            free(it->second);
            udp_remotsock_map.erase(it++);
        }
    }
    pthread_mutex_unlock(&remotesock_mutex);

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
int sm_init(void *instance) {
    /*init semaphore object*/
    sem_init(&gSemRecv, 0, 0);
    g_sm_end = 0;
    pthread_mutex_init(&localsock_mutex, NULL);
    pthread_mutex_init(&remotesock_mutex, NULL);
    sys_thread_t thId = NULL;
    gVPN_thread_data.receive_udp_packet_thread_flag = 0;
    /*if (pthread_create(&thId, NULL, receive_udp_packet_thread, NULL) != 0)*/
//	if((thId = sys_thread_new(instance,NULL,"receive_udp_packet_thread",(lwip_thread_fn)receive_udp_packet_thread,NULL,2048,0)) == NULL)
//	{
//        LogD("sm_init: vpn_tun_send_udp_packet_handle thread create fail !");
//        /*destroy semaphore object*/
//        sem_destroy(&gSemRecv);
//        return -1;
//    }
    if(thId != NULL)
    gVPN_thread_data.receive_udp_packet_thread_t = thId->pthread;
    gVPN_thread_data.receive_udp_packet_thread_flag = 1;
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
void sm_release() {


    g_sm_end = 1;
    if (g_wait_sem_flag == 1) {
        /*notify the semaphore object and quit thread*/
        sem_post(&gSemRecv);
    }
    //pthread_cancel(gVPN_thread_data.receive_udp_packet_thread_t);
    LogD("udp_handle_release : Stop udp Threads ");
    if(gVPN_thread_data.receive_udp_packet_thread_t != 0) {
        pthread_join(gVPN_thread_data.receive_udp_packet_thread_t, NULL);
        /*destroy semaphore object*/
        sem_destroy(&gSemRecv);
        gVPN_thread_data.receive_udp_packet_thread_flag = 0;
    }
    LogD("receive_udp_packet_thread end!");
    close_and_remove_fd_from_map();
    pthread_mutex_destroy(&localsock_mutex);
    pthread_mutex_destroy(&remotesock_mutex);
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
int create_udp_socket(const ip4_addr_p_t *src_ip) {

    socklen_t sin_size;
    int sockfd;
    int ret = -1;
    struct sockaddr_in localAddr;
    bzero(&localAddr, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = 0;
    localAddr.sin_addr.s_addr = src_ip->addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LogE("create socket fails:%s", strerror(errno));
        return (-1);
    }

#if !LINUX_PLATFORM
    JNIEnv *env = NULL;
    /*getting environment parameter from global JavaVM*/
    int status = gJavaVM->AttachCurrentThread(&env, NULL);
    if (env == NULL || status < 0) {
        LogE("create_udp_socket: get environment fail.");
        close(sockfd);
        return -1;
    }
    /*Get the java class */
    jclass javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogE("create_udp_socket: get java class object fail.");
        close(sockfd);
        gJavaVM->DetachCurrentThread();
        return -1;
    }

    /*Get the callback function in the java class */
    jmethodID gMid = env->GetMethodID(javaClass, "protectCFd", "(I)I");
    if (gMid == NULL) {
        LogE("create_udp_socket: get callback method fail. %s", strerror(errno));
        close(sockfd);
        gJavaVM->DetachCurrentThread();
        return -1;
    }

    LogD("tun status: %s", tunUp == 1 ? "UP" : "DOWN");
    if (env->CallIntMethod(gJavaObj, gMid, sockfd)) {
        LogE("create_udp_socket: CallVoidMethod fail. %s", strerror(errno));
        close(sockfd);
        gJavaVM->DetachCurrentThread();
        return -1;
    }
    gJavaVM->DetachCurrentThread();
#endif
    LogD("UDP bind local addr:%s", inet_ntoa(localAddr.sin_addr));
    ret = bind(sockfd, (struct sockaddr *) &localAddr, sizeof(localAddr));
    if (ret < 0) {
        LogE("create_udp_socket: bind ip:%s fail. errorno:%d", inet_ntoa(localAddr.sin_addr),
             errno);
        close(sockfd);
        return -1;
    }
    return sockfd;
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
int find_socket(const ip4_addr_p_t *src_ip, u16_t src_port,
                const ip4_addr_p_t *dst_ip, u16_t dst_port) {

    int sock = -1;
    if (g_sm_end) {
        return sock;
    }
#ifdef FEATURE_WIFI_OCO
    ip4_addr_p_t tempIp = UDP_SOCKET_CUR_IP;
    LogD("priority net type:%s,lte prio:%d,wifi prio:%d",
             (gMPTCP_config.lpriority > gMPTCP_config.wpriority ? "LTE" : "WIFI"),
             gMPTCP_config.lpriority, gMPTCP_config.wpriority);
    if (curIp.addr != tempIp.addr) {
        LogI("curIp:%x,tempIp:%x", curIp.addr, tempIp.addr);
        /*if local ip changed, release all ip pair*/
        close_and_remove_fd_from_map();
        curIp.addr = tempIp.addr;
    }
#endif

    char tmpkey[64];
    sprintf(tmpkey, "%d%d", dst_ip->addr, dst_port);
    struct udp_localsock_pair *tmp_localsock = NULL;
    /*sync the map handling with deleting operation*/
    LogD("find_socket udp socket, start sync");
    pthread_mutex_lock(&localsock_mutex);
    std::map<std::string, struct udp_localsock_pair *>::iterator iter = udp_localsock_map.find(
            tmpkey);
    if (udp_localsock_map.end() != iter) {
        tmp_localsock = iter->second;
    }
    /*do not find the same dst ip and dst port pair*/
    if (tmp_localsock == NULL) {
        pthread_mutex_unlock(&localsock_mutex);
        struct udp_localsock_list *usp = (struct udp_localsock_list *) malloc(
                sizeof(struct udp_localsock_list));
        if (usp == NULL) {
            LogE("find_socket: malloc	fail.");
            return -1;
        }
        usp->next = NULL;
        usp->src_ip = *src_ip;
        usp->src_port = src_port;
        /* we use the fist socket send data to new server*/
        pthread_mutex_lock(&remotesock_mutex);
        if (udp_remotsock_map.size() > 0) {
            struct udp_packet_net_key_pair *tmpkp = (struct udp_packet_net_key_pair *) malloc(
                    sizeof(struct udp_packet_net_key_pair));
            if (tmpkp == NULL) {
                LogE("find_socket: malloc  fail.");
                free(usp);
                pthread_mutex_unlock(&remotesock_mutex);
                return -1;
            }
            tmpkp->src_ip = *src_ip;
            tmpkp->src_port = src_port;
            tmpkp->dest_ip = *dst_ip;
            tmpkp->dest_port = dst_port;
            usp->sock = udp_remotsock_map.begin()->first;
            LogD("clear fd %d the count", usp->sock);
            udp_remotsock_map.begin()->second->count = 0;
            tmpkp->next = udp_remotsock_map.begin()->second->net_key_pair_list;
            udp_remotsock_map.begin()->second->net_key_pair_list = tmpkp;
            pthread_mutex_unlock(&remotesock_mutex);
        } else {
            pthread_mutex_unlock(&remotesock_mutex);
            struct udp_sock_pair *psockpair = (struct udp_sock_pair *) malloc(
                    sizeof(struct udp_sock_pair));
            if (psockpair == NULL) {
                LogE("find_socket: malloc  fail.");
                free(usp);
                return -1;
            }
            struct udp_packet_net_key_pair *tmpkp = (struct udp_packet_net_key_pair *) malloc(
                    sizeof(struct udp_packet_net_key_pair));
            if (tmpkp == NULL) {
                LogE("find_socket: malloc  fail.");
                free(usp);
                free(psockpair);
                return -1;
            }
#ifdef FEATURE_WIFI_OCO
            ip4_addr_p_t addrForDebug = UDP_SOCKET_CUR_IP;
            LogD("current ip addr:%08x", *((u32_t *)&addrForDebug));
            usp->sock = create_udp_socket(&(UDP_SOCKET_CUR_IP));
#else
            usp->sock = create_udp_socket(&gMPTCP_config.wifiIp);
#endif
            if (usp->sock < 0) {
                LogE("find_socket: create udpsocket  fail.");
                free(usp);
                free(psockpair);
                free(tmpkp);
                return -1;
            }

            tmpkp->src_ip = *src_ip;
            tmpkp->src_port = src_port;
            tmpkp->dest_ip = *dst_ip;
            tmpkp->dest_port = dst_port;
            tmpkp->next = NULL;
            psockpair->net_key_pair_list = tmpkp;
            psockpair->sockfd = usp->sock;
            psockpair->count = 0;
            pthread_mutex_lock(&remotesock_mutex);
            udp_remotsock_map.insert(std::make_pair((int)psockpair->sockfd, psockpair));
            pthread_mutex_unlock(&remotesock_mutex);
        }
        struct udp_localsock_pair *udp_pair = (struct udp_localsock_pair *) malloc(
               sizeof(struct udp_localsock_pair));
        udp_pair->udp_list = usp;
        udp_pair->dest_ip = *dst_ip;
        udp_pair->dest_port = dst_port;
        pthread_mutex_lock(&localsock_mutex);
        udp_localsock_map.insert(std::make_pair(tmpkey, udp_pair));
        sock = usp->sock;
        pthread_mutex_unlock(&localsock_mutex);
    } else {
        /* if we found the same service address, we should check the src address firstly.*/
        struct udp_localsock_list *tmp_sock_list = NULL;
        tmp_sock_list = tmp_localsock->udp_list;
        while (tmp_sock_list != NULL) {
            if (tmp_sock_list->src_ip.addr == src_ip->addr &&
                tmp_sock_list->src_port == src_port) {
                sock = tmp_sock_list->sock;
                //reset the count
                pthread_mutex_unlock(&localsock_mutex);
                LogI("clear fd %d the count", sock);
                pthread_mutex_lock(&remotesock_mutex);
                std::map<int, struct udp_sock_pair *>::iterator it = udp_remotsock_map.find(sock);
                if (udp_remotsock_map.end() != it) {
                    it->second->count = 0;
                }
                pthread_mutex_unlock(&remotesock_mutex);
                break;
            }
            tmp_sock_list = tmp_sock_list->next;
        }
        /*new src ip and src port request*/
        if (tmp_sock_list == NULL) {
            pthread_mutex_unlock(&localsock_mutex);
            struct udp_localsock_list *usp = (struct udp_localsock_list *) malloc(
                    sizeof(struct udp_localsock_list));
            if (usp == NULL) {
                LogE("find_socket: malloc  fail.");
                return -1;
            }

            usp->src_ip = *src_ip;
            usp->src_port = src_port;
            struct udp_sock_pair *psockpair = (struct udp_sock_pair *) malloc(
                    sizeof(struct udp_sock_pair));
            if (psockpair == NULL) {
                LogE("find_socket: malloc  fail.");
                free(usp);
                return -1;
            }
            //memset(psockpair,0,sizeof(struct udp_sock_pair));

            struct udp_packet_net_key_pair *tmpkp = (struct udp_packet_net_key_pair *) malloc(
                    sizeof(struct udp_packet_net_key_pair));
            if (tmpkp == NULL) {
                LogE("find_socket: malloc  fail.");
                free(usp);
                free(psockpair);
                return -1;
            }
#ifdef FEATURE_WIFI_OCO
            usp->sock = create_udp_socket(&(UDP_SOCKET_CUR_IP));
#else
            usp->sock = create_udp_socket(&gMPTCP_config.wifiIp);
#endif
            if (usp->sock < 0) {
                LogE("find_socket: create udpsocket  fail.");
                free(usp);
                free(tmpkp);
                free(psockpair);
                return -1;
            }
            tmpkp->src_ip = *src_ip;
            tmpkp->src_port = src_port;
            tmpkp->dest_ip = *dst_ip;
            tmpkp->dest_port = dst_port;
            tmpkp->next = NULL;
            psockpair->net_key_pair_list = tmpkp;
            psockpair->sockfd = usp->sock;
            psockpair->count = 0;
            //insert data to remote list
            pthread_mutex_lock(&remotesock_mutex);
            udp_remotsock_map[psockpair->sockfd] = psockpair;
            pthread_mutex_unlock(&remotesock_mutex);
            //insert data to local list
            pthread_mutex_lock(&localsock_mutex);
            usp->next = tmp_localsock->udp_list;
            tmp_localsock->udp_list = usp;
            sock = usp->sock;
            pthread_mutex_unlock(&localsock_mutex);
        }
    }

    LogD("find_socket udp socket =%d, g_wait_sem_flag =%d end sync",sock,g_wait_sem_flag);

    /* wakeup read thread*/
    if (g_wait_sem_flag == 1) {
        /*notify the semaphore object and quit thread*/
        sem_post(&gSemRecv);
    }
    return sock;
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
int send_udp_packet_to_network(void *msg, int msglen, ip4_addr_p_t *src_ip, u16_t src_port,
                               ip4_addr_p_t *dstip, u16_t dstport) {
    int ret = -1;
    struct sockaddr_in srvAddr;
    bzero(&srvAddr, sizeof(srvAddr));
    int sndfd = find_socket(src_ip, src_port, dstip, dstport);
    if (sndfd < 0) {
        LogE("send_udp_packet_to_network: find socket faild");
        return -1;
    }
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = dstport;
    srvAddr.sin_addr.s_addr = dstip->addr;
    ret = (int) sendto(sndfd, msg, msglen, 0, (struct sockaddr *) &srvAddr,
                       sizeof(struct sockaddr_in));

    LogD("udp send ret =%d, msg =%s sndfd =%d  addr:%s,port:%d", ret, (char*) msg, sndfd, inet_ntoa(srvAddr.sin_addr), htons(srvAddr.sin_port));
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
void *receive_udp_packet_thread(void *arg) {
    int ret = -1;
    char buffer[MAX_UDP_DATA];
    UINT32 lastTime = (UINT32) time(NULL);
    int expiredCheckFlag = 0;
    struct sockaddr_in senderAddr;
    socklen_t sndaddrsize = sizeof(struct sockaddr_in);
    int maxFd = 0;
    gVPN_thread_data.receive_udp_packet_thread_flag = 1;

    fd_set readset;
    struct timeval tv = {2, 0};
    char name[40]={ 0 };
    sprintf(name,"receive_udp_packet_thread");
    setThreadName(name);
    while (!g_sm_end) {
        /*if no have socket in map, thread will wait */
        pthread_mutex_lock(&remotesock_mutex);
        if (udp_remotsock_map.size() == 0) {
            pthread_mutex_unlock(&remotesock_mutex);
            LogI("No udp connect, wait sem flag ");
            g_wait_sem_flag = 1;
            sem_wait(&gSemRecv);
            g_wait_sem_flag = 0;
            LogI("sem wait complete, g_sm_end=%d map size =%d", g_sm_end,
                (int)udp_remotsock_map.size());
            if (g_sm_end) {
                return NULL;
            }
            if (udp_remotsock_map.size() == 0) {
                continue;
            }
        } else {
            FD_ZERO(&readset);
            maxFd = 0;
			for (std::map<int, udp_sock_pair *>::iterator it = udp_remotsock_map.begin();
             it != udp_remotsock_map.end();)
            /*for (std::map<int, udp_sock_pair *>::iterator it = udp_remotsock_map.begin();
                 it != udp_remotsock_map.end(); it++) */{
                if (it->first >= maxFd) {
                    maxFd = it->first + 1;
                }
                FD_SET(it->first, &readset);
				it++;
            }
            pthread_mutex_unlock(&remotesock_mutex);
        }
        tv.tv_sec = 2;
        LogI("receive_udp_packet_thread enter select");
        int rc = select(maxFd, &readset, NULL, NULL, &tv);
        if (rc == 0 || rc == -1) {
            if (rc == -1) {
                LogI("select receive_udp_packet_thread\n");
            }
            else {
                LogI("receive_udp_packet_thread Running\n");
                udp_connect_expire_check();
                lastTime = (UINT32) time(NULL);
            }
            continue;
        } else {
            UINT32 sec = (UINT32) time(NULL);
            if (sec - lastTime >= EXPIRE_CHECK_TIME) {
                lastTime = sec;
                expiredCheckFlag = 1;
            }
            pthread_mutex_lock(&remotesock_mutex);
            for (std::map<int, udp_sock_pair *>::iterator it = udp_remotsock_map.begin();
                 it != udp_remotsock_map.end();) {
                if (FD_ISSET (it->first, &readset)) {
                    /* received data from socket */
                    int reclen = (int) recvfrom(it->first, buffer, MAX_UDP_DATA, 0,
                                                (struct sockaddr *) &senderAddr, &sndaddrsize);
                    if (reclen != -1) {
                        it->second->count = 0;
                        //find client matched
                        LogI("receive_udp_packet_thread: find the vpn socket");
                        struct udp_packet_net_key_pair *tmp_sock_pair = it->second->net_key_pair_list;
                        while (tmp_sock_pair != NULL) {
                            if (tmp_sock_pair->dest_ip.addr == (u32_t) senderAddr.sin_addr.s_addr &&
                                tmp_sock_pair->dest_port == senderAddr.sin_port) {
                                break;
                            }
                            tmp_sock_pair = tmp_sock_pair->next;
                        }
                        if (tmp_sock_pair != NULL) {
                            vpn_tun_send_udp_packet_handle((u8_t *) buffer, reclen,
                                                           &tmp_sock_pair->dest_ip,
                                                           tmp_sock_pair->dest_port,
                                                           &tmp_sock_pair->src_ip,
                                                           tmp_sock_pair->src_port);
                        }
                    } else {
                        LogI("receive udp packet from thread failed\n");
                        it->second->count++;
                    }
                    it++;
                } else if (expiredCheckFlag) {
                    if (it->second->count++ > EXPIRE_CHECK_COUNT) {
                        free_udp_sock_pair(it->second);
                        udp_remotsock_map.erase(it++);
                    } else {
                        it++;
                    }
                } else {
                    it++;
                }
            }
            pthread_mutex_unlock(&remotesock_mutex);
        }
    }
	gVPN_thread_data.receive_udp_packet_thread_t = 0;
    gVPN_thread_data.receive_udp_packet_thread_flag = 0;
    return 0;
}
