
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/tcp.h"
#include "lwip/prot/tcp.h"
#include "lwip/tcpip.h"

#if LWIP_PERFORMANCE_TEST_ENABLE_VETH0

#define ETHERNET_MTU 1500

struct netif *p_netif_default;

#if WLAN_ENABLE
#define WLAN_IFACE_NAME "wlan0"
static int pkt_fd_wlan = -1;
struct netif netif_wlan;
#if ETHNET_ENABLE
struct netif *p_netif_wlan;
#endif
#endif

#if ETHNET_ENABLE
#define ETH_IFACE_NAME "veth0"
static int pkt_fd_eth = -1;
struct netif netif_eth;
#endif
extern unsigned  long tunnel_snd_worktime;
extern unsigned  long tunnel_snd_sleeptime;
extern unsigned  long tunnel_rcv_worktime;
extern unsigned  long tunnel_rcv_sleeptime;

int linux_netif_runing = 1;
struct PacketBuff {
    struct PacketBuff *next;
    int fd;
    int len;
    char buff[2000];
};
sem_t dataListSndSem;
pthread_mutex_t datalistMutex;
struct PacketBuff *datalistHead = NULL;
struct PacketBuff *datalistEnd = NULL;

void netif_send_data_thread(void *arg) {
    int ret = 0,len, wrote;
    u8_t was_readable = 1;
    struct PacketBuff *dataPack;
    char sndBuf[2000];
    while (linux_netif_runing) {
        was_readable = 0;
        dataPack = NULL;
        pthread_mutex_lock(&datalistMutex);
        if(datalistHead != NULL) {
            if (datalistHead != datalistEnd) {
                dataPack = datalistHead;
                datalistHead = datalistHead->next;
            } else {
                dataPack = datalistHead;
                datalistHead = datalistEnd = NULL;
            }
        }
        pthread_mutex_unlock(&datalistMutex);
        if(dataPack != NULL) {
            was_readable = 1;
            len = dataPack->len;
            wrote = 0;
#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
            struct timeval t_start,t_end;
            gettimeofday(&t_start, NULL);
#endif
            while (wrote < len) {
                ret = send(dataPack->fd, dataPack->buff + wrote, len - wrote, 0);
                //ret = send(pkt_fd_eth, sndBuf + wrote, len - wrote, 0);
                if(ret == -1 && errno == EAGAIN)
                    continue;
                else if(ret >= 0)
                    wrote += ret;
                else{
                    break;
                }
            }
#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
            gettimeofday(&t_end, NULL);
            tunnel_snd_worktime +=
                    1000000 * (t_end.tv_sec - t_start.tv_sec) + t_end.tv_usec - t_start.tv_usec;
#endif
            free(dataPack);
        }
        if (!was_readable) {
#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
            struct timeval t_start,t_end;
            gettimeofday(&t_start, NULL);
#endif
            do {
                struct timespec ts;
                if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
                    break;
                }
                ts.tv_sec += 1;
                while ((sem_timedwait(&dataListSndSem, &ts)) == -1 && errno == EINTR)
                    continue;       /* Restart if interrupted by handler */
            } while (0);
#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
            gettimeofday(&t_end, NULL);
            tunnel_snd_sleeptime +=
                    1000000 * (t_end.tv_sec - t_start.tv_sec) + t_end.tv_usec - t_start.tv_usec;
#endif
        }
    }
    return;
}

//struct RecvPacketBuff {
//    struct RecvPacketBuff *next;
//    struct pbuf *buf;
//};
//sem_t recvDataListSndSem;
//pthread_mutex_t recvDatalistMutex;
//struct RecvPacketBuff *recvDatalistHead = NULL;
//struct RecvPacketBuff *recvDatalistEnd = NULL;
//int  recvpacknumber = 0;
//void recv_packet_input_thread(){
//
//    u8_t was_readable = 1;
//    int recvprint = 0;
//    struct RecvPacketBuff *dataPack;
//    struct netif *pnetif = &netif_eth;
//    while (linux_netif_runing) {
//        was_readable = 0;
//        if(recvDatalistHead != NULL) {
//            was_readable = 1;
//            pthread_mutex_lock(&recvDatalistMutex);
//            if (recvDatalistHead != recvDatalistEnd) {
//                dataPack = recvDatalistHead;
//                recvDatalistHead = recvDatalistHead->next;
//            } else {
//                dataPack = recvDatalistHead;
//                recvDatalistHead = recvDatalistEnd = NULL;
//            }
//            if(recvpacknumber>50 && recvprint) {
//                LWIP_DEBUGF(MPTCP_PROXY_DEBUG,
//                            ("[lwip statistics] tunnel recv packnum=%lu , \n", recvpacknumber));
//                recvprint = 0;
//            }
//
//            recvpacknumber--;
//            pthread_mutex_unlock(&recvDatalistMutex);
//#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
//            struct timeval t_start,t_end;
//            gettimeofday(&t_start, NULL);
//#endif
//            pnetif->input(dataPack->buf, pnetif);
//#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
//            gettimeofday(&t_end, NULL);
//            tunnel_rcv_worktime +=
//                    1000000 * (t_end.tv_sec - t_start.tv_sec) + t_end.tv_usec - t_start.tv_usec;
//#endif
//            free(dataPack);
//        }
//        if (!was_readable) {
//#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
//            struct timeval t_start,t_end;
//            gettimeofday(&t_start, NULL);
//            recvprint = 1;
//#endif
//            do {
//                struct timespec ts;
//                if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
//                    break;
//                }
//                ts.tv_sec += 1;
//                while ((sem_timedwait(&recvDataListSndSem, &ts)) == -1 && errno == EINTR)
//                    continue;       /* Restart if interrupted by handler */
//            } while (0);
//#if LWIP_PERFORMANCE_IMPROVE_CHECKLOG
//            gettimeofday(&t_end, NULL);
//            tunnel_rcv_sleeptime +=
//                    1000000 * (t_end.tv_sec - t_start.tv_sec) + t_end.tv_usec - t_start.tv_usec;
//#endif
//        }
//    }
//    return ;
//}

static err_t prepare_packet_socket(char *if_name, int *sock){
    int sk;
    int sock_buf_size = 4194304; /* 4M */
	struct ifreq ifr;
	struct sockaddr_ll ll;

    sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sk < 0){
        LWIP_PLATFORM_DIAG(("%s: socket() failed, errno=%d\n", __FUNCTION__, errno));
        return ERR_GENERIC;
    }

    memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if(ioctl(sk, SIOCGIFINDEX, &ifr) < 0){
        LWIP_PLATFORM_DIAG(("%s: ioctl(SIOCGIFINDEX) failed, errno=%d\n", __FUNCTION__, errno));
        close(sk);
        return ERR_GENERIC;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(ETH_P_ALL);
	if(bind(sk, (struct sockaddr *)&ll, sizeof(ll)) < 0){
        LWIP_PLATFORM_DIAG(("%s: bind() failed, errno=%d\n", __FUNCTION__, errno));
        close(sk);
        return ERR_GENERIC;
	}

    if(setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &sock_buf_size,
                  sizeof(sock_buf_size)) == -1){
        LWIP_PLATFORM_DIAG(("%s:%d: setsockopt() failed, errno=%d", __FUNCTION__, __LINE__, errno));
    }

    *sock = sk;
    return ERR_OK;
}

static err_t packet_if_output(int fd, struct pbuf *p){
    size_t lenToSend, lenSent;
    ssize_t ret;
//    char *pBuf;
//    struct pbuf *tmp = p;
//
//    pBuf = (char *)malloc(p->tot_len);
//    if(pBuf == NULL)
//        return ERR_MEM;
//    lenToSend = (size_t)pbuf_copy_partial(p, pBuf, p->tot_len, 0);
//    if(lenToSend <= 0){
//        free(pBuf);
//        return ERR_OK;
//    }
//    lenSent = 0;
//    while(lenSent < lenToSend){
//        ret = send(fd, pBuf + lenSent, lenToSend - lenSent, 0);
//        if(ret == -1 && errno == EAGAIN)
//            continue;
//        else if(ret >= 0)
//            lenSent += ret;
//        else{
//            free(pBuf);
//            return ERR_GENERIC;
//        }
//    }
//    free(pBuf);
    struct PacketBuff *dataPack = malloc(sizeof(struct PacketBuff));
    if (dataPack == NULL)
        return ERR_MEM;
    lenToSend = (size_t)pbuf_copy_partial(p, dataPack->buff, p->tot_len, 0);
    dataPack->fd = fd;
    dataPack->len = lenToSend;
    dataPack->next = NULL;
    pthread_mutex_lock(&datalistMutex);
    if(datalistEnd != NULL) {
        datalistEnd->next = dataPack;
        datalistEnd = dataPack;
    } else {
        datalistHead = datalistEnd = dataPack;
        sem_post(&dataListSndSem);
    }
    pthread_mutex_unlock(&datalistMutex);
    return ERR_OK;
}


#if WLAN_ENABLE
static err_t netif_output_wlan(struct netif *netif, struct pbuf *p){
    return packet_if_output(pkt_fd_wlan, p);
}
#endif

#if ETHNET_ENABLE
static err_t netif_output_eth(struct netif *netif, struct pbuf *p){
    return packet_if_output(pkt_fd_eth, p);
}
#endif

#if WLAN_ENABLE
static err_t netif_init_wlan(struct netif *netif){
    err_t ret;
    unsigned char mac_addr[NETIF_MAX_HWADDR_LEN];

    if((ret = prepare_packet_socket(WLAN_IFACE_NAME, &pkt_fd_wlan)) != ERR_OK)
        return ret;

    netif->linkoutput = netif_output_wlan;
    netif->output = etharp_output;
    netif->mtu = ETHERNET_MTU;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;

#if 1
    mac_addr[0] = 0xbc;
    mac_addr[1] = 0x6e;
    mac_addr[2] = 0x64;
    mac_addr[3] = 0xea;
    mac_addr[4] = 0xaa;
    mac_addr[5] = 0x12;
#else
    mac_addr[0] = 0x44;
    mac_addr[1] = 0x80;
    mac_addr[2] = 0xeb;
    mac_addr[3] = 0xee;
    mac_addr[4] = 0xfb;
    mac_addr[5] = 0x86;
#endif
    SMEMCPY(netif->hwaddr, mac_addr, sizeof(netif->hwaddr));
    netif->hwaddr_len = sizeof(netif->hwaddr);

    return ERR_OK;
}
#endif

#if ETHNET_ENABLE
static err_t netif_init_eth(struct netif *netif){
    err_t ret;
    unsigned char mac_addr[NETIF_MAX_HWADDR_LEN];

    if((ret = prepare_packet_socket(ETH_IFACE_NAME, &pkt_fd_eth)) != ERR_OK)
        return ret;

    netif->linkoutput = netif_output_eth;
    netif->output = etharp_output;
    netif->mtu = ETHERNET_MTU;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;

#if 0
    mac_addr[0] = 0x00;
    mac_addr[1] = 0xe0;
    mac_addr[2] = 0x4c;
    mac_addr[3] = 0x36;
    mac_addr[4] = 0xe1;
    mac_addr[5] = 0xda;
#else
    mac_addr[0] = 0xee;
    mac_addr[1] = 0x51;
    mac_addr[2] = 0x29;
    mac_addr[3] = 0xec;
    mac_addr[4] = 0xc4;
    mac_addr[5] = 0xc6;
#endif
    SMEMCPY(netif->hwaddr, mac_addr, sizeof(netif->hwaddr));
    netif->hwaddr_len = sizeof(netif->hwaddr);

    return ERR_OK;
}
#endif

void if_read_thread(void *arg){
    int type = (int)arg;
    int pkt_fd;
    ssize_t ret;
    struct netif *pnetif;
    char *pBuf;

#if ETHNET_ENABLE && WLAN_ENABLE
    pkt_fd = (type == 0) ? pkt_fd_eth : pkt_fd_wlan;
    pnetif = (type == 0) ? &netif_eth : &netif_wlan;
#elif ETHNET_ENABLE
    if(type != 0)
        return;
    pkt_fd = pkt_fd_eth;
    pnetif = &netif_eth;
#elif WLAN_ENABLE
    if(type != 1)
        return;
    pkt_fd = pkt_fd_wlan;
    pnetif = &netif_wlan;
#endif

    pBuf = (char *)malloc(ETHERNET_MTU + 100);
    if(pBuf == NULL){
        LWIP_PLATFORM_DIAG(("%s: malloc() failed\n", __FUNCTION__));
        return;
    }
    while(1){
        if(pkt_fd < 0){
            usleep(100 * 1000);
            continue;
        }
        ret = read(pkt_fd, pBuf, ETHERNET_MTU + 100);
        if(ret < 0 && errno != EAGAIN){
            LWIP_PLATFORM_DIAG(("%s: read() failed, errno=%d\n", __FUNCTION__, errno));
            break;
        }
        if(ret > 0){
            struct pbuf *buf = pbuf_alloc(pnetif->instance,PBUF_RAW, (u16_t)ret, PBUF_RAM);
            if(buf == NULL){
                LWIP_PLATFORM_DIAG(("%s: pbuf_alloc() failed\n", __FUNCTION__));
                continue;
            }
            memcpy(buf->payload, pBuf, (u16_t)ret);
            pnetif->input(buf, pnetif);
//            struct RecvPacketBuff *dataPack = malloc(sizeof(struct RecvPacketBuff));
//            if (dataPack == NULL)
//                continue;
//            dataPack->buf = buf;
//            dataPack->next = NULL;
//            pthread_mutex_lock(&recvDatalistMutex);
//            recvpacknumber++;
//            if(recvDatalistEnd != NULL) {
//                recvDatalistEnd->next = dataPack;
//                recvDatalistEnd = dataPack;
//            } else {
//                recvDatalistHead = recvDatalistEnd = dataPack;
//                sem_post(&recvDataListSndSem);
//            }
//            pthread_mutex_unlock(&recvDatalistMutex);
        }
    }
    free(pBuf);
}

void netif_linux_setup(){
    ip4_addr_t addr, mask, gw;

#if ETHNET_ENABLE
    netif_eth.name[0] = 'E';
    netif_eth.name[1] = 'T';
    ip4addr_aton("192.168.42.2", &addr);
    ip4addr_aton("255.255.255.0", &mask);
    ip4addr_aton("192.168.42.1", &gw);
    netif_add(&netif_eth, &addr, &mask, &gw, NULL, netif_init_eth, tcpip_input);
    netif_set_default(&netif_eth);
    p_netif_default = &netif_eth;
    netif_set_up(&netif_eth);
    netif_set_link_up(&netif_eth);
    pthread_mutex_init(&datalistMutex, NULL);
    sem_init(&dataListSndSem, 0, 0);
    //pthread_mutex_init(&recvDatalistMutex, NULL);
    //sem_init(&recvDataListSndSem, 0, 0);
    sys_thread_new("eth_if_read", if_read_thread, (void *)0, 0, 0);
    //sys_thread_new("eth_if_recv_read", recv_packet_input_thread, (void *)0, 0, 0);
    sys_thread_new("eth_if_write", netif_send_data_thread, (void *)0, 0, 0);
#endif

#if WLAN_ENABLE
    netif_wlan.name[0] = 'W';
    netif_wlan.name[1] = 'L';
    ip4addr_aton("192.168.1.123", &addr);
    ip4addr_aton("255.255.255.0", &mask);
    ip4addr_aton("192.168.1.1", &gw);
    netif_add(&netif_wlan, &addr, &mask, &gw, NULL, netif_init_wlan, tcpip_input);
#if !(ETHNET_ENABLE)
    netif_set_default(&netif_wlan);
    p_netif_default = &netif_wlan;
#else
    p_netif_wlan = &netif_wlan;
#endif
    netif_set_up(&netif_wlan);
    netif_set_link_up(&netif_wlan);
    sys_thread_new("wlan_if_read", if_read_thread, (void *)1, 0, 0);
#endif
}

void netif_linux_deinit(){
    linux_netif_runing = 0;
    //sem_post(&recvDataListSndSem);
    sem_post(&dataListSndSem);
    usleep(10000);
    sem_destroy(&dataListSndSem);
    pthread_mutex_destroy(&datalistMutex);
    //sem_destroy(&recvDataListSndSem);
    //pthread_mutex_destroy(&recvDatalistMutex);
}
#endif