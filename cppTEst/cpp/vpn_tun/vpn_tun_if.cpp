/******************************************************************************
NAME  =	 vpn_tun_if.c
FUNC  =
NOTE  =
DATE  =	 2017-04-10 ;
AUTH  =
HIST  =	 2017-04-10, (mpd), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/

#include <semaphore.h>
#include <fcntl.h>
#include "../mptcp/proxy/nolock.h"
#include "traffic_loadblance.h"
#include "../tunnel/tunnel.h"

extern "C" {
#include <arpa/inet.h>
#include <lwip/ip4_nat.h>
#include <lwip/tcpip.h>
#include <lwip/mptcp/mptcp_proxy.h>
#include "../udp/udp_handle.h"
#include "../tunnel/tunnel.h"
#include "lwip/mptcp/mptcp_proxy.h"
#ifdef LWIP_SHELL_CONSOLE
#include "../tools/shell.h"
#endif
#if LINUX_PLATFORM
#include<sys/time.h>
#endif

#if LWIP_PERFORMANCE_TEST_ENABLE_VETH0
void netif_linux_setup();
void netif_linux_deinit();
#endif
}

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_VPN_TUN

//#define __android_log_print(...) do{}while(0)

extern int create_lte_socket_ext(void *instance,JNIEnv *env, int ipaddr, int port);

extern int mutp_start_create_socket();
static void mptcp_proxy_exit_all(lwip_instance *instances,int n);
void vpn_tun_read_data(void *instance,pbuf *p, int len);

/* global variate define */
mptcp_data_init_V01 gMPTCP_config = {0};
/* global variate for save all thread status */
vpn_thread_data gVPN_thread_data;

int s_tunif_end = 0;
/*lwip device associate with vpn tun*/
struct netif netif_vpntun;
int tunUp = 0;
static int tun_write_flag = 1;
struct queue *vpn_data_list = NULL;
sem_t tunWrtSem;
pthread_mutex_t tunPacketListMutex;
#if !LWIP_TCP_ZEROCOPY
struct dataPacket *tunDataListHead = NULL;
struct dataPacket *tunDataListEnd = NULL;
typedef struct _nocopydata {
    struct pbuf* p;
    struct _nocopydata* next;
}DP;
struct _nocopydata* pbuf_tun_head = NULL;
struct _nocopydata* pbuf_tun_end = NULL;
#else
struct pbuf *tunDataListHead = NULL;
struct pbuf *tunDataListEnd = NULL;
#endif
struct lwip_instance g_stlwipInstance;
struct lwip_instance g_stlwipInstanceOther[MAX_INSTANCE_NUM -1];

struct lwip_instance g_stPartlwipInstance;
struct lwip_instance g_stPartlwipInstanceOther[MAX_INSTANCE_NUM -1];
struct packet_queue *vpn_write_que = NULL;
/*struct dataPacket *dataPackReuse = NULL;*/

#if LWIP_PCAP_SUPPORT
int vpn_pcap_fd = -1;
pthread_mutex_t pcap_write_mutex = PTHREAD_MUTEX_INITIALIZER;
int pcap_open_set = 0;

int pcap_set_direction = LWIP_PCAP_VPN_UP_STRAM | LWIP_PCAP_VPN_DOWN_STRAM | LWIP_PCAP_TUNNEL_UP_STRAM | LWIP_PCAP_TUNNEL_UP_STRAM;

char *pcr_buf = NULL;
int pcr_snd_len = 0;
int pcr_rcv_len = 0;

#define bpf_u_int32 u32_t
#define bpf_int32 s32_t

struct pcap_file_header {
        bpf_u_int32 magic;
        u_short version_major;
        u_short version_minor;
        bpf_int32 thiszone;     /* gmt to local correction */
        bpf_u_int32 sigfigs;    /* accuracy of timestamps */
        bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
        bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_timeval {
    bpf_int32 tv_sec; /* seconds */
    bpf_int32 tv_usec; /* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts; /* time stamp */
    bpf_u_int32 caplen; /* length of portion present */
    bpf_u_int32 len; /* length this packet (off wire) */
};

int tun_pcap_init(char *filename)
{
   int fd;
   char pcaph[24];
   
   fd = open(filename, O_CREAT | O_WRONLY, 0644);

   if(fd>0){
   	memset(&pcaph, 0x0,24);
	pcaph[0] = 0xd4;
	pcaph[1] = 0xc3;
	pcaph[2] = 0xb2;
	pcaph[3] = 0xa1;
	pcaph[4] = 0x02;
	pcaph[6] = 0x04;
   	pcaph[16] = 0xFF;
	pcaph[17] = 0xFF;
	pcaph[20] = 0x71;
   	write(fd, (void *)&pcaph, 24);
	pcap_open_set = 1;
   }
   else
   {
      LogD("lwip create pcap file strerror: %s", strerror(errno));
   }
   
   return fd;
}

inline int tun_write_pcap(int fd, char *buf, int len, int pcap_type_direction)
{
   struct timeval tv;
   struct pcap_timeval ptv;
   int Caplen ;
   time_t t; 
   char eth_ii_hdr[16];
   struct ip_hdr *iphc;

   if(unlikely(pcap_open_set)){
       iphc = (struct ip_hdr *)buf;
       len = PCAP_LEN(len);
	   t = time(NULL);
	   gettimeofday(&tv, NULL);
	   ptv.tv_sec = (bpf_int32)t;
	   ptv.tv_usec = (bpf_int32)tv.tv_usec;
	   memset(&eth_ii_hdr, 0x0,16);
	   eth_ii_hdr[1] = 0x04;
	   eth_ii_hdr[2] = 0xff;
	   eth_ii_hdr[3] = 0xfe;
	   eth_ii_hdr[14] = 0x08; 
	
	   pthread_mutex_lock(&pcap_write_mutex);

	   if( (pcr_buf != NULL) && (pcr_snd_len > 0) && (pcr_rcv_len > 0))
	   {
	    LogE("lwip tun_write_pcr_packet write send=%d recv=%d", pcr_snd_len,pcr_rcv_len);
	    write(fd, (void *)&ptv, sizeof(struct pcap_timeval));
		Caplen = pcr_snd_len+16;
	    write(fd, (void *)&Caplen, sizeof(bpf_u_int32));
	    write(fd, (void *)&Caplen, sizeof(bpf_u_int32));  
	    write(fd, (void *)&eth_ii_hdr, 16);
	    write(fd, (void *)pcr_buf, pcr_snd_len);
		ptv.tv_usec += 100;

	    write(fd, (void *)&ptv, sizeof(struct pcap_timeval));
		Caplen = pcr_rcv_len+16;
	    write(fd, (void *)&Caplen, sizeof(bpf_u_int32));
	    write(fd, (void *)&Caplen, sizeof(bpf_u_int32));  
	    write(fd, (void *)&eth_ii_hdr, 16);
	    write(fd, (void *)(pcr_buf+pcr_snd_len), pcr_rcv_len);
		
		ptv.tv_usec += 100;
		free(pcr_buf);
		pcr_buf = NULL;
		pcr_snd_len = 0;
		pcr_rcv_len = 0;
	   }
	   

	   Caplen = len + 16;
	   write(fd, (void *)&ptv, sizeof(struct pcap_timeval));
	   write(fd, (void *)&Caplen, sizeof(bpf_u_int32));
	   write(fd, (void *)&Caplen, sizeof(bpf_u_int32));  
	   write(fd, (void *)&eth_ii_hdr, 16);
	   write(fd, (void *)buf, len);
	  
	   pthread_mutex_unlock(&pcap_write_mutex);
   }
   return len;
}

int tun_pcap_close(int fd)
{
    close(fd);
	pcap_open_set = 0;
	vpn_pcap_fd = -1;
	return 0;
}

void tun_write_pcr_packet(void *sndBuf, int sndLen, void *rcvBuf, int rcvLen, int src_ip,u16_t src_port,int dest_ip, u16_t dest_port)
{
     int ip_and_udp_hdr_size = sizeof(struct ip_hdr) + sizeof(struct udphdr);
	 struct ip_hdr *iph;
	 struct udphdr *udph;

	 LogE("lwip tun_write_pcr_packet enter send=%d recv=%d", sndLen,rcvLen);

     pcr_buf = (char *)malloc(sndLen+rcvLen+2*ip_and_udp_hdr_size);
	 if(pcr_buf != NULL)
	 {
	    /*
	    0004000100063cfa4304df5a08000800
	 	ip hdr(16B): 45000025451d40004011712dc0a801f6c0a80137
	 	udp hdr(8B): 533c1f90001116d2
	 	data(9B)   : 436875726368696c6c
	 	*/
         memset(pcr_buf, 0, sndLen+rcvLen+2*ip_and_udp_hdr_size);
	     LogE("lwip tun_write_pcr_packet send=%d recv=%d", sndLen,rcvLen);
	 	 iph = (struct ip_hdr *)pcr_buf;
		 udph = (struct udphdr *)(iph+1);
		 pcr_buf[0] = 0x45;
		 pcr_buf[1] = 0x00;
		 pcr_buf[2] = 0x00;
		 pcr_buf[3] = 0x25;
		 pcr_buf[4] = 0x45;
		 pcr_buf[5] = 0x1d;
		 pcr_buf[6] = 0x40;
		 pcr_buf[7] = 0x00;
		 pcr_buf[8] = 0x40;
		 pcr_buf[9] = 0x11;
		 pcr_buf[10] = 0x71;
		 pcr_buf[11] = 0x2d;
		 iph->src.addr = htonl(src_ip);/*144.11.6.27*/
		 iph->dest.addr = htonl(dest_ip);/*172.24.13.31*/
		 iph->_chksum = 0;
		 iph->_len = htons((u16_t)(sizeof(struct ip_hdr)+sizeof(struct udphdr)+ sndLen));
         iph->_chksum = cal_chksum((unsigned short *) pcr_buf, sizeof(struct ip_hdr));
		 udph->src = htons(src_port);
		 udph->dest = htons(dest_port);

		 udph->len = htons((u16_t)(sizeof(struct udphdr)+ sndLen));
		 udph->chksum = 0;
		 //udph->chksum = cal_chksum((unsigned short *) (pcr_buf+ sizeof(struct ip_hdr)), udph->len);
		 
	     memcpy(pcr_buf+ip_and_udp_hdr_size, sndBuf, sndLen);
		 memcpy(pcr_buf+sndLen+ip_and_udp_hdr_size, rcvBuf, rcvLen);
		 iph = (struct ip_hdr *)(pcr_buf+sndLen+ip_and_udp_hdr_size);
		 udph = (struct udphdr *)(iph+1);
	 	 pcr_buf[sndLen+ip_and_udp_hdr_size] = 0x45;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+1] = 0x00;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+2] = 0x00;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+3] = 0x25;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+4] = 0x45;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+5] = 0x1d;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+6] = 0x40;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+7] = 0x00;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+8] = 0x40;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+9] = 0x11;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+10] = 0x71;
		 pcr_buf[sndLen+ip_and_udp_hdr_size+11] = 0x2d;
		 iph->src.addr = htonl(dest_ip);/*172.24.13.31*/
		 iph->dest.addr = htonl(src_ip);/*144.11.6.27*/
		 iph->_chksum = 0;
		 iph->_len = htons((u16_t)(sizeof(struct ip_hdr)+sizeof(struct udphdr)+ rcvLen));
         iph->_chksum = cal_chksum((unsigned short *) (pcr_buf+sndLen+ip_and_udp_hdr_size), sizeof(struct ip_hdr));
		 udph->src = htons(dest_port);

		 udph->dest = htons(src_port);
		 udph->len = htons((u16_t)(sizeof(struct udphdr)+rcvLen));
		 udph->chksum = 0;
		 //udph->chksum = cal_chksum((unsigned short *) (pcr_buf+ sndLen +ip_and_udp_hdr_size + sizeof(struct ip_hdr)), udph->len);
		 

		 pcr_snd_len = sndLen+ip_and_udp_hdr_size;
		 pcr_rcv_len = rcvLen+ip_and_udp_hdr_size;
	 }
}
#endif


#if !LWIP_TCP_ZEROCOPY
static void * vpn_write_data_thread(void *arg) {
    u8_t was_readable = 1;
    struct dataPacket *dataPack,*tmpPack;
    int ret = -1;
    int sndLen = 0;
    int i,totallen = 0;
    int vpnTunFd = gMPTCP_config.tunnel_FD;
    void *instance = arg;
#if LWIP_VPNQUE_PACKET
	struct dataPacket *dataPackList[5];
#endif

    global_set_thread_instance(instance);
    char name[40]={ 0 };
    sprintf(name,"vpn_write:%d ",get_instance_logic_id(instance));
    setThreadName(name);


    while (!s_tunif_end) {
        was_readable = 0;
		dataPack = NULL;
		#if LWIP_VPNQUE_PACKET
		totallen = packet_queue_try_deque_list(vpn_write_que,5,(void **)dataPackList);
		if(totallen > 0){
			tmpPack = dataPackList[0];
			dataPack = tmpPack;
			tmpPack->next = NULL;
			for(i=1;i<totallen;i++){
				tmpPack->next = dataPackList[i];
				tmpPack = tmpPack->next;
			}
		}
		#else
        pthread_mutex_lock(&tunPacketListMutex);
        if(tunDataListHead != NULL) {
            dataPack = tunDataListHead;
            tunDataListHead = tunDataListEnd = NULL;
        }
        pthread_mutex_unlock(&tunPacketListMutex);
		#endif
        if(dataPack == NULL){
            usleep(1000);
        }
        while(dataPack != NULL) {

            was_readable = 1;
            tmpPack = dataPack->next;
            totallen = dataPack->len;
            sndLen = 0;
            while (sndLen < totallen) {
                ret = write(vpnTunFd, dataPack->buff + sndLen, totallen - sndLen);
                if(ret == -1  ){
#if TUNNEL_STAT
                    vpnStat.vpnWriteFails++;
#endif
                    if(errno == EAGAIN || errno == ENOBUFS || errno == EINTR){
                        LogE("lwip 1 strerror: %s", strerror(errno));
                        usleep(1000);
                        continue;
                    }else{
                        LogE("lwip 2 strerror: %s", strerror(errno));
                        break;
                    }
                }
                else if(ret >= 0){
                    sndLen += ret;
                }
                else{
                    break;
                }
            }

			#if LWIP_PCAP_SUPPORT
			if(sndLen > 0)
				tun_write_pcap(vpn_pcap_fd,dataPack->buff,(sndLen), LWIP_PCAP_VPN_UP_STRAM);
			#endif
			/*if(dataPackReuse == NULL){
				dataPackReuse = dataPack;
				dataPack->next = NULL;
			}
			else*/
                free(dataPack);
            dataPack = tmpPack;
        }

        if (!was_readable) {
            do {
                struct timespec ts;
                if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
                    break;
                }
                ts.tv_sec += 1;
                while ((sem_timedwait(&tunWrtSem, &ts)) == -1 && errno == EINTR)
                    continue;       /* Restart if interrupted by handler */
            } while (0);
        }
    }
    return 0;
}

void write_pbuf(int fd,struct pbuf* p){
    int tot_len;
    tot_len = p->tot_len;
    int tot_snd = 0;
    int sndLen,ret;
    int len  = 0;
#if WRITE_VPN_P20
	int count  = 0;
#endif
#if 0
    while(p != NULL){
        sndLen = 0;
        while(sndLen< p->len && tot_len){
            if(tot_len < p->len)
                len = tot_len;
            else
                len = p->len;
            ret = write(fd,p->payload,len);
            if(ret == -1  ){
                if(errno == EAGAIN || errno == ENOBUFS || errno == EINTR){
                    LogE("lwip 1 strerror: %s", strerror(errno));
                    usleep(1000);
                    continue;
                }else{
                    LogE("lwip 2 strerror: %s", strerror(errno));
                    break;
                }
            }
            else if(ret >= 0){
                sndLen += ret;
                tot_len -= ret;
            }
            else{
                break;
            }
        }
        p = p->next;
    }
#endif
    ret = -1;
#if LWIP_PCAP_SUPPORT
    tun_write_pcap(vpn_pcap_fd,(char*)p->payload,((int)p->tot_len), LWIP_PCAP_VPN_DOWN_STRAM);
#endif

#if WRITE_VPN_P20
	count  = 0;
#endif

    while(ret < 0){
        ret = write(fd,p->payload,p->tot_len);
        if(ret == -1  ){
            if(errno == EAGAIN || errno == ENOBUFS || errno == EINTR){
                LogD("lwip 1 strerror: %s", strerror(errno));
				
				#if WRITE_VPN_P20
                usleep(5000);
				count ++;
				if(count > 50)
				{
					break;
				}else
				{
					continue;
				}
				#else
                
					#if WRITE_VPN_BLOCK
					break;
					#else
					usleep(1000);
	                continue;
					#endif
				
				#endif
				
            }else{
                LogD("lwip 2 strerror: %s", strerror(errno));
                break;
            }
        }
    }
}

static void * vpn_write_pubf_thread(void *arg) {
    u8_t was_readable = 1;
    DP *dataPack,*tmpPack;
    int vpnTunFd = gMPTCP_config.tunnel_FD;
    void *instance = arg;
#if LWIP_VPNQUE_PACKET
    struct dataPacket *dataPackList[5];
#endif

    global_set_thread_instance(instance);
    char name[40]={ 0 };
    sprintf(name,"vpn_write:%d ",get_instance_logic_id(instance));
    setThreadName(name);


    while (likely(tun_write_flag)) {
        was_readable = 0;
        dataPack = NULL;
        pthread_mutex_lock(&tunPacketListMutex);
        if(pbuf_tun_head != NULL) {
            dataPack = pbuf_tun_head;
            pbuf_tun_head = pbuf_tun_end = NULL;
        }
        pthread_mutex_unlock(&tunPacketListMutex);
        if(dataPack == NULL){
            usleep(1000);
        }
        while(dataPack != NULL) {

            was_readable = 1;
            tmpPack = dataPack->next;

            write_pbuf(vpnTunFd,dataPack->p);

            pbuf_free(dataPack->p);
            free(dataPack);  // free the struct to temp store the pbuf
            dataPack = tmpPack;
        }

        if (!was_readable) {
            do {
                struct timespec ts;
                if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
                    break;
                }
                ts.tv_sec += 1;
                while ((sem_timedwait(&tunWrtSem, &ts)) == -1 && errno == EINTR)
                    continue;       /* Restart if interrupted by handler */
            } while (0);
        }
    }
    /*when just 1 thread left, stack must exit when exculate flow code*/
    if(pbuf_tun_head){
        dataPack = pbuf_tun_head;
        while(dataPack != NULL){
            tmpPack = dataPack->next;
            pbuf_free(dataPack->p);
            free(dataPack);
            dataPack = tmpPack;
        }
    }
    pbuf_tun_head = pbuf_tun_head = NULL;
    return 0;
}
/******************************************************************************
NAME  =	 vpn_tun_device_write() ;
FUNC  =	 write data to vpn tun device;
INPUT =
RETU  =
DATE  =	 2017-04-10 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, cuiql , Original ;
*******************************************************************************/
int vpn_tun_device_write(u8_t *wrBuff, int wrLen) 
{
    int ret = -1;
    int sndLen = 0;
    int vpnTunFd = -1;
    fd_set writefds;
    struct timeval tv;
	
#if !LWIP_PERFORMANCE_ASYNC_TUN_RXTX
    struct dataPacket *dataPack;

    /*if(dataPackReuse != NULL){
		dataPack = dataPackReuse;
	    dataPackReuse = NULL;
    }
	else*/
		dataPack = (struct dataPacket *)malloc(sizeof(struct dataPacket));
    if (dataPack == NULL)
        return ERR_MEM;
	/*global variate config check*/
    vpnTunFd = gMPTCP_config.tunnel_FD;


    pbuf_memcpy(dataPack->buff, wrBuff, wrLen);
	
    dataPack->len = wrLen;
    
    dataPack->next = NULL;
#if LWIP_VPNQUE_PACKET
    packet_queue_try_enque(vpn_write_que,(void *)dataPack);
#else
    pthread_mutex_lock(&tunPacketListMutex);
    if(tunDataListEnd != NULL) {
        tunDataListEnd->next = dataPack;
        tunDataListEnd = dataPack;
    } else {
        tunDataListHead = tunDataListEnd = dataPack;
        sem_post(&tunWrtSem);
    }
    pthread_mutex_unlock(&tunPacketListMutex);
#endif
    END:
    return wrLen;
#endif
}

int vpn_tun_write_pubf(struct pbuf* p)
{
    int ret = -1;
    int sndLen = 0;
    int vpnTunFd = -1;
    fd_set writefds;
    struct timeval tv;

    if(!tun_write_flag){
        pbuf_free(p);
        return -1;
    }

    DP * dataPacket = (DP*)malloc(sizeof(DP));
    if(dataPacket == NULL){
        pbuf_free(p);
        return -1;
    }
    dataPacket->p = p;
    dataPacket->next = NULL;
    //LogE("%s:%d pbuf:%p total len:%d len:%d",__func__,__LINE__,p,p->tot_len,p->len);
    pthread_mutex_lock(&tunPacketListMutex);
    if(pbuf_tun_head != NULL) {
        pbuf_tun_end->next = dataPacket;
        pbuf_tun_end = dataPacket;
    } else {
        pbuf_tun_head = pbuf_tun_end = dataPacket;
        sem_post(&tunWrtSem);
    }
    pthread_mutex_unlock(&tunPacketListMutex);

    END:
    LogD("quit vpn_tun_device_write()");
    return 0;
}
#else
int vpn_tun_device_write_pbuf(struct pbuf *p)
{
    pthread_mutex_lock(&tunPacketListMutex);
    if(tunDataListEnd != NULL) {
        tunDataListEnd->next_packet = p;
        tunDataListEnd = p;
    } else {
        tunDataListHead = tunDataListEnd = p;
        sem_post(&tunWrtSem);
    }
    p->next_packet = NULL;
    pthread_mutex_unlock(&tunPacketListMutex);
    return 0;
}

static int vpn_write_one_packet(int vpnTunFd,struct pbuf *dataPack, u8_t *was_readable)
{
	int ret = -1;
	int sndLen = 0;
	int totallen = dataPack->len;

	*was_readable = 0;
	while (sndLen < totallen) {
		ret = write(vpnTunFd, (u8_t *)dataPack->payload + sndLen, totallen - sndLen);
		if(ret == -1  ){
#if TUNNEL_STAT
			vpnStat.vpnWriteFails++;
#endif
			if(errno == EAGAIN || errno == ENOBUFS || errno == EINTR){
				LogE("lwip 1 strerror: %s", strerror(errno));
				usleep(1000);
				continue;
			}else{
				LogE("lwip 2 strerror: %s", strerror(errno));
				break;
			}
		}
		else if(ret >= 0){
			sndLen += ret;
			*was_readable = 1;
		}
		else{
			break;
		}
	}
    return sndLen;
}

static void * vpn_write_data_thread(void *arg)
{
		u8_t was_readable = 0;
		struct pbuf *dataPack,*tmpPack,*FirstDataPack, *p;
		int ret = -1;
		int sndLen = 0;
		int pcap_len,i,totallen = 0;
		int vpnTunFd = gMPTCP_config.tunnel_FD;
		void *instance = arg;
		struct ip_hdr *iph;
		struct tcp_hdr *tcph;
		char *pcap_buf = NULL;

		global_set_thread_instance(instance);
	
		while (!s_tunif_end) {
			was_readable = 0;
			dataPack = NULL;

			pthread_mutex_lock(&tunPacketListMutex);
			if(tunDataListHead != NULL) {
				dataPack = tunDataListHead;
				tunDataListHead = tunDataListEnd = NULL;
			}
			pthread_mutex_unlock(&tunPacketListMutex);
	
			if(dataPack == NULL){
				usleep(1000);
			}

			while(dataPack != NULL) {
	
				was_readable = 0;

				if(dataPack->len < dataPack->tot_len)
				{
					u16_t left;
					u16_t buf_copy_len;
					u16_t copied_total = 0;
					u16_t len = dataPack->tot_len;
					u16_t offset=0;
					
					for (p = dataPack; len != 0 && p != NULL; p = p->next) {
						if ((offset != 0) && (offset >= p->len)) {
						  /* don't copy from this buffer -> on to the next */
						  offset -= p->len;
						} else {
						  /* copy from this buffer. maybe only partially. */
						  buf_copy_len = p->len - offset;
						  if (buf_copy_len > len) {
						    buf_copy_len = len;
						  }
						  /* copy the necessary parts of the buffer */
						  pcap_len = vpn_write_one_packet(vpnTunFd, p, &was_readable);
						  copied_total += buf_copy_len;
						  left += buf_copy_len;
						  len -= buf_copy_len;
						  offset = 0;
						}
					}
	#if LWIP_PCAP_SUPPORT
					pcap_buf = (char *)malloc(copied_total);
					if(pcap_buf != NULL){
					if(pbuf_copy_partial(dataPack,pcap_buf,(u16_t)copied_total,0) >= copied_total)
						tun_write_pcap(vpn_pcap_fd,pcap_buf,copied_total, LWIP_PCAP_VPN_UP_STRAM);
					}
	#endif
				}
				else{
					pcap_len= vpn_write_one_packet(vpnTunFd, dataPack, &was_readable);
					#if LWIP_PCAP_SUPPORT
					tun_write_pcap(vpn_pcap_fd,(char *)dataPack->payload,pcap_len, LWIP_PCAP_VPN_UP_STRAM);
					#endif
				}
				
                p = dataPack;
				if(dataPack->len < dataPack->tot_len){
					if(dataPack->next_packet == NULL)
						dataPack = NULL;
					else
					    dataPack = dataPack->next_packet;
				}
				else
					dataPack = NULL;
				
				if(!(p->flags & PBUF_FLAG_UNACKED)){
                    pbuf_free(p);
					p = NULL;
				}

				if (!was_readable) {
					do {
						struct timespec ts;
						if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
							break;
						}
						ts.tv_sec += 1;
						while ((sem_timedwait(&tunWrtSem, &ts)) == -1 && errno == EINTR)
							continue;		/* Restart if interrupted by handler */
					} while (0);
				}
			}
		}
		return 0;
}

#endif

/******************************************************************************
NAME  =	 vpn_tun_device_read_thread() ;
FUNC  =	 read data from vpn tun and handle the data;
INPUT =
RETU  =
DATE  =	 2017-04-10 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-10, cuiql , Original ;
*******************************************************************************/

static void *vpn_tun_device_read_thread(void *arg) {
    fd_set readfds;
    struct timeval tv;
    int retval = 0;
    ssize_t rd_len = -1;
    int vpnTunFd = -1;
	void *lwip_instance_context = arg;
	pbuf *p;
	void *loadblance_lwip_instance = NULL;
	struct ip_hdr *iph;
	struct tcp_hdr *tcph;

    ENTER_FUNC;
	global_set_thread_instance(lwip_instance_context);
    /*global variate config check*/
    vpnTunFd = gMPTCP_config.tunnel_FD;

    LogD("vpn_tun_device_read_thread entry thread\n");
    char name[40]={ 0 };
    sprintf(name,"vpn read");
    setThreadName(name);

    write(vpnTunFd, "aa", sizeof("aa")); //write the tun make the tun up,the data forword
    tunUp = 1;
#define TUN_MTU  (TUN_TCP_MSS + 40 +8)//1536 //65535
#if TUN_MTU > (65535-8)
#error "Error Len for TUN_MTU the max len is 65535 for pbuf, and when use udp, the offeset should be 8"
#endif
	p = pbuf_alloc(lwip_instance_context,PBUF_RAW, (u16_t) TUN_MTU, PBUF_RAM);
    while (likely(!s_tunif_end)) {
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        FD_ZERO(&readfds);
        FD_SET(vpnTunFd, &readfds);
        retval = select(vpnTunFd + 1, &readfds, NULL, NULL, &tv);

        if (unlikely(retval == -1)) {
            LogE(" vpn_tun_device_read_thread select error:%s.\n", strerror(errno));
            /*We should check if the vpnFd has updated*/
            goto END;
        }
        if (retval == 0) {
            LogI(" vpn_tun_device_read_thread select is timeout.\n");
            continue;
        }
        LogI("we need the handle result!\n");
        if (FD_ISSET(vpnTunFd, &readfds)) {
            /*memset(rdBuff, 0, sizeof(rdBuff));*/
            /*rd_len = read(vpnTunFd, rdBuff, sizeof(rdBuff));*/
			rd_len = read(vpnTunFd, p->payload, TUN_MTU);
            if (rd_len == -1) {
                if ((errno == EAGAIN) || (errno == EINTR)) {
                    /* Try again later */
                    continue;
                } else {
                    LogE("%s:%d, %s vpn tun read fails",__func__,__LINE__,strerror(errno));
                    goto END;
                }
            } else if (rd_len == 0) {
                LogI(" vpn_tun_device_read_thread read data from tun return 0");
                goto END;
            } else {
                LogI("start parsePacket,and packet len:%d", (int) rd_len);
				p->len = (u16_t)rd_len;
#if LWIP_MULTI_INSTANCE
                iph =(struct ip_hdr *)p->payload;
				switch(iph->_proto){
					case IP_PROTO_TCP:
					case IP_PROTO_UDP:
						tcph = (struct tcp_hdr *)(iph+1);
                        /*LWIP_DEBUGF(LWIP_STREAM_ALL_DEBUG,("src ip=%s sport=%d dport=%d len=%d",inet_ntoa((struct in_addr)iph->src),ntohs(tcph->src), ntohs(tcph->dest),rd_len));*/
						loadblance_lwip_instance = traffic_do_src_direct(ntohs(tcph->src), ntohs(tcph->dest), ntohl(iph->src.addr), ntohl(iph->dest.addr));
						break;
					/*case IP_PROTO_IGMP:*/
					/*case IP_PROTO_ICMP:*/
					default:
						break;
				}
#endif
				if(loadblance_lwip_instance == NULL)
					loadblance_lwip_instance = lwip_instance_context;
				
				p->instance = loadblance_lwip_instance;
                LWIP_DEBUGF(LWIP_STREAM_ALL_DEBUG, ( "vpn_tun_read_data select instance=%p",loadblance_lwip_instance));
                vpn_tun_read_data(loadblance_lwip_instance,p, (int) rd_len);
				
				p = pbuf_alloc(loadblance_lwip_instance,PBUF_RAW, (u16_t) TUN_MTU, PBUF_RAM);
				if(unlikely( p == NULL)){
					LogE("%s:%d, %s vpn tun pbuf_alloc fails",__func__,__LINE__,strerror(errno));
                    goto END;
				}
            }
        }
    }
    END:
	if(p != NULL)
	{
	   pbuf_free(p);
	}
    EXIT_FUNC;
    LogD("quit vpn_tun_device_read_thread");
    return NULL;
}

static void debug_tcp_flags(u8_t flags)
{
	if (flags & 0x01U) {
	  LogD("tun > net tcphdr flag : FIN ");
	}
	if (flags & 0x02U) {
	  LogD("tun > net tcphdr flag :SYN ");
	}
	if (flags & 0x04U) {
	  LogD("tun > net tcphdr flag :RST ");
	}
	if (flags & 0x08U) {
	  LogD("tun > net tcphdr flag :PSH ");
	}
	if (flags & 0x10U) {
	  LogD("tun > net tcphdr flag :ACK ");
	}
	if (flags & 0x20U) {
	  LogD("tun > net tcphdr flag :URG ");
	}
	if (flags & 0x40U) {
	  LogD("tun > net tcphdr flag :ECE ");
	}
	if (flags & 0x80U) {
	  LogD("tun > net tcphdr flag :CWR ");
	}
	if (flags & 0x80U) {
	  LogD("tun > net tcphdr flag :CWR ");
	}
}

void mptcp_print_header(struct pbuf *p) {
    struct ip_hdr *iphdr = LWIP_ALIGNMENT_CAST(struct ip_hdr*, p->payload);
    struct tcp_hdr *tcphdr;
    ip4_addr_t ip;

    LogD("IP Version/header length:%d", iphdr->_v_hl);
    LogD("Header Length:%d", iphdr->_len);
    LogD("Protocol:%d", iphdr->_proto);
    LogD("src:%d", iphdr->src.addr);
    LogD("dst:%d", iphdr->dest.addr);

    tcphdr = (struct tcp_hdr *) ((char *) p->payload + IP_HLEN);

    LogD("tcp src:%d", tcphdr->src);
    LogD("tcphdr dest:%d", tcphdr->dest);
    LogD("tcphdr ackno:%d", tcphdr->ackno);
    LogD("tcphdr seqno:%d", tcphdr->seqno);
    LogD("tcphdr wnd:%d", tcphdr->wnd);
    LogD("tcphdr chksum:%d", tcphdr->chksum);
	
	debug_tcp_flags(TCPH_FLAGS(tcphdr));

	LogD("tun > net tcphdr src : %d",ntohs(tcphdr->src));
	LogD("tun > net tcphdr dest : %d",ntohs(tcphdr->dest));
    ip.addr =  iphdr->src.addr;
    LogD("tun > net tcphdr src ip: %s", ip4addr_ntoa(&ip));
    ip.addr =  iphdr->dest.addr;
	LogD("tun > net tcphdr dest ip: %s",ip4addr_ntoa(&ip));
    LogD("tun > net tcphdr len : %d", ntohs(iphdr->_len));
}

void printStream1(char *data, int len) {
    char *buf = new char[len * 3 + 1];
    for (int i = 0; i < len; i++) {
        sprintf(&buf[i * 3], "%2x ", data[i]);
        if (data[i] > 0 && data[i] < 10)
            buf[i * 3] = '0';
    }
    LogD("icmp mutp message:%s", buf);
    delete[] buf;
}

unsigned short cal_chksum(unsigned short *buff, int Size) {
    unsigned long cksum = 0;
    while (Size > 1) {
        cksum += *buff++;
        Size -= sizeof(unsigned short);
    }
    if (Size == 1) {
        cksum += *(unsigned char *) buff;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (~(unsigned short)cksum);
}

void vpn_tun_read_data(void *instance,pbuf *p, int len) {
    ip_head *iphdr;
    struct pbuf *q;
    struct ip_hdr *temp;
    struct udphdr *udphdr;
    static uint32_t tunAddr = inet_addr(TUN_IP);
    //static uint32_t tunAddr = inet_addr("23.14.1.210");
    char *packet = (char *)p->payload;

    iphdr = (ip_head *) packet;
    switch (iphdr->_proto) {
        case IP_PROTO_TCP: {
#ifdef MPTCP_PROXY_MODULE
            temp = (struct ip_hdr *) packet;

            LogI("%s:%d %s",__func__,__LINE__,inet_ntoa(temp->dest.addr));
            if (temp->src.addr == tunAddr) {
            //if (temp->dest.addr == inet_addr("39.14.1.6") || temp->dest.addr == inet_addr("39.14.1.4")) {
            //if (temp->dest.addr == inet_addr("23.14.1.210")) {
                            /*mptcp_print_header(p);*/
			    
#if LWIP_PCAP_SUPPORT
				tun_write_pcap(vpn_pcap_fd,(char *)p->payload,((int)p->len), LWIP_PCAP_VPN_UP_STRAM);
#endif
			    ip4_nat_input_pkt_from_tun(instance,p);
            }
			else
			{
			    pbuf_free(p);
			}
#endif
            break;
        }
        case IP_PROTO_UDP:  {
            temp = (struct ip_hdr *) packet;
#if LWIP_UDP_THROUGH_HAG
            LogI("UDP: src  %x", temp->src.addr);
            if (temp->src.addr == inet_addr(TUN_IP)) {
                temp->src.addr = ppca_s->mccp_ue_ip;
                temp->_chksum = 0;
                temp->_offset = htons((ntohs(temp->_offset)) &(0x1FFFU));
                temp->_chksum = cal_chksum((unsigned short *) packet, sizeof(struct ip_hdr));
                char *udpPacket = packet + sizeof(struct ip_hdr);
                udphdr = (struct udphdr *) udpPacket;
                if((ntohs(temp->_offset)&IP_OFFMASK) == 0) {
                    udphdr->chksum = 0;
                }

                LogI("UDP: sent by tunne src %x:%d dst %x:%d", temp->src.addr,ntohs(udphdr->src),temp->dest.addr,ntohs(udphdr->dest));

                MEMMOVE((char *) (p->payload) + 8, packet, len);
                LogI("icmp char:%c", *((char *) (p->payload) + 8));
                p->payload = (char*)(p->payload) + 8;
#if LWIP_PCAP_SUPPORT
                tun_write_pcap(vpn_pcap_fd,(char *)p->payload,((int)p->len),LWIP_PCAP_VPN_UP_STRAM);
#endif

#if LWIP_TWO_TCP_STACK
#if !WIFI_LTE_SWITCH
                mutp_encode_send((void *)&g_stPartlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
#else
                if(isSetLteAddr){
                    mutp_encode_send((void *)&g_stPartlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
                }
                if(isSetWifiAddr && !isSetLteAddr){
                    mutp_encode_send((void *)&g_stPartlwipInstance,ppca_s->mccp_mpgw_ip1, ppca_s->mccp_mpgw_port , p,1);
                }
#endif
#else
#if !WIFI_LTE_SWITCH
                mutp_encode_send((void *)&g_stlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
#else
                if(isSetLteAddr){
                    mutp_encode_send((void *)&g_stlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
                }
                if(isSetWifiAddr && !isSetLteAddr){
                    mutp_encode_send((void *)&g_stlwipInstance,ppca_s->mccp_mpgw_ip1, ppca_s->mccp_mpgw_port , p,1);
                }
#endif
#endif



                pbuf_free(p);
            }else{
                char *udpPacket = packet + sizeof(struct ip_hdr);
                LogI("UDP: sent not by tunne src %x:%d dst %x:%d", temp->src.addr,ntohs(udphdr->src),temp->dest.addr,ntohs(udphdr->dest));
                int udpLen = len - sizeof(struct ip_hdr);
#if LWIP_PCAP_SUPPORT
                tun_write_pcap(vpn_pcap_fd,(char *)p->payload,((int)p->len),LWIP_PCAP_VPN_UP_STRAM);
#endif
                vpn_tun_receive_udp_packet_handle(temp, udpPacket, udpLen);

                pbuf_free(p);
            }
#else
            {
				char *udpPacket = packet + sizeof(struct ip_hdr);
                LogI("UDP: sent not by tunne src %x:%d dst %x:%d", temp->src.addr,ntohs(udphdr->src),temp->dst.addr,ntohs(udphdr->dest));
                int udpLen = len - sizeof(struct ip_hdr);
#if LWIP_PCAP_SUPPORT
				tun_write_pcap(vpn_pcap_fd,(char *)p->payload,(int)p->len,LWIP_PCAP_VPN_UP_STRAM);
#endif

                vpn_tun_receive_udp_packet_handle(temp, udpPacket, udpLen);

                pbuf_free(p);
            }
#endif
            break;
        }
        case IP_PROTO_ICMP: {
            temp = (struct ip_hdr *) packet;
				
            temp->src.addr = ppca_s->mccp_ue_ip;
			temp->_chksum = 0;

            temp->_chksum = cal_chksum((unsigned short *) packet, sizeof(struct ip_hdr));

            MEMMOVE((char *) (p->payload) + 8, packet, len);
            LogI("icmp char:%c", *((char *) (p->payload) + 8));

	        p->payload = (char*)(p->payload) + 8;

#if LWIP_PCAP_SUPPORT
			tun_write_pcap(vpn_pcap_fd,(char *)p->payload,((int)p->len), LWIP_PCAP_VPN_UP_STRAM);
#endif
#if LWIP_TWO_TCP_STACK
#if !WIFI_LTE_SWITCH
            mutp_encode_send((void *)&g_stPartlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
#else
            if(isSetLteAddr){
                mutp_encode_send((void *)&g_stPartlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
            }
            if(isSetWifiAddr && !isSetLteAddr){
                mutp_encode_send((void *)&g_stPartlwipInstance,ppca_s->mccp_mpgw_ip1, ppca_s->mccp_mpgw_port , p,1);
            }
#endif
#else
            #if !WIFI_LTE_SWITCH
                mutp_encode_send((void *)&g_stlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
			#else
                if(isSetLteAddr){
                    mutp_encode_send((void *)&g_stlwipInstance,ppca_s->mccp_mpgw_ip, ppca_s->mccp_mpgw_port , p,1);
                }
                if(isSetWifiAddr && !isSetLteAddr){
                    mutp_encode_send((void *)&g_stlwipInstance,ppca_s->mccp_mpgw_ip1, ppca_s->mccp_mpgw_port , p,1);
                }
			#endif
#endif

            pbuf_free(p);
            break;
        }
        default:
            LogI("unkown proto type: %d", iphdr->_proto);
			pbuf_free(p);
            break;
    }
}

/*===========================================================================
  FUNCTION mptcp_init()

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
int tunif_init(mptcp_data_init_V01 *data, JNIEnv *env) {


    LogD("tunif_init entry");

    int i,ret = -1;
	
	traffic_init();

	LogE("tunif_init address=%p",(void *)(&tunif_init));
	LogE("tcpip_input address=%p",(void *)(&tcpip_input));
	LogE("tcp_output address=%p",(void *)(&tcp_output));
	LogE("ip4_nat_input_pkt_from_tun address=%p",(void *)(&ip4_nat_input_pkt_from_tun));
	
    memset((void *)&g_stlwipInstance, 0x0,sizeof(struct lwip_instance));
	register_lwip_instance(&g_stlwipInstance);
	traffic_register_member(&g_stlwipInstance);

#if LWIP_TWO_TCP_STACK
    memset((void *)&g_stPartlwipInstance, 0x0,sizeof(struct lwip_instance));
    register_lwip_instance(&g_stPartlwipInstance);
    /*traffic_register_member(&g_stPartlwipInstance);*/
#endif

#if	LWIP_MULTI_INSTANCE
    for(i=0;i<MAX_INSTANCE_NUM-1;i++){
        memset((void *)&g_stlwipInstanceOther[i], 0x0,sizeof(struct lwip_instance));
	    register_lwip_instance(&g_stlwipInstanceOther[i]);
	    traffic_register_member(&g_stlwipInstanceOther[i]);
#if LWIP_TWO_TCP_STACK
		memset((void *)&g_stPartlwipInstanceOther[i], 0x0,sizeof(struct lwip_instance));
        register_lwip_instance(&g_stPartlwipInstanceOther[i]);
#endif
        /*traffic_register_member(&g_stPartlwipInstanceOther[i]);*/
    }

#endif

    LogE("tunif_init: traffic num=%d !",traffic_get_instance_num());
    pthread_mutex_init(&tunPacketListMutex, NULL);
    sem_init(&tunWrtSem, 0, 0);
    vpn_data_list = queueCreate((char*)"vpnlist",1024);
#if LWIP_VPNQUE_PACKET
	vpn_write_que = packet_queue_init("vpn",4096,(free_node_callback)&free);
#endif

    ret = udp_handle_init((void *)&g_stlwipInstance);
    if (ret) {
        LogE("tunif_init: udp_handle_init fail !");
        return -1;
    }

    /* create vpn tun device read thread*/
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    s_tunif_end = 0;
    pthread_t thId = 0;

#if TEST_TUNNEL
    Test_lwip_to_tunnel();
#endif
    /*init mptcp protocol module.*/
#ifdef LWIP_TCP
    tcpip_init(&g_stlwipInstance, NULL, NULL);
#if LWIP_TWO_TCP_STACK
    tcpip_init(&g_stPartlwipInstance, NULL, NULL);
#endif
#endif
#if LWIP_PERFORMANCE_TEST_ENABLE_VETH0
    netif_linux_setup();
#endif
#if MPTCP_PROXY_MODULE
    /*init the proxy server module.*/
    mptcp_proxy_server_init(&g_stlwipInstance, &g_stPartlwipInstance);
#endif

#if UNITE_TEST
    ppca_s->mccp_mpgw_ip = inet_addr("10.54.255.138");
    ppca_s->mccp_mpgw_port = 5557;
#endif

#if !LWIP_PERFORMANCE_TEST_ENABLE_VETH0
#if !LWIP_TWO_TCP_STACK
	mutp_start_recv((void *)(&g_stlwipInstance),mptcp_proxy_get_netif((void *)(&g_stlwipInstance)));
#else 
    mutp_start_recv((void *)(&g_stPartlwipInstance),mptcp_proxy_get_netif((void *)(&g_stPartlwipInstance)));
#endif
#endif

#if LWIP_MULTI_INSTANCE
   for(i=0;i<MAX_INSTANCE_NUM-1;i++){
       tcpip_init(&g_stlwipInstanceOther[i], NULL, NULL);
#if LWIP_TWO_TCP_STACK
       tcpip_init(&g_stPartlwipInstanceOther[i], NULL, NULL);
#endif
       mptcp_proxy_server_init(&g_stlwipInstanceOther[i], &g_stPartlwipInstanceOther[i]);
#if !LWIP_TWO_TCP_STACK
       mutp_start_recv((void *)(&g_stlwipInstanceOther[i]),mptcp_proxy_get_netif((void *)(&g_stlwipInstanceOther[i])));
#else 
	   mutp_start_recv((void *)(&g_stPartlwipInstanceOther[i]),mptcp_proxy_get_netif((void *)(&g_stPartlwipInstanceOther[i])));
#endif

   }
#endif

#if LWIP_ICMP_SUPPORT
    icmp_init((void *)&g_stlwipInstance,env);
#endif
/*
    pthread_attr_t attr_T;
    pthread_attr_init(&attr_T);
    attr_T.sched_priority = sched_get_priority_max(SCHED_FIFO);*/
    //attr_T.sched_policy = SCHED_FIFO;
#if 1
    tun_write_flag = 1;
    if (pthread_create(&thId, NULL, vpn_write_pubf_thread, (void *)&g_stlwipInstance) != 0) {
        LogE("sm_init: vpn_tun_send_udp_packet_handle thread create fail !");
        /*destroy semaphore object*/
        udp_handle_release();
        tcpip_deinit(&g_stlwipInstance);
        mptcp_proxy_server_destroy(&g_stlwipInstance);
        return -1;
    }
#else
    if (pthread_create(&thId, NULL, vpn_write_data_list_thread, NULL) != 0) {
        LogE("sm_init: vpn_tun_send_udp_packet_handle thread create fail !");
        /*destroy semaphore object*/
        udp_handle_release();
        tcpip_deinit();
        mptcp_proxy_server_destroy();
        //sys_sem_free(&proxy_server_sem);
        return -1;
    }
#endif

    if (pthread_create(&thId, NULL, vpn_tun_device_read_thread, (void *)&g_stlwipInstance) != 0) {
        LogE("sm_init: vpn_tun_send_udp_packet_handle thread create fail !");
        /*destroy semaphore object*/
        udp_handle_release();
        tcpip_deinit(&g_stlwipInstance);
        mptcp_proxy_server_destroy(&g_stlwipInstance);
        //sys_sem_free(&proxy_server_sem);
        return -1;
    }

    gVPN_thread_data.vpn_tun_device_read_thread_t = thId;
    gMPTCP_config.is_mptcp_init = 1;

    return 0;
}

/*===========================================================================
  FUNCTION mptcp_destroy()

  DESCRIPTION
    destroy MPTCP protocol stack,realse resouce and stop thread.

  PARAMETERS
    None

  RETURN VALUE
    None

  DEPENDENCIES
    None

  SIDE EFFECTS
    None
===========================================================================*/

void tunif_end_loop() {
    int i;
	struct timeval tv, st;
	
    LogD("close the mptcp loop");
    tunUp = 0;

    if (gMPTCP_config.is_mptcp_init ) {
/**********************************************************************************/
        s_tunif_end = 1;
        pthread_join(gVPN_thread_data.vpn_tun_device_read_thread_t, NULL);
        /*1. exit mptcp proxy in first*/
        mptcp_proxy_server_destroy(&g_stlwipInstance);
        mutp_destory(&g_stlwipInstance);
        usleep(1);
        gettimeofday(&tv, NULL);
        LogE("mptcp_proxy_server_destroy g_stlwipInstance cost sec=%u, usec=%u",(u32_t)(tv.tv_sec - st.tv_sec),(u32_t)(tv.tv_usec - st.tv_usec));
        for(i=0;i<MAX_INSTANCE_NUM-1;i++) {
            mptcp_proxy_server_destroy(&g_stlwipInstanceOther[i]);
            mutp_destory(&g_stlwipInstanceOther[i]);
            usleep(1);
            gettimeofday(&tv, NULL);
            LogE("mptcp_proxy_server_destroy g_stlwipInstanceOther[%d] cost sec=%d, usec=%d", i,
                 (u32_t) (tv.tv_sec - st.tv_sec), (u32_t) (tv.tv_usec - st.tv_usec));
        }
        udp_handle_release();
        sleep(1);/*wait for all proxy thread and accept thread exit*/
/**********************************************************************************/
        sleep(1);/*wait for all message have been exit*/
/**********************************************************************************/
       /*3. exit mptcp_stack */
        tcpip_deinit(&g_stlwipInstance);
        usleep(1);
        gettimeofday(&tv, NULL);
        LogE("tcpip_deinit g_stlwipInstance cost sec=%d, usec=%d",(u32_t)(tv.tv_sec - st.tv_sec),(u32_t)(tv.tv_usec - st.tv_usec));

        for(i=0;i<MAX_INSTANCE_NUM-1;i++){
            tcpip_deinit(&g_stlwipInstanceOther[i]);
            usleep(1);
            gettimeofday(&tv, NULL);
            LogE("tcpip_deinit g_stlwipInstanceOther[%d] cost sec=%d, usec=%d",i,(u32_t)(tv.tv_sec - st.tv_sec),(u32_t)(tv.tv_usec - st.tv_usec));
        }
        sleep(1);
        tun_write_flag = 0;/*exit tun write thread to delete buf in the list*/
/**********************************************************************************/
        gettimeofday(&st, NULL);
		global_free_param();

        sem_destroy(&tunWrtSem);
        pthread_mutex_destroy(&tunPacketListMutex);
    }
    if(vpn_data_list != NULL ){
		destoryQue(vpn_data_list);
		vpn_data_list = NULL;
    }
#if LWIP_VPNQUE_PACKET
	if(vpn_write_que != NULL)
	{
	   packet_queue_free(vpn_write_que);
	   vpn_write_que = NULL;
	}
#endif
    gMPTCP_config.is_mptcp_init  = 0;

#if LWIP_PCAP_SUPPORT
    tun_pcap_close(vpn_pcap_fd);
#endif

}

/***
 * mptcp proxy exit all instance,
 * @param instances  the instance must be a array
 * @param n  the number of the instance need to be destory
 */
static void mptcp_proxy_exit_all(lwip_instance *instances,int n){
    if(instances != NULL){
        for(int i = 0;i<n;i++){
            mptcp_proxy_server_destroy(instances + i);
        }
    }
}
