#include "lwip/lwipopts.h"
#include "tools/tools.h"
#include "vpn_tun/vpn_tun_if.h"
#include <arpa/inet.h>
#include "tunnel/tunnel.h"
#include <iostream>
#include <lwip/module.h>
#include "heartbeat/heartbeat.h"
#include "linux_stub.h"
#include <string.h>
#include <stdlib.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <signal.h>
#include <termios.h>
#include <sys/time.h>
#include <unistd.h>
#include <getopt.h>


extern int tunnel_debug_counter(void *instance, char *pBuffer, unsigned int len);

static char *GET_ENV_VALUE(char *name, char *default_val){
	char *envPtr = getenv((name));  
	if(envPtr != NULL)  
		return envPtr; 
	else  
		return (default_val); 
}

#define LTE_IP GET_ENV_VALUE((char*)"LTE_IP",(char*)"189.29.11.116")
#define WIFI_IP GET_ENV_VALUE((char*)"WIFI_IP",(char*)"192.168.2.49")
#define LTE_GATEWAY GET_ENV_VALUE((char*)"LTE_GATEWAY",(char*)"189.0.0.1")
#define WIFI_GATEWAY GET_ENV_VALUE((char*)"WIFI_GATEWAY",(char*)"192.168.2.1")

#define HAG_SRV_IP GET_ENV_VALUE((char*)"HAG_SRV_IP",(char*)"172.26.13.2")
#define HAG_SRV_PORT GET_ENV_VALUE((char*)"HAG_SRV_PORT",(char*)"10000")

#define WIFI_DEV_NAME GET_ENV_VALUE((char*)"WIFI_DEV_NAME",(char*)"wlp3s0")
#define LTE_DEV_NAME GET_ENV_VALUE((char*)"LTE_DEV_NAME",(char*)"enp2s0")
#define IMSI GET_ENV_VALUE((char*)"IMSI",(char*)"454061234567888")
#define IEMI GET_ENV_VALUE((char*)"IEMI",(char*)"865810030088765")

extern int tunUp;
extern mptcp_data_init_V01 gMPTCP_config;
extern int LogOpenOrClose;

void init_daemon(void)
{
    int pid;
    int i;

    if(pid=fork())
        exit(0);/*是父进程，结束父进程*/
    else if(pid< 0)
        exit(1);/*fork失败，退出*/

    /*是第一子进程，后台继续执行*/
    setsid();/*第一子进程成为新的会话组长和进程组长*/
    /*并和控制终端分离*/
    if(pid=fork())
       exit(0);/*是第一子进程，结束第一子进程*/
    else if(pid< 0)
       exit(1);/*fork失败，退出*/

    /*是第二子进程，继续*/
    /*第二子进程不再是会话组长*/

    for(i=0;i< NOFILE; i)/*关闭打开的文档描述符*/
       close(i);
    chdir("/tmp");/*改变工作目录到/tmp*/
    umask(0);/*重设文档创建掩模*/
    return;
}

int tun_create( char * dev, int flags) 
{ 
     struct ifreq ifr; 
     int fd, err; 


     if ( ( fd = open("/dev/net/tun" , O_RDWR) ) < 0) 
         return fd; 

     memset (&ifr, 0, sizeof ( ifr) ) ; 
     ifr. ifr_flags |= flags; 
     if ( * dev != '\0' ) 
         strncpy ( ifr. ifr_name, dev, IFNAMSIZ) ; 
     if (( err = ioctl(fd, TUNSETIFF, ( void * ) & ifr) ) < 0) { 
         close ( fd) ; 
         return err; 
     } 
     strcpy(dev, ifr. ifr_name) ; 

     return fd; 
} 

 int test_main(int argc, char * argv[ ]) 
{ 
        int tun, ret; 
        char tun_name[IFNAMSIZ] ; 
        unsigned char buf[4096] ; 
        unsigned char ip[4] ={0xa,0,2,0};

        /*init_daemon();/*初始化为Daemon*/ 
        tun_name[ 0] = '\0' ; 
        tun = tun_create(tun_name, IFF_TUN | IFF_NO_PI) ; 
        if ( tun < 0) { 
                perror ("tun_create" ) ; 
                return 1; 
        } 
        printf("TUN name is %s\n" , tun_name) ;

        while (1) { 
                 

                ret = read(tun, buf, sizeof (buf) ) ; 
                if ( ret < 0) 
                        break ; 
                memcpy(ip, & buf[ 12] , 4) ; 
                memcpy(&buf[ 12] , &buf[ 16] , 4) ; 
                memcpy(&buf[ 16] , ip, 4) ; 
                buf[20] = 0; 
                *(( unsigned short *)&buf[22]) += 8; 
                /*printf("read %d bytes/n" , ret) ;*/ 
                ret = write(tun, buf, ret) ; 
                /*printf("write %d bytes/n" , ret) ;*/ 
        } 
        close(tun);

        return 0; 
}

/*set wifi ip*/
void VpnNative_setWifiIp(char *ip) {

    gMPTCP_config.wifiIp.addr = htonl(inet_addr(ip));
	gMPTCP_config.wpriority = 2;
    mutp_setWifiAddr(ip);
}

void VpnNative_setLteIp(char *ip) 
{
    gMPTCP_config.lteIp.addr = htonl(inet_addr(ip));
	gMPTCP_config.wpriority = 1;
    mutp_setLteAddr(ip);
    set_lte_ip(inet_addr(ip));
}

int VpnNative_setAuthInfo(
        char *imsi,
        char *imei,
        char *mac,
        char *auth_server_ip,
        int port,
        int mode) {

    int ret = 0;

    memset(&gMPTCP_config, 0, sizeof(gMPTCP_config));

    stillRun = 1;
    if (imsi == NULL || auth_server_ip == NULL) {
        LogE("current argument is not correct! file:%s line %d", __FILE__, __LINE__);
        return -1;
    }

    global_init_once();

	
	/*imsi=454061234567888*/
	/*imei=865810030088765*/
	
    ret = mccp_init(imsi, imei, mac, auth_server_ip, port);
    if (ret == 0) {		
		ret = mccp_auth();
    }
  
    return ret;
}

void VpnNative_openCrashLog(void){

#if LWIP_PCAP_SUPPORT
		char *sdcard_dir;
		char pcap_file_name[512];
        int i;

		
        /*only one instance work when pcap is setting*/
		if(vpn_pcap_fd >0 )
			return ;

		sdcard_dir = get_local_storage_dir();
		if(sdcard_dir != NULL){
			memset(pcap_file_name, 0x0,512);
			strcpy(pcap_file_name, sdcard_dir);
			
			time_t t = time(NULL);
			char buff1[32]={0};
 			strftime(buff1, sizeof(buff1), "%Y-%m-%d-%H%M%S", localtime(&t));
            LogE("tunif_init strftime=%s",buff1);
			for(i=0; i<strlen(buff1);i++){
				if(buff1[i] == '\\' || buff1[i] == '/')
					buff1[i] = '-';
			}
			strcat(pcap_file_name,"/pcap-");
			strcat(pcap_file_name,buff1);
			strcat(pcap_file_name, ".cap");
			vpn_pcap_fd = tun_pcap_init(pcap_file_name);
			free(sdcard_dir);
		}
		else
			vpn_pcap_fd = tun_pcap_init("/sdcard/Android/data/com.example.user.myapplication/test.cap");
#endif
}

void VpnNative_closeCrashLog(void){
#if LWIP_PCAP_SUPPORT
    tun_pcap_close(vpn_pcap_fd);
#endif
}

void VpnNative_openLog(int openClose){
    LogOpenOrClose = openClose;
}

void add_datalink_route(int isWiFi,const char *env_item_name, char *host_ip, char *gateway, char *dev_name)
{
    char cmd_sys_buf[256];
	char *bufPtr;
	int isAddItem = 1;
	
	memset(cmd_sys_buf,0x0,256);
	sprintf(cmd_sys_buf,"export %s=`route -n | grep %s | grep UGH |  egrep \"([0-9]{1,3}\.?){4}\" -o |head -1`\0", env_item_name,dev_name);
	system(cmd_sys_buf);
	bufPtr = getenv(env_item_name);
	if(bufPtr != NULL)
	{
	    if(strcmp(bufPtr, host_ip) == 0)
			isAddItem = 0;
			
	}
	
	printf("add_datalink_route %s host ip=%s gateway=%s device=%s isAddItem=%d\r\n", env_item_name,bufPtr,gateway,dev_name,isAddItem);
	if(isAddItem > 0)
	{
		memset(cmd_sys_buf,0x0,256);
		sprintf(cmd_sys_buf,"sudo route add -net %s netmask 255.255.255.255 gw %s dev %s\0", host_ip,gateway,dev_name);
		system(cmd_sys_buf);
		printf("mptcp: add hag %s route ip item :%s to interface %s\r\n",(isWiFi?"WiFi":"LTE"),host_ip,dev_name);
	}
    return;
}

void add_datalink_dynamic_route(int isWiFi,char *host_ip)
{
    if(isWiFi==0)
	    add_datalink_route(0,"HAG_LET_DATA_IP",host_ip,LTE_GATEWAY,LTE_DEV_NAME);
    else
	    add_datalink_route(1,"HAG_WIFI_DATA_IP",host_ip,WIFI_GATEWAY,WIFI_DEV_NAME);
    return;
}

void delete_default_route(int isWiFi,const char *env_item_name, char *gateway, char *dev_name)
{
    char cmd_sys_buf[256];
	char *bufPtr;
	int isDelItem = 0;

	memset(cmd_sys_buf,0x0,256);
	sprintf(cmd_sys_buf,"export %s=`ip route show | grep default | grep %s | grep %s |	egrep \"([0-9]{1,3}\.?){4}\" -o |head -1`\0", env_item_name, dev_name, gateway);
	system(cmd_sys_buf);
	bufPtr = getenv(env_item_name);
	
	if(bufPtr != NULL)
	{
	    if(strcmp(bufPtr, "10.0.2.0") != 0){
			if(strcmp(bufPtr, gateway) == 0)
			   isDelItem = 1;
	    }	
	}
	
	printf("delete_default_route %s host ip=%s gateway=%s device=%s isDelItem=%d\r\n", env_item_name,bufPtr,gateway,dev_name,isDelItem);
	if(isDelItem > 0){
		memset(cmd_sys_buf,0x0,256);
		sprintf(cmd_sys_buf,"sudo route delete default gw %s dev %s\0",gateway, dev_name);
		system(cmd_sys_buf);
		printf("mptcp: delete hag %s default gateway :%s to interface %s\r\n",(isWiFi?"WiFi":"LTE"),gateway,dev_name);
		
	}
    return;
}

char *get_network_interface_ip(const char *env_item_name, char *dev_name)
{
    char cmd_sys_buf[256];
	char *bufPtr = NULL;

	memset(cmd_sys_buf,0x0,256);
	sprintf(cmd_sys_buf,"export %s=`ifconfig %s | egrep \"([0-9]{1,3}\.?){4}\" -o |head -1`\0", env_item_name, dev_name);
	system(cmd_sys_buf);
	bufPtr = getenv(env_item_name);
	return bufPtr ;
}
	
void exit_handler(int signo)   
{  
    printf("mptcp exit! stop!!!\n");  
    _exit(0);  
}  

void mptcp_on_exit(void)
{

	stillRun = 0;
    mccp_destory();
    if (ppca_s->mccp_auth == TRUE)
    {
        tunif_end_loop();
        mutp_all_instance_destory();
    }

	VpnNative_openLog(0);
	
	VpnNative_closeCrashLog();
}

void signal_exit_handler(int sig)
{
    exit(0);
}

void changemode(int);
int  kbhit(void);
 
void changemode(int dir)
{
  static struct termios oldt, newt;

  if ( dir == 1 )
  {
    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~( ICANON | ECHO );
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);
  }
  else
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
}

int kbhit (void)
{
  struct timeval tv;
  fd_set rdfs;

  tv.tv_sec = 0;
  tv.tv_usec = 0;

  FD_ZERO(&rdfs);
  FD_SET (STDIN_FILENO, &rdfs);

  select(STDIN_FILENO+1, &rdfs, NULL, NULL, &tv);
  return FD_ISSET(STDIN_FILENO, &rdfs);
}


void Usage(void)
{
}

int main(int argc,char *argv[])
{

    int fd;/*/dev/tun*/
	char lteIp[16] = {0};
	char wifiIp[16] = {0};
	char imsi[32] = {0};
	char imei[32] = {0};
	char mac[32] = {0};
	char auth_server_ip[32]={0};
	char auth_server_port[8]={0};
	int ret,port = 10000;
	int trace_log = 0;
	int pcap_log = 0;
    char  tun_name[32]={0};
    int times = 0;
	char scan_c;
	struct in_addr lte_addr;
	char cmd_sys_buf[256];
	char *bufPtr = NULL;
	struct timeval tv1,tv2;
	int opt;  
	int count_arg = 0; 
	
 
 
	atexit(mptcp_on_exit);
    signal(SIGTERM, signal_exit_handler);
    signal(SIGINT, signal_exit_handler);

	
	/*default value*/
	memset(cmd_sys_buf,0x0,256);
	bufPtr = get_network_interface_ip("WIFI_IP", WIFI_DEV_NAME);
	if(bufPtr != NULL)
		strcpy(wifiIp,bufPtr);
	else
		strcpy(wifiIp,WIFI_IP);
	
	bufPtr = get_network_interface_ip("LTE_IP", LTE_DEV_NAME);
	if(bufPtr != NULL)
		strcpy(lteIp,bufPtr);
	else
		strcpy(lteIp,LTE_IP);
	
	strcpy(auth_server_ip,HAG_SRV_IP);

    bufPtr = HAG_SRV_PORT;
	strcpy(auth_server_port, bufPtr);
	port = atoi(auth_server_port);
		
	/*imsi=454061234567888*/
	/*strcpy(imsi,IMSI);*/
	/*imei=865810030088765*/
	/*strcpy(imei,IMEI);*/
	mac[0] = 0x9a;
	mac[1] = 0xd2;
	mac[2] = 0x60;
	mac[3] = 0x72;
	mac[4] = 0x4c;
	mac[5] = 0x97;
	
	/*open crash*/
    setup_breakpad();
#ifdef GET_OPT
   while ((opt = getopt(argc, argv, "pt")) != -1) {  
          switch (opt) {  
                case 'p':  
                        pcap_log = 1;    
                        break;  
				case 't':  
                        trace_log = 1;    
                        break; 
                case 'l':  
                        strcpy(lteIp,optarg);       
                        break;  
                case 'w':  
                        strcpy(wifiIp,optarg); ;  
                        break;  
                case 'h':   
                        strcpy(auth_server_ip,optarg);  
                        break;  
                case 'p':  
                        strcpy(auth_server_port, optarg);;  
                        break;  
			    case 'd':   
                        strcpy(wifi_device,optarg);  
                        break;  
                case 'e':  
                        strcpy(lte_device, optarg);;  
                        break; 
			    case 'i':  
                        strcpy(imsi, optarg); 
                        break; 
				case 'e':  
                        strcpy(imei, optarg); 
                        break; 
                default:        /* '?' */  
                        Usage();  
                        exit(-1);  
                        break;  
                }  
        }      
#endif
	
	/*open pcap*/
	if(pcap_log > 0){
		VpnNative_openCrashLog();
		printf("mptcp pcap function is on\r\n");
	}

        tun_name[ 0] = '\0' ; 
        fd = tun_create(tun_name, IFF_TUN | IFF_NO_PI) ; 
        if ( fd < 0) { 
                perror ("tun_create" ) ; 
                return 1; 
        } 
        printf("TUN name is %s\n" , tun_name) ;

		
		/*system("/sbin/ip link set dev tun0 up mtu 1500");*/
		/*system("/sbin/ip addr add dev tun0 10.0.2.0");*/
		/*system("/sbin/ip route add 0.0.0.0/1 via 10.0.2.0");*/
		system("sudo ifconfig tun0 10.0.2.0 up");
		/*virtualbox host:192.168.1.204*/
		/*virtualbox host gateway:192.168.1.1*/

		/*
		memset(cmd_sys_buf,0x0,256);
		sprintf(cmd_sys_buf,"export HAG_SRV_ROUTE=`route -n | grep %s | grep UGH |	egrep \"([0-9]{1,3}\.\?){4}\" -o |head -1`\0", HAG_SRV_IP);
		system(cmd_sys_buf);
		bufPtr = getenv("HAG_SRV_ROUTE");
		if(bufPtr == NULL || strcmp(bufPtr, HAG_SRV_IP) != 0)
		{
			memset(cmd_sys_buf,0x0,256);
			sprintf(cmd_sys_buf,"sudo route add -net %s netmask 255.255.255.255 gw %s dev %s\0", HAG_SRV_IP,LTE_GATEWAY,LTE_DEV_NAME);
			system(cmd_sys_buf);
			printf("mptcp: add hag lte route ip item :%s to interface %s\r\n",HAG_SRV_IP,LTE_DEV_NAME);
		}*/
		add_datalink_route(0, "HAG_SRV_ROUTE", HAG_SRV_IP,LTE_GATEWAY,LTE_DEV_NAME);

		/*
		memset(cmd_sys_buf,0x0,256);
		sprintf(cmd_sys_buf,"export HAG_LET_DATA_IP=`route -n | grep %s | grep UGH |	egrep \"([0-9]{1,3}\.?){4}\" -o |head -1`\0", HAG_LET_DATA_IP);
		system(cmd_sys_buf);
		bufPtr = getenv("HAG_LET_DATA_IP");
		if(bufPtr == NULL || strcmp(bufPtr, HAG_LET_DATA_IP) != 0)
		{		
			memset(cmd_sys_buf,0x0,256);
			sprintf(cmd_sys_buf,"sudo route add -net %s netmask 255.255.255.255 gw %s dev %s\0", HAG_LET_DATA_IP,LTE_GATEWAY,LTE_DEV_NAME);
			system(cmd_sys_buf);
			printf("mptcp: add hag lte data ip item :%s to interface %s\r\n",HAG_LET_DATA_IP,LTE_DEV_NAME);
        }

		memset(cmd_sys_buf,0x0,256);
		sprintf(cmd_sys_buf,"export HAG_WIFI_DATA_IP=`route -n | grep %s | grep UGH |	egrep \"([0-9]{1,3}\.?){4}\" -o |head -1`\0", HAG_WIFI_DATA_IP);
		system(cmd_sys_buf);
		bufPtr = getenv("HAG_WIFI_DATA_IP");
		if(bufPtr == NULL || strcmp(bufPtr, HAG_WIFI_DATA_IP) != 0)
		{
			memset(cmd_sys_buf,0x0,256);
			sprintf(cmd_sys_buf,"sudo route add -net %s netmask 255.255.255.255 gw %s dev %s\0", HAG_WIFI_DATA_IP,WIFI_GATEWAY,WIFI_DEV_NAME);
			system(cmd_sys_buf);
			
			printf("mptcp: add hag wifi data ip item :%s to interface %s\r\n",HAG_WIFI_DATA_IP,WIFI_DEV_NAME);
		}
		*/
		
		/*500M HAG
		system("route add -net 192.168.1.204 netmask 255.255.255.255 gw 20.0.2.1 dev eth0");
		system("route add -net 192.168.1.1 netmask 255.255.255.255 gw 20.0.2.1 dev eth0");*/
		/*DNS*/

        /*physical host pc is not need*/
		/*system("route add -net 10.10.11.249 netmask 255.255.255.255 gw 20.0.2.1 dev wlan0");
		  system("route add -net 10.10.11.1 netmask 255.255.255.255 gw 20.0.2.1 dev wlan0");*/ /*DNS*/
	
      
        system("sudo route add default gw 10.0.2.0 dev tun0");

		delete_default_route(0,"DEFAULT_GATEWAY_LTE_IP", LTE_GATEWAY, LTE_DEV_NAME);
		delete_default_route(1,"DEFAULT_GATEWAY_WIF_IP", WIFI_GATEWAY, WIFI_DEV_NAME);

		#if 0
		memset(cmd_sys_buf,0x0,256);
		sprintf(cmd_sys_buf,"export DEFAULT_GATEWAY_IP=`ip route show | grep default | grep %s | grep %s |	egrep \"([0-9]{1,3}\.?){4}\" -o |head -1`\0", LTE_DEV_NAME, LTE_GATEWAY);
		system(cmd_sys_buf);
		bufPtr = getenv("DEFAULT_GATEWAY_IP");
		if(bufPtr != NULL && strcmp(bufPtr, "10.0.2.0") != 0){
			memset(cmd_sys_buf,0x0,256);
			if(strcmp(bufPtr, LTE_GATEWAY) == 0){
			   sprintf(cmd_sys_buf,"sudo route delete default gw %s dev %s\0",LTE_GATEWAY, LTE_DEV_NAME);
			   system(cmd_sys_buf);
			   printf("mptcp: delete hag lte default gateway :%s to interface %s\r\n",LTE_GATEWAY,LTE_DEV_NAME);
			}
		}

		memset(cmd_sys_buf,0x0,256);
		sprintf(cmd_sys_buf,"export DEFAULT_GATEWAY_IP=`ip route show | grep default | grep %s | grep %s |	egrep \"([0-9]{1,3}\.?){4}\" -o |head -1`\0", WIFI_DEV_NAME, WIFI_GATEWAY);
		system(cmd_sys_buf);
		bufPtr = getenv("DEFAULT_GATEWAY_IP");
		if(bufPtr != NULL && strcmp(bufPtr, "10.0.2.0") != 0){
			if(strcmp(bufPtr, WIFI_GATEWAY) == 0){
			   sprintf(cmd_sys_buf,"sudo route delete default gw %s dev %s\0",WIFI_GATEWAY, WIFI_DEV_NAME);
			   system(cmd_sys_buf);
			   
			   printf("mptcp: delete hag wifi default gateway :%s to interface %s\r\n",WIFI_GATEWAY,WIFI_DEV_NAME);
			}
		}
		#endif
	    /*system("/sbin/ip addr add dev tun0 local 10.0.2.0 peer 10.0.2.193");*/
        /*system("/sbin/ip route add 192.168.1.204/32 via 20.0.2.1");*/
        /*system("/sbin/ip route add 0.0.0.0/1 via 10.0.2.193");
        system("/sbin/ip route add 128.0.0.0/1 via 10.0.2.193");
        system("/sbin/ip route add 10.0.2.1/32 via 10.0.2.193");*/
		
	/*mccp auth*/
	/*set lte ip*/
	VpnNative_setLteIp(lteIp);
	/*set wifi ip, wifi ip get from lte first mptcp connect*/
	VpnNative_setWifiIp(wifiIp);

	ret = VpnNative_setAuthInfo(IMSI,IEMI, mac, auth_server_ip, port, 0);
	if(ret == 0)
	{
	    printf("VpnNative_setAuthInfo auth ok\r\n");
		/*open log*/
		if(trace_log > 0){
			VpnNative_openLog(trace_log);
			printf("mptcp trace log function is on\r\n");
		}

		times = 0;	
		do{
           if(ppca_s->mccp_auth == TRUE || times > 30)
		   	break;
		   else
		   	sleep(1);
		   times++;
		}while(ppca_s->mccp_auth == FALSE);


		if(ppca_s->mccp_auth == TRUE){
			struct in_addr lte_datalink_addr;
			printf("VpnNative_setAuthInfo get PCR success\r\n");
			lte_datalink_addr.s_addr = ppca_s->mccp_mpgw_ip;
			add_datalink_route(0,"HAG_LET_DATA_IP",inet_ntoa(lte_datalink_addr),LTE_GATEWAY,LTE_DEV_NAME);
		}
		else{
			printf("VpnNative_setAuthInfo get PCR timeout\r\n");
			close(fd);
			return 1;
		}

	    gMPTCP_config.tunnel_FD = fd;
		ret = tunif_init(&gMPTCP_config,NULL);
	    if( 0 != ret) {
	        //TODO: destroy MPTCP protocol stack
	        printf("mptcp tunif_init fail ret=%d\r\n",ret);
			close(fd);
	        goto fail_err;
	    }

		/*sleep*/
		times = 0;
		changemode(1); 
		gettimeofday(&tv1,NULL);
 		while(!kbhit()){
			gettimeofday(&tv2,NULL);
			printf("mptcp  already running %d min and press q or Q exit....\r\n",(int)((tv2.tv_sec - tv1.tv_sec)/60));
  
			scan_c = getchar();
			if(scan_c == 'q' || scan_c == 'Q')
				break; 
			else
			{
			   memset(cmd_sys_buf, 0x0, 256);
			   for(scan_c=0; scan_c<2; scan_c++){
			      tunnel_debug_counter(get_instance(scan_c),cmd_sys_buf,256);
				  if(strlen(cmd_sys_buf))
				  	printf("instance%d packet count list:\r\n %s",scan_c, cmd_sys_buf);
			   }
			}
				
		}
		changemode(0);

		/*exit*/
fail_err:		
	    stillRun = 0;
	    mccp_destory();
	    if (ppca_s->mccp_auth == TRUE)
	    {
	        tunif_end_loop();
	        //mutp_all_instance_destory();
	    }

		if(trace_log > 0){
			VpnNative_openLog(0);
		}
	}else
	{
	    printf("VpnNative_setAuthInfo fail ret=%d\r\n",ret);
	}

	if(pcap_log > 0){
		VpnNative_closeCrashLog();
	}
	printf("now exit ,wait 20s\r\n");
	sleep(20);
    return 0;
}
