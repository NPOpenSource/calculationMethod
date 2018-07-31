//
// Created by huawei on 18-4-3.
//

#include <sys/socket.h>
#include "Heartbeat_v02.h"
#include "lwip/pbuf.h"
#include "../vpn_tun/traffic_loadblance.h"
#include "../tunnel/tunnel.h"
#include <netinet/in.h>
#define HEART_BEAT_PACKET_LEN 64
//#define LogG(...) __android_log_print(ANDROID_LOG_DEBUG,"Vpn",__VA_ARGS__)
#define LogG(...)
#define HEART_BEAT_DEBUG   0
static int beatTimes = 0 ;/* beat times */
static int beatTimeInterval = 0;/* beat times interval */
static struct pbuf *heartBeatPacket;/* heart beat packet  */
static int lte_heartBeat;
static int wifi_heartBeat;
/* current time is need start*/
static int isExit;   /*heart beat exit when app close */
static sem_t startSem;
static HB_SEND_TYPE heartbeatStrategy;
static int heartBeat_switch = 0;

void switchHeartOpenClose(int open){
    if(open)
        heartBeat_switch = 1;
    else
        heartBeat_switch = 0;
}

/* fill heartbeat Request or response Header*/
static void fillHeartBeatRequestHeader();
static void fillHeartBeatResponseHeader();
int getBeatTimes()  {
    return beatTimes;
}

int getBeatTimeInterval()  {
    return beatTimeInterval;
}

void setBeatTimes(int bs) {
    if(beatTimes >= BT_MIN && beatTimes <= BT_MAX)
        beatTimes = bs;
    else
        beatTimes = BT_DEF;
    LogI("%s:%d beattimes:%d",__func__, __LINE__, beatTimes);
}

void setBeatTimeInterval(int bti) {
    if(beatTimeInterval >= BTI_MIN && beatTimeInterval <= BTI_MAX)
        beatTimeInterval = bti;
    else
        beatTimeInterval = BTI_DEF;
    LogI("%s:%d beattimeInterval:%ds",__func__, __LINE__, beatTimeInterval);
}
static void init(void *instance);
void HeartBeatInit(void *instance) {
    init(instance);
    LogG("%s:%d instance:%p",__func__, __LINE__, instance );
}
static void destory();
void  HeartBeatDestory() {
    destory();
    LogI("%s:%d",__func__,__LINE__);
}

static void init(void *pInstance) {
    struct lwip_instance *instance = (struct lwip_instance*)pInstance;
    heartBeatPacket = pbuf_alloc(instance,PBUF_RAW,HEART_BEAT_PACKET_LEN,PBUF_RAM);
    sem_init(&startSem,0,0);
    isExit = 0;//set flag before start thread
    setWifiHeartBeat(0);
    setLteHeartBeat(0);
    switchHeartOpenClose(0);
    startHeartBeatThread();//start the heartbeat thread
}

 static void destory() {
   LogI("%s:%d",__func__,__LINE__);
   Exit();/*exit the thread*/
   if(heartBeatPacket != NULL) {
       pbuf_free(heartBeatPacket);
       heartBeatPacket = NULL;
   }
   sem_destroy(&startSem);
}

void fillHeartBeatRequestHeader() {
    LogI("%s:%d",__func__,__LINE__);
    if(heartBeatPacket == NULL) return;
    fillMutpHeaderNormal(heartBeatPacket,Echo_Request); /* fix in Requset*/
}

void fillHeartBeatResponseHeader() {
    LogI("%s:%d",__func__,__LINE__);
    fillMutpHeaderNormal(heartBeatPacket,Echo_Response); /* fix in Requset*/
}

void sendHeartBeatPacket(HB_SEND_TYPE type) {
    struct lwip_instance *instance = (struct lwip_instance*)get_instance(0);
    int lte  = getTunnelFd(instance,1);
    int wifi = getTunnelFd(instance,0);
    struct sockaddr_in *destLte = getTunnelDestAddr(instance,1);
    struct sockaddr_in *destWifi = getTunnelDestAddr(instance,0);
    LogI("%s:%d send type:%d",__func__,__LINE__,type);
    if(heartBeatPacket == NULL) return;
    switch(type){
        case HB_TH_LTE:
            if(lte_heartBeat){
                LogD("send LTE heartbeat");
                sendto(lte,heartBeatPacket->payload,heartBeatPacket->len,0,(struct sockaddr*)destLte,sizeof(struct sockaddr_in));
            }
            break;
        case HB_TH_WIFI:
            if(wifi_heartBeat){
                LogD("send WIFI heartbeat");
                sendto(wifi,heartBeatPacket->payload,heartBeatPacket->len,0,(struct sockaddr*)destWifi,sizeof(struct sockaddr_in));
            }
            break;
        case HB_TH_BOTH:
            if(lte_heartBeat){
                LogD("send LTE heartbeat");
                sendto(lte,heartBeatPacket->payload,heartBeatPacket->len,0,(struct sockaddr*)destLte,sizeof(struct sockaddr_in));
            }
            if(wifi_heartBeat) {
                LogD("send WIFI heartbeat");
                sendto(wifi, heartBeatPacket->payload, heartBeatPacket->len, 0,
                       (struct sockaddr *) destWifi, sizeof(struct sockaddr_in));
            }
            break;
        default:
            break;
    }
}

void fillHeartBeatHeaderType(HB_MSG_TYPE type) {
    LogI("%s:%d Heartbeat message type:%d",__func__,__LINE__, type);
    if(heartBeatPacket == NULL){
        return ;
    }
    if(type == Echo_Request){
        fillHeartBeatRequestHeader();
    }
    else if(type == Echo_Response){
        fillHeartBeatResponseHeader();
    }
}

void *heartBeatThead(void *data) {
    int times = 0;
    int sleepcount = 0;
    LogE("%s start",__func__);
    while(!isExit){
        LogG("%s:%d",__func__,__LINE__);
        sem_wait(&startSem);
        LogG("%s:%d lte_heartBeat:%d wifi_heartBeat:%d tiems:%d",
            __func__,__LINE__,lte_heartBeat,wifi_heartBeat,times);
        sleepcount = 0;
        while(heartBeat_switch &&(lte_heartBeat || wifi_heartBeat) && times++ < beatTimes){
            fillHeartBeatRequestHeader();
            sendHeartBeatPacket(heartbeatStrategy);
            LogG("%s:%d waitfor a heart beat time interval:%d times:%d",__func__,__LINE__,beatTimeInterval,times);
            while ((sleepcount++ < beatTimeInterval) && (lte_heartBeat || wifi_heartBeat)) {
                sleep(1);
                LogG("current count:%d beatTimeInterval:%d",sleepcount,beatTimeInterval);
            }
            sleepcount = 0;
        }
        LogG("times:%d beatTimes:%d lte:%d wifi:%d",times, beatTimes, lte_heartBeat,wifi_heartBeat);
        if(times >= beatTimes){
            if(lte_heartBeat || wifi_heartBeat) //01 or 10 or 11 need a back call
                handleHeartBeatFail(!lte_heartBeat,!wifi_heartBeat);
            if(!lte_heartBeat && !wifi_heartBeat){ // if only one is error,don't exit the heartbeat
                setLteHeartBeat(0);
                setWifiHeartBeat(0);
                break;
            }
            /*clear flag for tigger the next heartbeat when only one way fails*/
            setLteHeartBeat(0);
            setWifiHeartBeat(0);
        }
        times = 0;
    }
    isExit = 1;
    sem_post(&startSem);/*send msg to call exit thread*/
    return NULL;
}

void Exit() {
    lte_heartBeat = 0;
    wifi_heartBeat = 0;
    LogI("post start Sem");
    if(isExit != 1) {
        isExit = 1;
        sem_post(&startSem);/*post for make the thread exit*/
        LogI("wait start Sem");
        sem_wait(&startSem);/*wait for the thread exit*/
        LogI("exit");
    }
}

HB_SEND_TYPE getHeartbeatStrategy()  {
    return heartbeatStrategy;
}

void setHeartbeatStrategy(HB_SEND_TYPE hs) {
    heartbeatStrategy = hs;
}

void handleHeartBeatFail(int lteState,int wifiState) {
    HB_SEND_TYPE  type = getHeartbeatStrategy();
    LogG("is setLteAddr:%d isSetWifiAddr:%d wifiState:%d lteState:%d",
         isSetLteAddr,isSetWifiAddr,wifiState,lteState);
    switch(type){
        case HB_TH_LTE:
            if(!lteState && isSetLteAddr){
                HeartBeatErrorStateToJava(lteState,wifiState);
            }
            break;
        case HB_TH_WIFI:
            if(!wifiState && isSetWifiAddr){
                HeartBeatErrorStateToJava(lteState,wifiState);
            }
            break;
        case HB_TH_BOTH:
            if((!wifiState && isSetWifiAddr)||(isSetLteAddr && !lteState)){
                HeartBeatErrorStateToJava(lteState,wifiState);
            }
            break;
        case HB_TH_CLOSE:
            HeartBeatErrorStateToJava(lteState,wifiState);
            break;
    }
}

void startHeartBeatThread() {
    pthread_t pt;
    isExit = 0;
    lte_heartBeat = 0;
    wifi_heartBeat = 0;
    pthread_create(&pt,NULL,heartBeatThead,NULL);
}

void setLteHeartBeat(int beat) {
#if HEART_BEAT_DEBUG
    if(lte_heartBeat && !beat)
        __android_log_print(ANDROID_LOG_DEBUG,"Vpn","clear Lte HeartBeat flag");
    if(beat == 1)
        __android_log_print(ANDROID_LOG_DEBUG,"Vpn","set Lte HeartBeat Flag");
#endif
    lte_heartBeat = beat;
}

int heartBeatCheckTimeout(long start,long end){

    static long BIV = beatTimeInterval*1000;

    if(lte_heartBeat || wifi_heartBeat){
        return 0;
    }
#if HEART_BEAT_DEBUG
    __android_log_print(ANDROID_LOG_DEBUG,"Vpn","heartbeat start:%ld end:%ld BIV:%ld distance:%ld",end,start, BIV, end- start);
#endif
    if(end - start > BIV){
#if HEART_BEAT_DEBUG
        __android_log_print(ANDROID_LOG_DEBUG,"Vpn","heartbeat wifi:%d lte:%d end-start:%ld BIV:%ld",wifi_heartBeat,lte_heartBeat,end-start, BIV);
        __android_log_print(ANDROID_LOG_DEBUG,"Vpn","BIV enter");
#endif
        return 1;
    }
    return 0;
}

void setWifiHeartBeat(int beat) {
#if HEART_BEAT_DEBUG
    if(wifi_heartBeat && !beat)
        __android_log_print(ANDROID_LOG_DEBUG,"Vpn","clear WIFI HeartBeat flag");
    if(beat == 1)
        __android_log_print(ANDROID_LOG_DEBUG,"Vpn","set WIFI HeartBeat Flag");
#endif
    wifi_heartBeat = beat;
}

void setStartHeartBeat(int startHeartBeat) {
      if(startHeartBeat){
         setLteHeartBeat(isSetLteAddr);
         setWifiHeartBeat(isSetWifiAddr);
      }else{
         setLteHeartBeat(0);
         setWifiHeartBeat(0);
      }
      LogD("heart beat start");
      LogG("%s:%d",__func__,__LINE__);
      sem_post(&startSem);
}

/*set defalut times and time interval*/
void HeartBeatInitDefaultTime() {
    if(!beatTimes) setBeatTimes(0);
    if(!beatTimeInterval) setBeatTimeInterval(0);
}

void setHeartBeatStrategyByNetworkChange(int wifi, int lte) {
    if(wifi && lte){
        setHeartbeatStrategy(HB_TH_BOTH);
    }else if(!lte && wifi){
        setHeartbeatStrategy(HB_TH_LTE);
    }else if(lte && !wifi){
        setHeartbeatStrategy(HB_TH_WIFI);
    }else {
        setHeartbeatStrategy(HB_TH_CLOSE);
    }
}
