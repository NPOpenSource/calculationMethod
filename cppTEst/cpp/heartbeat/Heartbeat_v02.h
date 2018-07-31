//
// Created by huawei on 18-4-3.
//

#ifndef MPTCP_HEARTBEAT_V02_H
#define MPTCP_HEARTBEAT_V02_H

#include <semaphore.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef enum _BT{
    BT_MIN = 1,
    BT_DEF = 3,
    BT_MAX = 10,
}BT;
typedef enum _BTI{
    BTI_MIN = 1,
    BTI_DEF = 1,
    BTI_MAX = 300,
}BTI;

typedef enum _HB_MSG_TYPE{
    Echo_Request = 11,
    Echo_Response = 12,
}HB_MSG_TYPE;

typedef enum HB_SEND_TYPE{
    HB_TH_LTE,
    HB_TH_WIFI,
    HB_TH_BOTH,
    HB_TH_CLOSE,
}HB_SEND_TYPE;

struct pubf;
/* heartbeat init*/
void HeartBeatInit(void *instance);
/* heartbeat init time */
void HeartBeatInitDefaultTime();
/* heartbeat destory */
void HeartBeatDestory();
void setLteHeartBeat(int beat);
void setWifiHeartBeat(int beat);
void setHeartBeatStrategyByNetworkChange(int wifi,int lte);
HB_SEND_TYPE getHeartbeatStrategy();
/* send through lte or wifi strategy set*/
void setHeartbeatStrategy(HB_SEND_TYPE heartbeatStrategy);
/* if recv from server response,clear flag*/
void setStartHeartBeat(int startHeartBeat);
void Exit();
void setBeatTimes(int beatTimes);
void setBeatTimeInterval(int beatTimeInterval);
int getBeatTimes() ;
int getBeatTimeInterval() ;
/* send request or response */
void fillHeartBeatHeaderType(HB_MSG_TYPE type);
/* send messsag through lte or wifi */
void sendHeartBeatPacket(HB_SEND_TYPE type);
/* support for app java level control the heartbeat*/
void switchHeartOpenClose(int open);

/* heart beat Thread run, exit when click close buttom */
void* heartBeatThead(void * data);
void startHeartBeatThread();
void handleHeartBeatFail(int lteState,int wifiState);
int heartBeatCheckTimeout(long start,long end);
#ifdef __cplusplus
};
#endif

#endif //MPTCP_HEARTBEAT_V02_H
