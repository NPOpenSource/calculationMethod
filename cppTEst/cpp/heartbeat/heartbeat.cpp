//
// Created by user on 2017/10/17.
//

#include <pthread.h>
#include <lwip/sys.h>
#include "heartbeat.h"
//#include "../tunnel/tunnel.h"
#include <string.h>


static int g_sHeartBeatCheckTime = HEARTBEAT_CHECK_TIME;
static int g_sHeartBeatCheckTimes =HEARTBEAT_CHECK_TIMES;
#if !WIFI_LTE_SWITCH
static heartbeat_header stHeartBeatHeader ={0};
#else
heartbeat_header stHeartBeatHeader ={0};
#endif

static int g_sHeartBeatWIFICheck = 0;// 1:check success,2:check failed
static int g_sHeartBeatLTECheck  = 0;// 1:check success,2:check failed

static int g_sHeartBeatInitFlag  = 0;


static   pthread_t g_sHeartBeatThreadId = 0;


typedef enum __HeartBeatCheckType {
    HEARTBEAT_WIFI_NORMAL_CHECK,
    HEARTBEAT_WIFI_BROKEN_CHECK,
    HEARTBEAT_LTE_NORMAL_CHECK,
    HEARTBEAT_LTE_BROKEN_CHECK
} HeartBeatCheckType;

struct heart_beat {
	int *wifi_fd;
	int *lte_fd;
	struct sockaddr_in *wifi_addr;
	struct sockaddr_in *lte_addr; 
	int *wifi_receive;
	int *lte_receive;
	int *stillRun;
};

static struct heart_beat *pHeartContext = NULL; 


 void heartbeat_set_timeval( int time)
 {
     if( time >= 1 && time <= 300)
     {
         g_sHeartBeatCheckTime = time;
     }
     else
     {
         g_sHeartBeatCheckTime = HEARTBEAT_CHECK_TIME;
     }
 }




void heartbeat_set_timesval( int times)
{
    if( times >= 1 && times <= 10)
    {
        g_sHeartBeatCheckTimes = times;
    }
    else
    {
        g_sHeartBeatCheckTimes = HEARTBEAT_CHECK_TIMES;
    }
}


void heartbeat_init_mutp_data(UINT32 tunnel_id)
{
    heartbeat_header *pHeader = &stHeartBeatHeader;

    ENTER_FUNC;
    
    LogI("%s:%d enter g_sMutpTunnelId:0x%x,size:%u,\n\r",__FUNCTION__,__LINE__,
        tunnel_id,sizeof(stHeartBeatHeader));
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




void heartbeat_check_bytype(TRType etype,struct heart_beat *pInTunnelContext)
{
     int count=0;
     int ret = 0;
     ENTER_FUNC;

	 if( NULL == pInTunnelContext)
	 {
		return ;
	 }
	 
    if(  LTE == etype )
    {
       *(pInTunnelContext->lte_receive)=2;
       count = 0;
       ret = sendto(*(pInTunnelContext->lte_fd), &stHeartBeatHeader, sizeof(stHeartBeatHeader), 0, (struct sockaddr *) pInTunnelContext->lte_addr, sizeof(struct sockaddr_in));
       if (ret == -1) {
         LogE("heartbeat lte current error:%s", strerror(errno));
        }

	     LogI("current send server ip :%s", inet_ntoa(pInTunnelContext->lte_addr->sin_addr));
         LogI("server port:%d", ntohs(pInTunnelContext->lte_addr->sin_port));

        while(1)
        {
            sys_msleep(100);
            count++;
            if( (count >20) || ( *(pInTunnelContext->lte_receive) ==1))
            {
                break;
            }
        }          
          // LogI("%s:%d enter count:%d,ltecheck:%d,ltecount:%d\n\r",__FUNCTION__,__LINE__,count,g_sHeartBeatLTECheck,ltecount);                    
    }
    else if( WIFI == etype)
    {
       
       *(pInTunnelContext->wifi_receive) =2;
        count = 0;
        ret = sendto(*(pInTunnelContext->wifi_fd), &stHeartBeatHeader, sizeof(stHeartBeatHeader), 0, (struct sockaddr *) pInTunnelContext->wifi_addr, sizeof(struct sockaddr_in));
        if (ret == -1) {
         LogE("heartbeat wifi current error:%s", strerror(errno));
        }

	 	LogI("current send server ip :%s", inet_ntoa(pInTunnelContext->lte_addr->sin_addr));
    	LogI("server port:%d", ntohs(pInTunnelContext->lte_addr->sin_port));
        while(1)
        {
            sys_msleep(100);
            count++;
            if( (count >20) || ( *(pInTunnelContext->wifi_receive) ==1))
            {
                break;
            }
        }
     
         //  LogI("%s:%d enter count:%d,wificheck:%d,wificount:%d\n\r",__FUNCTION__,__LINE__,count,g_sHeartBeatWIFICheck,wificount);     
    }

    EXIT_FUNC;
}


extern int isSetWifiAddr;
extern int isSetLteAddr;

static void * heartbeat_process(void *args)
{    
	 int  wificount = 0,ltecount = 0;
	 HeartBeatCheckType eWifiCheckType = HEARTBEAT_WIFI_NORMAL_CHECK;
	 HeartBeatCheckType eLteCheckType = HEARTBEAT_LTE_NORMAL_CHECK;
     while( *(pHeartContext->stillRun) )
     {

		LogI("%s:%d g_sHeartBeatCheckTime:%d\n\r",__FUNCTION__,__LINE__,g_sHeartBeatCheckTime);
        sys_msleep(g_sHeartBeatCheckTime*1000);
      
	    if(eLteCheckType == HEARTBEAT_LTE_NORMAL_CHECK)
	   	{

			if( isSetLteAddr)
			{

			
			  LogE("%s:%d lte_addr:%d\n\r",__FUNCTION__,__LINE__,pHeartContext->lte_addr->sin_addr.s_addr);
			  if(pHeartContext->lte_addr->sin_addr.s_addr > 0)
			  	{
					heartbeat_check_bytype(LTE,pHeartContext); 
			  	}

			   if(*(pHeartContext->lte_receive) == 1)
			   {
				   ltecount = 0;	
			   }
			   else if(*(pHeartContext->lte_receive) == 2)
			   {
                   ltecount++;
				   if( ltecount >= g_sHeartBeatCheckTimes)
				   {
                       eLteCheckType = HEARTBEAT_LTE_BROKEN_CHECK;					  
				   }
			   }
			}
	    }
		
	    if(eWifiCheckType == HEARTBEAT_WIFI_NORMAL_CHECK)
	    {
			if(isSetWifiAddr) {				
				LogE("%s:%d wifiaddr:%d\n\r",__FUNCTION__,__LINE__,pHeartContext->wifi_addr->sin_addr.s_addr);
                if (pHeartContext->wifi_addr->sin_addr.s_addr > 0) {
                    heartbeat_check_bytype(WIFI, pHeartContext);
                }

                if (*(pHeartContext->wifi_receive) == 1)
                {
                    wificount = 0;
                }
                else if (*(pHeartContext->wifi_receive) == 2)
                {
                    wificount++;
                    if (wificount >= g_sHeartBeatCheckTimes)
                    {
                        eWifiCheckType = HEARTBEAT_WIFI_BROKEN_CHECK;
                    }
                }
            }
	    } 

		LogE("%s:%d enter wificheck:%d,ltecheck:%d,wificount:%d,ltecount:%d,isSetLteAddr:%d,isSetWifiAddr:%d\n\r",__FUNCTION__,__LINE__,*pHeartContext->wifi_receive,*pHeartContext->lte_receive,wificount,ltecount,isSetLteAddr,isSetWifiAddr);

         if( isSetLteAddr && isSetWifiAddr) {
             if ((eLteCheckType == HEARTBEAT_LTE_BROKEN_CHECK) &&
                 (eWifiCheckType == HEARTBEAT_WIFI_BROKEN_CHECK)) {
                 LogE("%s:%d enter hag is error to java\n\r", __FUNCTION__, __LINE__);
                 HeartBeatIsBroken_ThoughtJava(0);
                 return NULL;
             }
         }else if( isSetLteAddr && !isSetWifiAddr) {
             if (eLteCheckType == HEARTBEAT_LTE_BROKEN_CHECK) {
                 LogE("%s:%d enter hag is error to java only lte\n\r", __FUNCTION__, __LINE__);
                 HeartBeatIsBroken_ThoughtJava(0);
                 return NULL;
             }
         }else if( !isSetLteAddr && isSetWifiAddr) {
             if (eWifiCheckType == HEARTBEAT_WIFI_BROKEN_CHECK) {
                 LogE("%s:%d enter hag is error to java only wifi\n\r", __FUNCTION__, __LINE__);
                 HeartBeatIsBroken_ThoughtJava(0);
                 return NULL;
             }
         }  
     }
     return NULL;
}

void HeartBeat_ThreadExitSignal(int nsigno)
{

    LogI("%s:%d enter nsigno:%d,SIGRTMIN:%d\n\r",__FUNCTION__,__LINE__,nsigno,SIGRTMIN);
    if( (SIGRTMIN+2) == nsigno )
    {
       pthread_exit(0);
    }
    
}
 
void HeartBeat_RegistrationExitSignal()
{
    LogI("%s:%d enter\n\r",__FUNCTION__,__LINE__);
    struct sigaction actions;
    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = HeartBeat_ThreadExitSignal;
    sigaction((SIGRTMIN+2), &actions, NULL);
    LogI("%s:%d exit\n\r",__FUNCTION__,__LINE__);

}
 
void HeartBeat_KillThread(pthread_t pid)
{
    int ret =0;

    ret = pthread_kill(pid, 0);
    LogI("%s:%d enter pid:%ld ret:%d\n\r",__FUNCTION__,__LINE__,pid,ret);
    if (ret == 0 )
    {
        pthread_kill(pid, (SIGRTMIN+2));
        pthread_join(pid, NULL);
    }
    LogI("%s:%d exit\n\r",__FUNCTION__,__LINE__);

}

void heartbeat_init
	(
	int *wifi_fd, 
	int *lte_fd, 
	struct sockaddr_in *wifi_addr, 
	struct sockaddr_in *lte_addr,
	int *stillRun,
	int *wifi_receive,
	int *lte_receive
	)
{
    int ret = 0;
	
    
    ENTER_FUNC;
 
    if( g_sHeartBeatInitFlag == 1 )
    {
        return ;
    }
	
    
	pHeartContext =(struct heart_beat *)malloc(sizeof(struct heart_beat)); 

	if( NULL == pHeartContext)
	{
		return;
	}	
    memset(pHeartContext,0x00,sizeof(struct heart_beat));

	pHeartContext->lte_addr  = lte_addr;
	pHeartContext->lte_fd 	 = lte_fd;
	pHeartContext->wifi_addr = wifi_addr;
	pHeartContext->wifi_fd 	 = wifi_fd;
	pHeartContext->stillRun  = stillRun;
	pHeartContext->wifi_receive = wifi_receive;
	pHeartContext->lte_receive =  lte_receive;

   HeartBeat_RegistrationExitSignal();
   //sys_thread_new(instance,&attr,"heartbeat_process",(lwip_thread_fn)heartbeat_process,instance,1024,0);
   
   ret = pthread_create(&g_sHeartBeatThreadId, NULL, heartbeat_process, (void *)pHeartContext);
   if( ret != 0)
   {
        LogE("pthread_create is error\n\r");
   }
   
   g_sHeartBeatInitFlag = 1;  
   EXIT_FUNC;
}

void heartbeat_deinit( void )
{

    ENTER_FUNC;
    if( g_sHeartBeatInitFlag == 0)
    {
        return ;
    }

	if( pHeartContext != NULL)
	{
		FREE(pHeartContext);
		pHeartContext = NULL;		
	}

    g_sHeartBeatInitFlag = 0;

	if( 0 != g_sHeartBeatThreadId)
	{
	    HeartBeat_KillThread(g_sHeartBeatThreadId);
	    g_sHeartBeatThreadId =0;
	}
	
    EXIT_FUNC;

}
