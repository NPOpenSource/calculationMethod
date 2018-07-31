//
// Created by wyjap on 2017/11/3.
//

#include <semaphore.h>


#include <lwip/arch/cc.h>
#include <lwip/igmp.h>
#include <lwip/ip4_nat.h>

#include "lwip/module.h"
#include "lwip/lwipopts.h"
#include "traffic_loadblance.h"
#include "vpn_tun_if.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#if !LINUX_PLATFORM
#include <android/log.h>
#include <stdatomic.h>
#endif
#include "lwip/debug.h"

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_VPN_TUN


struct traffic_map {
	void *instance;
};

static traffic_map  traffic_maps[MAX_INSTANCE_NUM];
u16_t loadblance_instance_num = 0;

void traffic_init(void){
	loadblance_instance_num = 0;
	memset((void *)&traffic_maps, 0x0, sizeof(traffic_maps));
}

int traffic_register_member(void *instance)
{
    if(loadblance_instance_num > (MAX_INSTANCE_NUM))
    {
        return 1;
    }
	traffic_maps[loadblance_instance_num].instance = instance;
	loadblance_instance_num++;
	return 0;
}

int traffic_unregister_member(void *instance){
	
    return 0;
}

void *traffic_do_src_direct(unsigned short src_port, unsigned short dest_port , unsigned int src_ip, unsigned int dest_ip)
{
    
	u16_t select_instance_id,i;
	void *instance;

   // /*����ע�������instance�����⣬�Ȳ�����ɾ�����������Ϊɾ�����ӣ��䲻����Ҫ����?/
#ifdef LWIP_MULTI_INSTANCE

#if LWIP_TWO_TCP_STACK_ZSQ
	select_instance_id = (src_port >> 1) % (MAX_INSIDE_INSTANCE_NUM);

#else
    /*odd number, even number by src port and dst port*/
    select_instance_id = (src_port >> 1) % MAX_INSTANCE_NUM;

/*
    select_instance_id = (u16_t)(src_port & (MAX_INSTANCE_NUM -1));
   */
   
//   	LWIP_DEBUGF(TRAFFIC_DEBUG, ("traffic_do_src_direct: select instance =%p source port =%d and instance id=%d loadblance_instance_num=%d\r\n",
//   	traffic_maps[select_instance_id].instance,src_port,select_instance_id,loadblance_instance_num));
#endif

#else
   select_instance_id = 0;	
#endif

#if 0
	for(i=0,isFound=0;i<traffic_maps[select_instance_id].used_num;i++)
	{
	   pTraffic =&(traffic_maps[select_instance_id].traffic[i]);
	   if(pTraffic->src_port == src_port && pTraffic->dest_port == dest_port \
	   	&& pTraffic->src_ip == src_ip && pTraffic->dest_ip == dest_ip)
	   	{
	   	   isFound = 1;
		   break;
	   	}
	}
	if(isFound == 0)
	{
	    i = traffic_maps[select_instance_id].used_num;
	    pTraffic =&(traffic_maps[select_instance_id].traffic[i]);
		pTraffic->src_port = src_port;
		pTraffic->dest_port = dest_port;
	   	pTraffic->src_ip = src_ip;
		pTraffic->dest_ip = dest_ip;
		/*�������ô�죬�����ٲ���,ĿǰԴ�˿�����Androidϵͳ���ƣ���������˳��ʹ�õģ�һ�㲻������������*/
		traffic_maps[select_instance_id].used_num++;
	}
#endif
    //instance = traffic_maps[select_instance_id].instance;

	return traffic_maps[select_instance_id].instance;
}

int traffic_remove_route(void *instance, u16_t src_port, u16_t dest_port, u32_t src_ip,u32_t dest_ip)
{

    return 1;
}


int traffic_add_route(void *instance, u16_t src_port, u16_t dest_port, u32_t src_ip,u32_t dest_ip)
{
    return 1;
}

unsigned int traffic_get_instance_num(void)
{
   return loadblance_instance_num;
}
