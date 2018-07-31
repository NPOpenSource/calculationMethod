//
// Created by wyjap on 2017/10/25.
//
#include <pthread.h>
#include "lwip/module.h"
#include "lwip/netif.h"
#include "lwip/ip4_nat.h"
#include <string.h>


static pthread_key_t keyInstance;
//static lwip_instance *gstInstance[MAX_INSTANCE_NUM*2] = {0};
lwip_instance *gstInstance[MAX_INSTANCE_NUM*2] = {0};
static unsigned int instance_num = 0;


/*从当前位置获取本实例里其他相关的context*/
struct module_conext *get_module_context(enum module_conext_type curType, struct module_conext *pConext, enum module_conext_type destType)
{
   if( pConext != NULL)
   {
       return  (pConext - (curType - destType));
   }
   else
   {
       return NULL;
   }
}


void register_lwip_instance(struct lwip_instance *pstInstance){
   gstInstance[instance_num++] = pstInstance;
}

struct lwip_instance *get_instance(unsigned int i)
{
   if(i>instance_num)
   {
   	  return NULL;
   }
   else
   {
   	return gstInstance[i];
   }
}

int get_instance_logic_id(void *instance)
{
    int i;
	
    for(i=0; i<instance_num;i++)
    {
		if((void *)gstInstance[i] == instance)
			return i;
    }
	return -1;
}

void set_lwip_instance_internal_context(struct lwip_instance *pstInstance, void *pContext)
{
}

void get_lwip_instance_internal_context(struct lwip_instance *pstInstance, void **pContext)
{
}

struct lwip_instance *get_instance_context(enum module_conext_type curType, struct module_conext *pConext)
{
     return (struct lwip_instance *)((u8_t *)pConext - curType*sizeof(struct module_conext));
}

void global_set_thread_instance(void *pVal){
	pthread_setspecific(keyInstance, pVal);
}

void *global_get_thread_instance(void){
	return pthread_getspecific(keyInstance);
}

void global_init_once(void){
    pthread_key_create(&keyInstance, NULL);
	instance_num = 0;
}

void global_free_param(void)
{
    /*pthread_key_delete(keyInstance);*/
	instance_num = 0;
}
