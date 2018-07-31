//
// Created by admin on 2018/2/9.
//
#include <pthread.h>
#include "iperf_key.h"


static pthread_key_t iperf;

void globalIperfKeyInit(){
    pthread_key_create(&iperf,NULL);
}
void setGlobalIperfInThread(void *val){
    pthread_setspecific(iperf, val);
}
void* getGlobalIperfInThread(){
    return pthread_getspecific(iperf);
}
void destoryGlobalIperf(){
    pthread_key_delete(iperf);
}
