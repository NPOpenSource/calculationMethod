//
// Created by admin on 2018/2/9.
//

#ifndef MYAPPLICATION_IPERF_KEY_H
#define MYAPPLICATION_IPERF_KEY_H
#ifdef __cplusplus
extern "C" {
#endif
void setGlobalIperfInThread(void *val);
void* getGlobalIperfInThread();
void globalIperfKeyInit();
#ifdef __cplusplus
};
#endif
#endif //MYAPPLICATION_IPERF_KEY_H
