//
// Created by wyjap on 2017/11/3.
//

#ifndef MYAPPLICATION_TRAFFIC_LOADBLANCE_H
#define MYAPPLICATION_TRAFFIC_LOADBLANCE_H
#ifdef __cplusplus
extern "C" {
#endif

void traffic_init(void);
int traffic_register_member(void *instance);
int traffic_unregister_member(void *instance);
unsigned int traffic_get_instance_num(void);
void *traffic_do_src_direct(unsigned short src_port, unsigned short dest_port, unsigned int src_ip, unsigned int dest_ip);

#ifdef __cplusplus
}
#endif
#endif //MYAPPLICATION_TRAFFIC_LOADBLANCE_H
