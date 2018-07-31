//
// Created by ts on 17-5-3.
//

#ifndef MYAPPLICATION_TEST_TRANS_TO_MUTP_H
#define MYAPPLICATION_TEST_TRANS_TO_MUTP_H

#include <sys/socket.h>
#include <arpa/inet.h>

int trans_mutp_init();
void trans_mutp_destory();
void trans_senddata(char *buf,int len,struct sockaddr_in* addr,int socklen);
void* trans_recv_data(void* data);

#endif //MYAPPLICATION_TEST_TRANS_TO_MUTP_H
