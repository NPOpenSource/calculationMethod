//
// Created by user on 2017/10/17.
//

#ifndef MYAPPLICATION_HEARTBEAT_H
#define MYAPPLICATION_HEARTBEAT_H


#include "../tools/common.h"
#include "../tunnel/tunnel.h"
#include <arpa/inet.h>
#include <sys/socket.h>


#ifdef __cplusplus
extern "C" {
#endif
#define ECHO_IND      (10)
#define ECHO_REQUEST  (11)
#define ECHO_RESPONSE  (12)

#define  HEARTBEAT_CHECK_TIME (60)
#define  HEARTBEAT_CHECK_TIMES (3)


typedef struct __heartbeat_header {

	mutp_header heartbeart;
	char        cbuffer[52];
	
} heartbeat_header;

void heartbeat_init
	(
	int *wifi_fd, 
	int *lte_fd, 
	struct sockaddr_in *wifi_addr, 
	struct sockaddr_in *lte_addr,
	int *stillRun,
	int *wifi_receive,
	int *lte_receive
	);

void heartbeat_set_timeval( int time);
void heartbeat_set_timesval( int times);
void heartbeat_init_mutp_data(UINT32 tunnel_id);
void heartbeat_deinit(void);
#ifdef __cplusplus
}
#endif

#endif //MYAPPLICATION_HEARTBEAT_H
