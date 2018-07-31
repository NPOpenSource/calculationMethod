//
// Created by user on 4/12/17. just for test
//

#ifndef MYAPPLICATION_2_TEST_INOUT_H
#define MYAPPLICATION_2_TEST_INOUT_H

//#include <lwip/udp.h>
#include "lwip/tcp.h"

void test_tcp();

void test_udp();

err_t test_for_tcp_output(struct netif *netif, struct pbuf *p,
                          const ip4_addr_t *ipaddr);

err_t test_for_tcp_intput(struct pbuf *p, struct netif *netif);

void test_timer();

void test_tcp_real_machine();

void socket_examples_init(void);

#endif //MYAPPLICATION_2_TEST_INOUT_H
