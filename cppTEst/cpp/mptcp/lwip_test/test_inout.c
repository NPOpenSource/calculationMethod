//
// Created by user on 4/12/17. just for test
//

#include <lwip/inet.h>
#include <lwip/sockets.h>
#include <lwip/tcpip.h>
#include <lwip/api.h>
#include <lwip/prot/tcp.h>
#include "test_inout.h"
#include "../../vpn_tun/vpn_tun_if.h"

/*********************************** udp local test start *************************************/

static int
test_sockets_alloc_socket_nonblocking(int type)
{
    int s = lwip_socket(AF_INET, type, IPPROTO_UDP);
    if (s >= 0) {
        int ret = lwip_fcntl(s, F_SETFL, O_NONBLOCK);
    }
    return s;
}

static void test_sockets_init_loopback_addr( struct sockaddr_storage *addr_st, socklen_t *sz)
{
    memset(addr_st, 0, sizeof(*addr_st));
    struct sockaddr_in *addr = (struct sockaddr_in*)addr_st;
    addr->sin_family = AF_INET;
    addr->sin_port = 0; /* use ephemeral port */
    addr->sin_addr.s_addr = PP_HTONL(INADDR_LOOPBACK);
    *sz = sizeof(*addr);
}

static void test_sockets_msgapi_udp_send_recv_loop(int s, struct msghdr *smsg, struct msghdr *rmsg)
{
    int i, ret;

    /* send/receive our datagram of IO vectors 10 times */
    for (i = 0; i < 10; i++) {
        ret = lwip_sendmsg(s, smsg, 0);

        while (tcpip_thread_poll_one());

        /* receive the datagram split across 4 buffers */
        ret = lwip_recvmsg(s, rmsg, 0);

        TSLOG("TS TEST", "%d", *((u8_t*)rmsg->msg_iov->iov_base));
        /* clear rcv_buf to ensure no data is being skipped */
        *((u8_t*)rmsg->msg_iov[0].iov_base) = 0x00;
        *((u8_t*)rmsg->msg_iov[1].iov_base) = 0x00;
        *((u8_t*)rmsg->msg_iov[2].iov_base) = 0x00;
        *((u8_t*)rmsg->msg_iov[3].iov_base) = 0x00;
    }
}

void test_udp()
{
    int s, i, ret;
    struct sockaddr_storage addr_storage;
    socklen_t addr_size;
    struct iovec riovs[4];
    struct msghdr rmsg;
    u8_t rcv_buf[4];
    struct iovec siovs[4];
    struct msghdr smsg;
    u8_t snd_buf[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    /* initialize IO vectors with data */
    for (i = 0; i < 4; i++) {
        siovs[i].iov_base = &snd_buf[i];
        siovs[i].iov_len = sizeof(u8_t);
        riovs[i].iov_base = &rcv_buf[i];
        riovs[i].iov_len = sizeof(u8_t);
    }

    test_sockets_init_loopback_addr(&addr_storage, &addr_size);

    s = test_sockets_alloc_socket_nonblocking(SOCK_DGRAM);
    ret = lwip_bind(s, (struct sockaddr*)&addr_storage, addr_size);
    ret = lwip_getsockname(s, (struct sockaddr*)&addr_storage, &addr_size);

    /* send and receive the datagram in 4 pieces */
    memset(&smsg, 0, sizeof(smsg));
    smsg.msg_iov = siovs;
    smsg.msg_iovlen = 4;
    memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_iov = riovs;
    rmsg.msg_iovlen = 4;

    /* perform a sendmsg with remote host (self) */
    smsg.msg_name = &addr_storage;
    smsg.msg_namelen = addr_size;

    test_sockets_msgapi_udp_send_recv_loop(s, &smsg, &rmsg);
}

/*********************************** udp local test end ****************************************/

/*********************************** tcp local netif start *************************************/

//struct sys_sem* sem;

struct netif* g_server_netif;
struct netif* g_client_netif;

struct netif* temp_netif;
//struct pbuf* temp_pbuf;
struct sys_sem_t* sem;
int tcp_server_fd;

void print_header(struct pbuf* p)
{
#define TAG "TS TEST"

    struct ip_hdr* iphdr = LWIP_ALIGNMENT_CAST(struct ip_hdr*,p->payload);
    struct tcp_hdr *tcphdr;

    __android_log_print(ANDROID_LOG_ERROR,TAG, "IP Version/header length:%d", iphdr->_v_hl);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "Header Length:%d", iphdr->_len);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "Protocol:%d",iphdr->_proto);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "src:%d",iphdr->src.addr);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "dst:%d",iphdr->dest.addr);

    iphdr++;

    tcphdr = (struct tcp_hdr *)iphdr;

    __android_log_print(ANDROID_LOG_ERROR,TAG, "tcp src:%d", tcphdr->src);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "tcphdr dest:%d", tcphdr->dest);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "tcphdr ackno:%d",tcphdr->ackno);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "tcphdr seqno:%d",tcphdr->seqno);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "tcphdr wnd:%d",tcphdr->wnd);
    __android_log_print(ANDROID_LOG_ERROR,TAG, "tcphdr chksum:%d",tcphdr->chksum);

}

char buf[1024];

void server_thread(void* arg)
{
    //TODO: bind -- listen -- accept
    struct sockaddr_in server_addr;
    struct sockaddr accpet_addr;
    socklen_t accept_len = sizeof(accpet_addr);
    int recv_len = -1;

    int tcp_server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    server_addr.sin_addr.s_addr = inet_addr("192.168.43.16");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = PP_HTONS(55557);

    if( bind(tcp_server_sock, (struct sockaddr*)(&server_addr),
             sizeof(struct sockaddr)) < 0)
    {
        TSLOG("TS TEST", "server bind fail", NULL);
        return ;
    }

    if( listen(tcp_server_sock, 5) < 0)
    {
        TSLOG("TS TEST", "server listen fail", NULL);
        return ;
    }

    TSLOG("TS TEST", "server thread", NULL);

    tcp_server_fd = accept(tcp_server_sock, &accpet_addr, &accept_len);

    TSLOG("TS TEST", "server accept sucess", NULL);

    if ((recv_len = recv(tcp_server_fd, buf, 1024, 0)) > 0)
        send(tcp_server_fd, buf, 1024, 0);
    else if ( recv_len == 0){
        lwip_close(tcp_server_sock);
        lwip_close(tcp_server_fd);
    } else {
        lwip_close(tcp_server_sock);
        lwip_close(tcp_server_fd);
    }

//    lwip_close(tcp_server_sock);
//    lwip_close(tcp_server_fd);

    return ;
}

void client_thread(void* arg)
{

    //TODO: connect -- send
    struct netif* server_if = (struct netif*)arg;

    struct sockaddr_in server_addr;
    char buf[1024] = "aaaaaaaaaaa";
    struct sockaddr_in client_addr;

    server_addr.sin_addr.s_addr = inet_addr("192.168.0.16");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = PP_HTONS(55557);

    client_addr.sin_addr.s_addr = inet_addr("192.168.0.12");
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = PP_HTONS(55558);

    int tcp_client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    TSLOG("TS TEST", "client thread", NULL);

    //sockaddr_storage is for
    // sockaddr_in change to sockaddr

    if(connect(tcp_client_sock, (struct sockaddr*)(&server_addr),
               sizeof(struct sockaddr)) == -1)
    {
        TSLOG("TS TEST", "server connect fail", NULL);
    }

    send(tcp_client_sock, buf, 1024, MSG_DONTWAIT);

    return;
}

err_t
test_for_tcp_intput(struct pbuf *p, struct netif *netif)
{
    TSLOG("TS TEST", "%s", "test_for_tcp_intput");

    ip_input(p, g_server_netif);
    
    return 0;
}

void input(void* p)
{
    TSLOG("TS TEST", "%s", "input");

    test_for_tcp_intput((struct pbuf*)p, temp_netif);
}

void test_temp(void* p)
{
    TSLOG("TS TEST", "%s", "test_temp");

    sys_timeout(1000, input, (struct pbuf*)p);
}

//just for test
err_t test_for_tcp_output(struct netif *netif, struct pbuf *p,
                          const ip4_addr_t *ipaddr)
{
    TSLOG("TS TEST", "%s", "test_for_tcp_output");

    temp_netif = netif;

    //print_header(p);

    struct pbuf* temp_pbuf =  pbuf_alloc(NULL,PBUF_TRANSPORT, p->tot_len, PBUF_POOL);

    pbuf_copy(temp_pbuf, p);

    //sys_thread_new("a", test_temp, temp_pbuf, 1024, 0);
    vpn_tun_device_write(p->payload, p->len);

    return 0;
}

//just for test
err_t test_for_tcp_link_output(struct netif *netif, struct pbuf *p)
{
    TSLOG("TS TEST", "%s", "test_for_tcp_link_output");

    return ERR_OK;
}

static err_t test_for_tcp_init(struct netif *netif)
{
    netif->name[0] = 'f';
    netif->name[1] = 'z';
    netif->output = test_for_tcp_output;
    netif->linkoutput = test_for_tcp_link_output;
    netif->hwaddr_len = 6;
    netif->flags = NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    netif->hwaddr[0] = 0x00;
    netif->hwaddr[1] = 0x23;
    netif->hwaddr[2] = 0xC1;
    netif->hwaddr[3] = 0xDE;
    netif->hwaddr[4] = 0xD0;
    netif->hwaddr[5] = 0x0D;

    return ERR_OK;
}

void test_tcp()
{
    //first fill in pbuf to transform.
    //struct pbuf* buf = (struct pbuf*)malloc(sizeof(struct pbuf));

    //init two netif fot server and client
    struct netif net_test_server; /*= (struct netif*)malloc(sizeof(struct netif))*/;
    //struct netif* net_test_client = (struct netif*)malloc(sizeof(struct netif));
    g_server_netif = (struct netif*)malloc(sizeof(struct netif));
    //g_client_netif = (struct netif*)malloc(sizeof(struct netif));

    ip4_addr_t addr_server;
    ip4_addr_t netmask_server;
    ip4_addr_t gw_server;
    u8_t pktbuf[2000];
    size_t len;

//    ip4_addr_t addr_client;
//    ip4_addr_t netmask_client;
//    ip4_addr_t gw_client;
    //tcpip_init(NULL, NULL);
    IP4_ADDR(&addr_server, 192, 168, 43, 16);
    IP4_ADDR(&netmask_server, 0, 0, 0, 0);
    IP4_ADDR(&gw_server, 192, 168, 43, 1);
    (&net_test_server)->mtu = 1500;

    netif_add(&net_test_server, &addr_server, &netmask_server, &gw_server, &net_test_server,
              test_for_tcp_init, test_for_tcp_intput);
    netif_set_up(&net_test_server);

    //IP4_ADDR(&addr_client, 192, 168, 0, 12);
    //IP4_ADDR(&netmask_client, 255, 255, 255, 0);
    //IP4_ADDR(&gw_client, 192, 168, 0, 1);
    //net_test_client->mtu = 1500;

    //netif_add(net_test_client, &addr_client, &netmask_client, &gw_client, net_test_client,
    //          test_for_tcp_init, test_for_tcp_intput);
    //netif_set_up(net_test_client);

    //g_client_netif = net_test_client;
    g_server_netif = &net_test_server;

    sys_thread_new("server_thread", server_thread, (void*)&net_test_server, 1024, 0);

}
/*********************************** tcp local netif end ***************************************/

/*********************************** socket example start***************************************/

#if LWIP_SOCKET

#ifndef SOCK_TARGET_HOST
#define SOCK_TARGET_HOST  "192.168.1.1"
#endif

#ifndef SOCK_TARGET_PORT
#define SOCK_TARGET_PORT  80
#endif

/** This is an example function that tests
    blocking- and nonblocking connect. */
static void
sockex_nonblocking_connect(void *arg)
{
    int s;
    int ret;
    u32_t opt;
    struct sockaddr_in addr;
    fd_set readset;
    fd_set writeset;
    fd_set errset;
    struct timeval tv;
    u32_t ticks_a, ticks_b;
    int err;

    LWIP_UNUSED_ARG(arg);
    /* set up address to connect to */
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = PP_HTONS(SOCK_TARGET_PORT);
    addr.sin_addr.s_addr = inet_addr(SOCK_TARGET_HOST);

    /* first try blocking: */

    /* create the socket */
    s = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s >= 0", s >= 0);

    /* connect */
    ret = lwip_connect(s, (struct sockaddr*)&addr, sizeof(addr));
    /* should succeed */
    LWIP_ASSERT("ret == 0", ret == 0);

    /* write something */
    ret = lwip_write(s, "test", 4);
    LWIP_ASSERT("ret == 4", ret == 4);

    /* close */
    ret = lwip_close(s);
    LWIP_ASSERT("ret == 0", ret == 0);

    /* now try nonblocking and close before being connected */

    /* create the socket */
    s = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s >= 0", s >= 0);
    /* nonblocking */
    opt = lwip_fcntl(s, F_GETFL, 0);
    LWIP_ASSERT("ret != -1", ret != -1);
    opt |= O_NONBLOCK;
    ret = lwip_fcntl(s, F_SETFL, opt);
    LWIP_ASSERT("ret != -1", ret != -1);
    /* connect */
    ret = lwip_connect(s, (struct sockaddr*)&addr, sizeof(addr));
    /* should have an error: "inprogress" */
    LWIP_ASSERT("ret == -1", ret == -1);
    err = errno;
    LWIP_ASSERT("errno == EINPROGRESS", err == EINPROGRESS);
    /* close */
    ret = lwip_close(s);
    LWIP_ASSERT("ret == 0", ret == 0);
    /* try to close again, should fail with EBADF */
    ret = lwip_close(s);
    LWIP_ASSERT("ret == -1", ret == -1);
    err = errno;
    LWIP_ASSERT("errno == EBADF", err == EBADF);
    printf("closing socket in nonblocking connect succeeded\n");

    /* now try nonblocking, connect should succeed:
       this test only works if it is fast enough, i.e. no breakpoints, please! */

    /* create the socket */
    s = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s >= 0", s >= 0);

    /* nonblocking */
    opt = 1;
    ret = lwip_ioctl(s, FIONBIO, &opt);
    LWIP_ASSERT("ret == 0", ret == 0);

    /* connect */
    ret = lwip_connect(s, (struct sockaddr*)&addr, sizeof(addr));
    /* should have an error: "inprogress" */
    LWIP_ASSERT("ret == -1", ret == -1);
    err = errno;
    LWIP_ASSERT("errno == EINPROGRESS", err == EINPROGRESS);

    /* write should fail, too */
    ret = lwip_write(s, "test", 4);
    LWIP_ASSERT("ret == -1", ret == -1);
    err = errno;
    LWIP_ASSERT("errno == EINPROGRESS", err == EINPROGRESS);

    FD_ZERO(&readset);
    FD_SET(s, &readset);
    FD_ZERO(&writeset);
    FD_SET(s, &writeset);
    FD_ZERO(&errset);
    FD_SET(s, &errset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    /* select without waiting should fail */
    ret = lwip_select(s + 1, &readset, &writeset, &errset, &tv);
    LWIP_ASSERT("ret == 0", ret == 0);
    LWIP_ASSERT("!FD_ISSET(s, &writeset)", !FD_ISSET(s, &writeset));
    LWIP_ASSERT("!FD_ISSET(s, &readset)", !FD_ISSET(s, &readset));
    LWIP_ASSERT("!FD_ISSET(s, &errset)", !FD_ISSET(s, &errset));

    FD_ZERO(&readset);
    FD_SET(s, &readset);
    FD_ZERO(&writeset);
    FD_SET(s, &writeset);
    FD_ZERO(&errset);
    FD_SET(s, &errset);
    ticks_a = sys_now();
    /* select with waiting should succeed */
    ret = lwip_select(s + 1, &readset, &writeset, &errset, NULL);
    ticks_b = sys_now();
    LWIP_ASSERT("ret == 1", ret == 1);
    LWIP_ASSERT("FD_ISSET(s, &writeset)", FD_ISSET(s, &writeset));
    LWIP_ASSERT("!FD_ISSET(s, &readset)", !FD_ISSET(s, &readset));
    LWIP_ASSERT("!FD_ISSET(s, &errset)", !FD_ISSET(s, &errset));

    /* now write should succeed */
    ret = lwip_write(s, "test", 4);
    LWIP_ASSERT("ret == 4", ret == 4);

    /* close */
    ret = lwip_close(s);
    LWIP_ASSERT("ret == 0", ret == 0);

    printf("select() needed %d ticks to return writable\n", ticks_b - ticks_a);


    /* now try nonblocking to invalid address:
       this test only works if it is fast enough, i.e. no breakpoints, please! */

    /* create the socket */
    s = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s >= 0", s >= 0);

    /* nonblocking */
    opt = 1;
    ret = lwip_ioctl(s, FIONBIO, &opt);
    LWIP_ASSERT("ret == 0", ret == 0);

    addr.sin_addr.s_addr++;

    /* connect */
    ret = lwip_connect(s, (struct sockaddr*)&addr, sizeof(addr));
    /* should have an error: "inprogress" */
    LWIP_ASSERT("ret == -1", ret == -1);
    err = errno;
    LWIP_ASSERT("errno == EINPROGRESS", err == EINPROGRESS);

    /* write should fail, too */
    ret = lwip_write(s, "test", 4);
    LWIP_ASSERT("ret == -1", ret == -1);
    err = errno;
    LWIP_ASSERT("errno == EINPROGRESS", err == EINPROGRESS);

    FD_ZERO(&readset);
    FD_SET(s, &readset);
    FD_ZERO(&writeset);
    FD_SET(s, &writeset);
    FD_ZERO(&errset);
    FD_SET(s, &errset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    /* select without waiting should fail */
    ret = lwip_select(s + 1, &readset, &writeset, &errset, &tv);
    LWIP_ASSERT("ret == 0", ret == 0);

    FD_ZERO(&readset);
    FD_SET(s, &readset);
    FD_ZERO(&writeset);
    FD_SET(s, &writeset);
    FD_ZERO(&errset);
    FD_SET(s, &errset);
    ticks_a = sys_now();
    /* select with waiting should eventually succeed and return errset! */
    ret = lwip_select(s + 1, &readset, &writeset, &errset, NULL);
    ticks_b = sys_now();
    LWIP_ASSERT("ret > 0", ret > 0);
    LWIP_ASSERT("FD_ISSET(s, &errset)", FD_ISSET(s, &errset));
    LWIP_ASSERT("!FD_ISSET(s, &readset)", !FD_ISSET(s, &readset));
    LWIP_ASSERT("!FD_ISSET(s, &writeset)", !FD_ISSET(s, &writeset));

    /* close */
    ret = lwip_close(s);
    LWIP_ASSERT("ret == 0", ret == 0);

    printf("select() needed %d ticks to return error\n", ticks_b - ticks_a);
    printf("all tests done, thread ending\n");
}

/** This is an example function that tests
    the recv function (timeout etc.). */
static void
sockex_testrecv(void *arg)
{
    int s;
    int ret;
    int err;
    int opt;
    struct sockaddr_in addr;
    size_t len;
    char rxbuf[1024];
    fd_set readset;
    fd_set errset;
    struct timeval tv;

    LWIP_UNUSED_ARG(arg);
    /* set up address to connect to */
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = PP_HTONS(SOCK_TARGET_PORT);
    addr.sin_addr.s_addr = inet_addr(SOCK_TARGET_HOST);

    /* first try blocking: */

    /* create the socket */
    s = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s >= 0", s >= 0);

    /* connect */
    ret = lwip_connect(s, (struct sockaddr*)&addr, sizeof(addr));
    /* should succeed */
    LWIP_ASSERT("ret == 0", ret == 0);

    /* set recv timeout (100 ms) */
    opt = 100;
    ret = lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &opt, sizeof(int));
    LWIP_ASSERT("ret == 0", ret == 0);

    /* write the start of a GET request */
#define SNDSTR1 "G"
    len = strlen(SNDSTR1);
    ret = lwip_write(s, SNDSTR1, len);
    LWIP_ASSERT("ret == len", ret == (int)len);

    /* should time out if the other side is a good HTTP server */
    ret = lwip_read(s, rxbuf, 1);
    LWIP_ASSERT("ret == -1", ret == -1);
    err = errno;
    LWIP_ASSERT("errno == EAGAIN", err == EAGAIN);

    /* write the rest of a GET request */
#define SNDSTR2 "ET / HTTP_1.1\r\n\r\n"
    len = strlen(SNDSTR2);
    ret = lwip_write(s, SNDSTR2, len);
    LWIP_ASSERT("ret == len", ret == (int)len);

    /* wait a while: should be enough for the server to send a response */
    sys_msleep(1000);

    /* should not time out but receive a response */
    ret = lwip_read(s, rxbuf, 1024);
    LWIP_ASSERT("ret > 0", ret > 0);

    /* now select should directly return because the socket is readable */
    FD_ZERO(&readset);
    FD_ZERO(&errset);
    FD_SET(s, &readset);
    FD_SET(s, &errset);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    ret = lwip_select(s + 1, &readset, NULL, &errset, &tv);
    LWIP_ASSERT("ret == 1", ret == 1);
    LWIP_ASSERT("!FD_ISSET(s, &errset)", !FD_ISSET(s, &errset));
    LWIP_ASSERT("FD_ISSET(s, &readset)", FD_ISSET(s, &readset));

    /* should not time out but receive a response */
    ret = lwip_read(s, rxbuf, 1024);
    /* might receive a second packet for HTTP/1.1 servers */
    if (ret > 0) {
        /* should return 0: closed */
        ret = lwip_read(s, rxbuf, 1024);
        LWIP_ASSERT("ret == 0", ret == 0);
    }

    /* close */
    ret = lwip_close(s);
    LWIP_ASSERT("ret == 0", ret == 0);

    printf("sockex_testrecv finished successfully\n");
}

/** helper struct for the 2 functions below (multithreaded: thread-argument) */
struct sockex_select_helper {
    int socket;
    int wait_read;
    int expect_read;
    int wait_write;
    int expect_write;
    int wait_err;
    int expect_err;
    int wait_ms;
    sys_sem_t sem;
};

/** helper thread to wait for socket events using select */
static void
sockex_select_waiter(void *arg)
{
    struct sockex_select_helper *helper = (struct sockex_select_helper *)arg;
    int ret;
    fd_set readset;
    fd_set writeset;
    fd_set errset;
    struct timeval tv;

    LWIP_ASSERT("helper != NULL", helper != NULL);

    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_ZERO(&errset);
    if (helper->wait_read) {
        FD_SET(helper->socket, &readset);
    }
    if (helper->wait_write) {
        FD_SET(helper->socket, &writeset);
    }
    if (helper->wait_err) {
        FD_SET(helper->socket, &errset);
    }

    tv.tv_sec = helper->wait_ms / 1000;
    tv.tv_usec = (helper->wait_ms % 1000) * 1000;

    ret = lwip_select(helper->socket, &readset, &writeset, &errset, &tv);
    if (helper->expect_read || helper->expect_write || helper->expect_err) {
        LWIP_ASSERT("ret > 0", ret > 0);
    } else {
        LWIP_ASSERT("ret == 0", ret == 0);
    }
    if (helper->expect_read) {
        LWIP_ASSERT("FD_ISSET(helper->socket, &readset)", FD_ISSET(helper->socket, &readset));
    } else {
        LWIP_ASSERT("!FD_ISSET(helper->socket, &readset)", !FD_ISSET(helper->socket, &readset));
    }
    if (helper->expect_write) {
        LWIP_ASSERT("FD_ISSET(helper->socket, &writeset)", FD_ISSET(helper->socket, &writeset));
    } else {
        LWIP_ASSERT("!FD_ISSET(helper->socket, &writeset)", !FD_ISSET(helper->socket, &writeset));
    }
    if (helper->expect_err) {
        LWIP_ASSERT("FD_ISSET(helper->socket, &errset)", FD_ISSET(helper->socket, &errset));
    } else {
        LWIP_ASSERT("!FD_ISSET(helper->socket, &errset)", !FD_ISSET(helper->socket, &errset));
    }
    sys_sem_signal(&helper->sem);
}

/** This is an example function that tests
    more than one thread being active in select. */
static void
sockex_testtwoselects(void *arg)
{
    int s1;
    int s2;
    int ret;
    struct sockaddr_in addr;
    size_t len;
    err_t lwiperr;
    struct sockex_select_helper h1, h2, h3, h4;

    LWIP_UNUSED_ARG(arg);
    /* set up address to connect to */
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = PP_HTONS(SOCK_TARGET_PORT);
    addr.sin_addr.s_addr = inet_addr(SOCK_TARGET_HOST);

    /* create the sockets */
    s1 = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s1 >= 0", s1 >= 0);
    s2 = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s2 >= 0", s2 >= 0);

    /* connect, should succeed */
    ret = lwip_connect(s1, (struct sockaddr*)&addr, sizeof(addr));
    LWIP_ASSERT("ret == 0", ret == 0);
    ret = lwip_connect(s2, (struct sockaddr*)&addr, sizeof(addr));
    LWIP_ASSERT("ret == 0", ret == 0);

    /* write the start of a GET request */
#define SNDSTR1 "G"
    len = strlen(SNDSTR1);
    ret = lwip_write(s1, SNDSTR1, len);
    LWIP_ASSERT("ret == len", ret == (int)len);
    ret = lwip_write(s2, SNDSTR1, len);
    LWIP_ASSERT("ret == len", ret == (int)len);

    h1.wait_read  = 1;
    h1.wait_write = 1;
    h1.wait_err   = 1;
    h1.expect_read  = 0;
    h1.expect_write = 0;
    h1.expect_err   = 0;
    lwiperr = sys_sem_new(&h1.sem, 0);
    LWIP_ASSERT("lwiperr == ERR_OK", lwiperr == ERR_OK);
    h1.socket = s1;
    h1.wait_ms = 500;

    h2 = h1;
    lwiperr = sys_sem_new(&h2.sem, 0);
    LWIP_ASSERT("lwiperr == ERR_OK", lwiperr == ERR_OK);
    h2.socket = s2;
    h2.wait_ms = 1000;

    h3 = h1;
    lwiperr = sys_sem_new(&h3.sem, 0);
    LWIP_ASSERT("lwiperr == ERR_OK", lwiperr == ERR_OK);
    h3.socket = s2;
    h3.wait_ms = 1500;

    h4 = h1;
    lwiperr = sys_sem_new(&h4.sem, 0);
    LWIP_ASSERT("lwiperr == ERR_OK", lwiperr == ERR_OK);
    h4.socket = s2;
    h4.wait_ms = 2000;

    /* select: all sockets should time out if the other side is a good HTTP server */

    sys_thread_new("sockex_select_waiter1", sockex_select_waiter, &h2, 0, 0);
    sys_msleep(100);
    sys_thread_new("sockex_select_waiter2", sockex_select_waiter, &h1, 0, 0);
    sys_msleep(100);
    sys_thread_new("sockex_select_waiter2", sockex_select_waiter, &h4, 0, 0);
    sys_msleep(100);
    sys_thread_new("sockex_select_waiter2", sockex_select_waiter, &h3, 0, 0);

    sys_sem_wait(&h1.sem);
    sys_sem_wait(&h2.sem);
    sys_sem_wait(&h3.sem);
    sys_sem_wait(&h4.sem);

    /* close */
    ret = lwip_close(s1);
    LWIP_ASSERT("ret == 0", ret == 0);
    ret = lwip_close(s2);
    LWIP_ASSERT("ret == 0", ret == 0);

    printf("sockex_testtwoselects finished successfully\n");
}

void socket_examples_init(void)
{
    sys_thread_new("sockex_nonblocking_connect", sockex_nonblocking_connect, NULL, 0, 0);
    sys_thread_new("sockex_testrecv", sockex_testrecv, NULL, 0, 0);
    /*sys_thread_new("sockex_testtwoselects", sockex_testtwoselects, NULL, 0, 0);*/
}

#endif /* LWIP_SOCKETS */
/*********************************** socket example end***************************************/
