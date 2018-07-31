//
// Created by ts on 17-5-3.
//

#include "test_trans_to_mutp.h"
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include "../../tools/tools.h"
#include "../../mccp/mccp.h"
#include "lwip/mptcp/mptcp_proxy.h"

int trans_test_mutp_fd = -1;
pthread_t  trans_tid;
int trans_flag = 0;
void* trans_recv_data(void* data);
int trans_mutp_init()
{
    int ret = 0;
    struct ifreq ethreq;
    struct sockaddr_ll ll;
    ENTER_FUNC;
    trans_test_mutp_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP)); //trans ip包
    //ret = protectFdFromJava(trans_test_mutp_fd);
    if(ret < -1)
    {
        return -1;
    }
    trans_flag = 1;
    strncpy(ethreq.ifr_name, "wlan0", IFNAMSIZ);            //指定网卡名称
    if(-1 == ioctl(trans_test_mutp_fd, SIOCGIFINDEX, &ethreq))    //获取网络接口
    {
        LogE("+++++++++++++++++++++++++++++++获取网口失败++++++++++++++++++");
        close(trans_test_mutp_fd);
        return -1;
    }
    else{
        LogE("+++++++++++++++++++++++++++++++获取网口成功++++++++++++++++++");
    }

    //init the ifreq sockaddr ll
    ll.sll_family = AF_PACKET;
    ll.sll_ifindex = ethreq.ifr_ifindex;
    ll.sll_protocol = htons(ETH_P_IP);

    if (bind(trans_test_mutp_fd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
        LogE("bind to %s: %s\n", "wlan", strerror(errno));
        close(trans_test_mutp_fd);
        return -1;
    }

    pthread_create(&trans_tid,NULL,trans_recv_data,NULL);
    EXIT_FUNC;
}

void trans_mutp_destory()
{
    trans_flag = 0;
    if(trans_test_mutp_fd > 0)
    {
        close(trans_test_mutp_fd);
        trans_test_mutp_fd = -1;
    }
}

void trans_senddata(char *buf,int len,struct sockaddr_in* addr,int socklen)
{
    if(buf == NULL || len < 0)
    {
        LogI("错误的数据");
        return;
    }
    len = (int) sendto(trans_test_mutp_fd, buf, len, 0, (struct sockaddr*)addr, socklen);
    if(len < 0)
    {
        LogI("错误的socket的传输");
    }
    else{
        LogI("输出到内核的数据长度:%d",len);
    }

}

void* trans_recv_data(void* data)
{
    fd_set recvdata;
    int ret = 0;
    int len = 0;
    socklen_t socklen;
    struct timeval tim;
    tim.tv_sec = 1;
    tim.tv_usec = 0;
    char *buf[2048] ={0};
    struct pbuf *pbuf1;
    struct sockaddr_in sockaddr;
    while(trans_flag)
    {
        memset(buf,0,sizeof(buf));
        FD_ZERO(&recvdata);
        FD_SET(trans_test_mutp_fd,&recvdata);
        ret = select(trans_test_mutp_fd,NULL,&recvdata,NULL,&tim);
        switch(ret)
        {
            case 0:
                LogD("mutp time out!");
                break;
            case -1:
                LogE("mutp transmisstion error!");
                return NULL;
            default:
                //需要将相应的数据放回协议栈
                len = (int) recvfrom(trans_test_mutp_fd, buf, sizeof(buf), 0, (struct sockaddr*)&sockaddr, &socklen);
                pbuf1 = pbuf_alloc(NULL,PBUF_IP,len,PBUF_ROM);
                pbuf_copy_partial(pbuf1,buf,len,0);//拷贝数据
                mptcp_proxy_client_netif.input(pbuf1,&mptcp_proxy_client_netif);//将相应的数据送入协议栈
                break;
        }
    }
    return NULL;
}