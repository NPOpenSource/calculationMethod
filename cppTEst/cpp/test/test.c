
// Created by ts on 17-4-12.
//

#include "test.h"
#include "../mccp/mccp.h"
#include "../tunnel/tunnel.h"

/******测试头文件*******/
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../mccp/mccp.h"
/******测试头文件*******/

/*
typedef struct __pca{
    UINT32 session_id;
    UINT32 mccp_ue_ip;
    UINT32 mccp_mpgw_ip;
    UINT16 mccp_mpgw_port;
    UINT16 mccp_max_quantity;
    UINT32 mccp_tunnel_id;
    BOOL mccp_auth;
    mccp_result_code result_code;
}PCA_S;
*/
char resultCodeMsg[][50] = {
        "mccp auth success",    //success
        "mccp unknow failure reason",  //unknow failure reason
        "mccp auth fail",    //auth fail
        "mccp context not found",   //context not found
        "mccp invalid message format", //invalid message format
        "mccp mandatory ie inconrrect",    //mandatory ie inconrrect
        "mccp mandatory ie missiing",  //mandatory ie missiing
        "mccp no resource is available",    //no resource is available
        "mccp system failure",   //system failure
        "mccp request refuse",   //request refuse
        "mccp network refuse",   //network refuse
        "mccp ue refuse",     //ue refuse
        "mccp used for reserved",     //used for reserved
        "more than mccp max result code"
};
char ra_string[][50] = {
        "PCR",
        "PCA",
        "PUR",
        "PUA",
        "DUR",
        "DSA"
};

char messageType[][50] = {
        "not used type",
        "Session ID",            //session id
        "TERMINATION_CAUSE",    //
        "DISCONNECT_CAUSE",    //
        "Result code",                //result code
        "MSISDN",                //
        "IMSI",
        "IMEI",
        "MAC",
        "WHITELIST",
        "QOS",
        "MPGW_IP",
        "MPGW_PORT",
        "Max connnectivity Quantity",
        "TEID",
        "UE_IP",
        "T_TYPE"
};

void testDecodeSessionId() {
    mccp_tlv tlv;
    mccp_tlv *pTlv = NULL;
    UINT32 session_id = 0;
    int value = htonl(1234);
    UINT8 *pMsg;
    memset(&tlv, 0, sizeof(tlv));
    tlv.type = SID;
    tlv.len = (UINT8) 4;
    tlv.data = (UINT8 *) malloc(tlv.len);

    memset(tlv.data, 0, tlv.len);

    pMsg = (UINT8 *) malloc(tlv.len + MCCP_HEADER_LEN);
    memset(pMsg, 0, sizeof(mccp_tlv));
    memcpy(tlv.data, &value, tlv.len);
    //memcpy(pMsg,&tlv,MCCP_HEADER_LEN);
    pMsg[0] = (UINT8) tlv.type;
    *(UINT16*)(pMsg+1) = htons(tlv.len);
    memcpy(pMsg + MCCP_HEADER_LEN, tlv.data, tlv.len);

    pTlv = decode_mccp_tlv(pMsg, 0);

    session_id = decode_session_id(pTlv);

    LogI("message Type:%s,the value is %d,the value len is %d", messageType[pTlv->type], session_id,
         pTlv->len);
}

void testDecodeResultCode() {
    mccp_tlv tlv;
    mccp_tlv *pTlv = NULL;
    UINT16 rcode = htons(0);
    int value = 0;
    UINT8 *pMsg;
    memset(&tlv, 0, sizeof(tlv));
    tlv.type = RCODE;
    tlv.len = 2;
    tlv.data = (UINT8 *) malloc(tlv.len);

    memset(tlv.data, 0, tlv.len);

    pMsg = (UINT8 *) malloc(tlv.len + MCCP_HEADER_LEN);
    memset(pMsg, 0, sizeof(mccp_tlv));
    memcpy(tlv.data, &value, tlv.len);
    //memcpy(pMsg,&tlv,MCCP_HEADER_LEN);
    pMsg[0] = (UINT8) tlv.type;
    *(UINT16*)(pMsg+1) =  htons(tlv.len);
    memcpy(pMsg + MCCP_HEADER_LEN, tlv.data, tlv.len);

    pTlv = decode_mccp_tlv(pMsg, 0);
    rcode = decode_result_code(pTlv);

    LogI("%d ,message Type:%s,the value is %d,the value len is %d", pTlv->type,
         messageType[pTlv->type], rcode, pTlv->len);
}

void testDecodeUeIp() {
    mccp_tlv tlv;
    mccp_tlv *pTlv = NULL;
    UINT32 UeIp = 0;
    struct in_addr sock;
    int value = inet_addr("192.168.43.225");
    UINT8 *pMsg;
    memset(&tlv, 0, sizeof(tlv));
    tlv.type = UE_IP;
    tlv.len = 5;
    tlv.data = (UINT8 *) malloc(tlv.len);
    value = inet_addr("192.168.0.2");
    LogI("curreent ip:%d", value);
    memset(tlv.data, 0, tlv.len);

    pMsg = (UINT8 *) malloc(tlv.len + MCCP_HEADER_LEN);
    memset(pMsg, 0, sizeof(mccp_tlv));
    memcpy(tlv.data, &value, tlv.len);
    //memcpy(pMsg,&tlv,MCCP_HEADER_LEN);
    pMsg[0] = (UINT8) tlv.type;
    *(UINT16*)(pMsg+1) =  htons(tlv.len);
    pMsg[3] = (UINT8) 128;
    memcpy(pMsg + MCCP_HEADER_LEN + 1, tlv.data, tlv.len-1);

    pTlv = decode_mccp_tlv(pMsg, 0);
    UeIp = decode_ue_ip(pTlv);
    sock.s_addr = UeIp;
    LogI("current ip address:%s", inet_ntoa(sock));
    LogI("%d ,message Type:%s,the value is %d,the value len is %d", pTlv->type,
         messageType[pTlv->type], UeIp, pTlv->len);
}

void testDecodeMpgwPort() {
    mccp_tlv tlv;
    mccp_tlv *pTlv = NULL;
    UINT16 port = 0;
    int value = htons(10000);
    UINT8 *pMsg;
    memset(&tlv, 0, sizeof(tlv));
    tlv.type = MPGW_PORT;
    tlv.len = 2;
    tlv.data = (UINT8 *) malloc(tlv.len);

    memset(tlv.data, 0, tlv.len);

    pMsg = (UINT8 *) malloc(tlv.len + MCCP_HEADER_LEN);
    memset(pMsg, 0, sizeof(mccp_tlv));
    memcpy(tlv.data, &value, tlv.len);
    //memcpy(pMsg,&tlv,MCCP_HEADER_LEN);
    pMsg[0] = (UINT8) tlv.type;
    *(UINT16*)(pMsg+1) =  htons(tlv.len);
    memcpy(pMsg + MCCP_HEADER_LEN, tlv.data, tlv.len);

    pTlv = decode_mccp_tlv(pMsg, 0);
    port = decode_mpgw_port(pTlv);
    LogI("%d ,message Type:%s,the value is %d,the value len is %d", pTlv->type,
         messageType[pTlv->type], port, pTlv->len);
}

void testDecodeMpgwIp() {
    mccp_tlv tlv;
    mccp_tlv *pTlv = NULL;
    UINT32 mpgwIp = 0;
    int value = inet_addr("192.168.43.25");//16 进制 对应输出结果 1193046
    UINT8 *pMsg;
    struct in_addr sock;
    memset(&tlv, 0, sizeof(tlv));
    tlv.type = MPGW_IP;
    tlv.len = 5;
    tlv.data = (UINT8 *) malloc(tlv.len);

    memset(tlv.data, 0, tlv.len);
    value = inet_addr("192.168.0.2");
    LogI("curreent ip:%d", value);

    pMsg = (UINT8 *) malloc(tlv.len + MCCP_HEADER_LEN);
    memset(pMsg, 0, sizeof(mccp_tlv));
    memcpy(tlv.data, &value, tlv.len);
    //memcpy(pMsg,&tlv,MCCP_HEADER_LEN);
    pMsg[0] = (UINT8) tlv.type;
    *(UINT16*)(pMsg+1) =  htons(tlv.len);
    pMsg[3] = (UINT8) 128;
    memcpy(pMsg + MCCP_HEADER_LEN + 1, tlv.data, tlv.len-1);

    pTlv = decode_mccp_tlv(pMsg, 0);
    mpgwIp = decode_mpgw_ip(pTlv);
    sock.s_addr = mpgwIp;
    LogI("current ip addr:%s", inet_ntoa(sock));
    LogI("%d ,message Type:%s,the value is %d,the value len is %d", pTlv->type,
         messageType[pTlv->type], mpgwIp, pTlv->len);
}

void testDecodeMcq() {
    mccp_tlv tlv;
    mccp_tlv *pTlv = NULL;
    UINT16 mcq = 0;
    int value = htons(50);
    UINT8 *pMsg;
    memset(&tlv, 0, sizeof(tlv));
    tlv.type = MCQ;
    tlv.len = 2;
    tlv.data = (UINT8 *) malloc(tlv.len);

    memset(tlv.data, 0, tlv.len);

    pMsg = (UINT8 *) malloc(tlv.len + MCCP_HEADER_LEN);
    memset(pMsg, 0, sizeof(mccp_tlv));
    memcpy(tlv.data, &value, tlv.len);
    //memcpy(pMsg,&tlv,MCCP_HEADER_LEN);
    pMsg[0] = (UINT8) tlv.type;
    *(UINT16*)( pMsg+1) =  htons(tlv.len);
    memcpy(pMsg + MCCP_HEADER_LEN, tlv.data, tlv.len);

    pTlv = decode_mccp_tlv(pMsg, 0);
    mcq = decode_max_connect_quantity(pTlv);
    LogI("%d ,message Type:%s,the value is %d,the value len is %d", pTlv->type,
         messageType[pTlv->type], mcq, pTlv->len);
}

void testDecodeTeId() {
    mccp_tlv tlv;
    mccp_tlv *pTlv = NULL;
    UINT32 teid = 0;
    int value = htonl(12345);
    UINT8 *pMsg;
    memset(&tlv, 0, sizeof(tlv));
    tlv.type = TEID;
    tlv.len = 4;
    tlv.data = (UINT8 *) malloc(tlv.len);

    memset(tlv.data, 0, tlv.len);

    pMsg = (UINT8 *) malloc(tlv.len + MCCP_HEADER_LEN);
    memset(pMsg, 0, sizeof(mccp_tlv));
    memcpy(tlv.data, &value, tlv.len);
    //memcpy(pMsg,&tlv,MCCP_HEADER_LEN);
    pMsg[0] = (UINT8) tlv.type;
    *(UINT16*)(pMsg+1) =  htons(tlv.len);
    memcpy(pMsg + MCCP_HEADER_LEN, tlv.data, tlv.len);

    pTlv = decode_mccp_tlv(pMsg, 0);
    teid = decode_tunnel_id(pTlv);
    LogI("%d ,message Type:%s,the value is %d,the value len is %d", pTlv->type,
         messageType[pTlv->type], teid, pTlv->len);
}

void showMessageType(int code) {
    if (code > MCCP_MAX_RESULT_CODE || code < 0) {
        LogE("current result code can't be reconglize");
    } else {
        LogI("current result code : %s", resultCodeMsg[code]);
    }
}

void testMutpStart() {
    //struct in_addr sockadd;
    UINT32 mpgwIp;
    UINT32 tunnel_id;
    UINT16 port = 23456;
    int ret = 0;
    char *serverIp = "197.123.56.47";
    char *ip = "192.168.43.25";
    char *ip1 = "10.17.142.228";
    int lte_fd = 0, wifi_fd = 0;
    struct sockaddr_in lte_sockaddr;
    struct sockaddr_in wifi_sockaddr;


    mpgwIp = (UINT32) inet_addr(serverIp);
    tunnel_id = 12345;

    ret = mutp_init_Info_of_server(mpgwIp, port, tunnel_id);
    if (ret != 0) {
        LogE("mutp_init_Info_of_server init the server");
        return;
    }

    lte_sockaddr.sin_family = AF_INET;
    lte_sockaddr.sin_port = 12445;
    lte_sockaddr.sin_addr.s_addr = inet_addr(ip);

    wifi_sockaddr.sin_family = AF_INET;
    wifi_sockaddr.sin_port = 22445;
    wifi_sockaddr.sin_addr.s_addr = inet_addr(ip);

    lte_fd = socket(AF_INET, SOCK_DGRAM, 0);
    wifi_fd = socket(AF_INET, SOCK_DGRAM, 0);

    ret = bind(lte_fd, (struct sockaddr *) &lte_sockaddr, sizeof(lte_sockaddr));
    if (ret != 0) {
        LogE("bind lte addr error");
        return;
    }

    ret = bind(wifi_fd, (struct sockaddr *) &wifi_sockaddr, sizeof(wifi_sockaddr));
    if (ret != 0) {
        LogE("bind wifi addr error");
        return;
    }
    mutp_start_recv(NULL,NULL);
}

void testPCA_OK() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("message type:%d,pPmb->m_type:%d", PCA, pPmb->m_type);
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);
    EXIT_FUNC;

    free(pMsg);
}

/**
 * PCA版本测试
 */
void testPCA_version_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x40;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_message_type_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    int array[] = {PCR, PCA, PUR, PUA, DSR, DSA, 13, 114};
    int i = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    for (i = 0; i < 8; i++) {
        pMsg[1] = (UCHAR) array[i];
        if (array[i] - PCR >= 0 && array[i] <= MAX_MESSAGE_TYPE)
            LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
                 ra_string[array[i] - PCR], pPmb->len);
        else {
            LogI("当前构造的消息type:%d,协议中没有定义的", array[i]);
        }
        mccp_process_window(pMsg,42);
        LogI("======================================================================================================");
    }

    EXIT_FUNC;

    free(pMsg);
}

void testPCA_len_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    *(USHORT *) (pMsg + 2) = (USHORT) (pPmb->len - 10);
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);
    mccp_process_window(pMsg,42);;
    LogW("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    *(USHORT *) (pMsg + 2) = (USHORT) (pPmb->len + 10);
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_session_id_len_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 2; //长度修改由4变成2
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_session_id_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4; //长度修改由4变成2
    pPmb->session_id = 1234;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_result_code_len_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    int i = 0;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 1;//len 2==>1
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
        mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_error_result_code() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    UINT array[15] = {
            MCCP_SUCCESS,    //success
            MCCP_UNKNOW_FAILURE_REASON,  //unknow failure reason
            MCCP_AUTH_FAILURE,    //auth fail
            MCCP_CONTEXT_NOT_FOUND,   //context not found
            MCCP_INVALID_MESSAGE_FORMAT, //invalid message format
            MCCP_MANDATORY_IE_INCORRECT,    //mandatory ie inconrrect
            MCCP_MANDATORY_IE_MISSING,  //mandatory ie missiing
            MCCP_NO_RES_AVAIL,    //no resource is available
            MCCP_SYSTEM_FAILURE,   //system failure
            MCCP_REQUEST_REFUSE,   //request refuse
            MCCP_NETWORK_REFUSE,   //network refuse
            MCCP_UE_REFUSE,     //ue refuse
            MCCP_RESERVED,
            13,
            14
    };
    int i = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    if (pPmb->rcode < 14)
        LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    for (i = 0; i < 15; i++) {
        *(USHORT *) (pMsg + 12) = (USHORT) array[i];
        if (pPmb->rcode < 14)
            LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
        else {
            LogE("虽然result code shi 不同的,但同时也是会主动发起该请求");
            LogI("result code:%d", array[i]);
        }
        mccp_process_window(pMsg,42);;
        LogI("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    }
    EXIT_FUNC;

    free(pMsg);
}

void testPCA1_result_code_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_UE_IP_VER_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x40;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    LogW("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    pPmb->ver_e = 0x20;
    pMsg[16] = (UCHAR) (pPmb->ver_e);
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_UE_IP_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 6;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("256.243.256.1");
    addr.s_addr = inet_addr("256.243.256.1");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("256.243.256.1"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA1_MPGW_IP_ver_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x40;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    LogW("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    pPmb->ver_m = 0x20;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA1_MPGW_IP_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 6;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = 12345;
    addr.s_addr = 12345;
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_mpgw_len_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 3;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    LogW("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_mpgw_port_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 1022;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_mcq_len_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 1;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 4;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    LogW("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    pMsg[33] = (UCHAR) 20;
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testPCA_tunnel_id_len_error() {
    PMB g_pmb;
    PMB *pPmb = &g_pmb;
    UCHAR *pMsg = 0;
    struct in_addr addr;
    char *p = NULL;
    pPmb->version = 0x20;
    pPmb->m_type = PCA;
    pPmb->len = 0;//这个长度待定

    pPmb->sess_type = SID;
    pPmb->sess_len = 4;
    pPmb->session_id = g_session_id;//这个必须和客户端保持一直，发送是什么，这里就必须是什么
    LogI("当前session id长度:%d,值:%d", pPmb->sess_len, pPmb->session_id);
    pPmb->rcode_type = RCODE;
    pPmb->rcode_len = 2;
    pPmb->rcode = MCCP_SUCCESS;
    LogI("当前result code长度:%d,值:%s", pPmb->rcode_len, resultCodeMsg[pPmb->rcode]);
    pPmb->ueip_type = UE_IP;
    pPmb->ueip_len = 5;
    pPmb->ver_e = 0x80;
    pPmb->ue_ip = inet_addr("192.168.3.3");
    addr.s_addr = inet_addr("192.168.3.3");
    p = ((pPmb->ver_e & 0x80) != 0) ? "ipv4" : ((pPmb->ver_e & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.3.3"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->ueip_len, p, inet_ntoa(addr));


    pPmb->mpgw_type = MPGW_IP;
    pPmb->mpgw_len = 5;
    pPmb->ver_m = 0x80;
    pPmb->mpgw_ip = inet_addr("192.168.7.90");
    addr.s_addr = inet_addr("192.168.7.90");
    p = ((pPmb->ver_m & 0x80) != 0) ? "ipv4" : ((pPmb->ver_m & 0x40) != 0) ? "ipv6"
                                                                           : "error version";
    LogI("current inet_addr is %d", inet_addr("192.168.7.90"));
    LogI("当前UE IP长度:%d,%s,值:%s", pPmb->mpgw_len, p, inet_ntoa(addr));

    pPmb->port_type = MPGW_PORT;
    pPmb->port_len = 2;
    pPmb->port = 12345;
    LogI("mpgw len:%d mpgw port:%d", pPmb->port_len, pPmb->port);


    pPmb->mcq_type = MCQ;
    pPmb->mcq_len = 2;
    pPmb->mcq = 50;
    LogI("当前MCQ的长度:%d,值:%d", pPmb->mcq_len, pPmb->mcq);

    pPmb->teid_type = TEID;
    pPmb->teid_len = 3;
    pPmb->tunnel_id = 10000;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    pPmb->len = pPmb->teid_len + pPmb->mcq_len + pPmb->port_len + pPmb->mpgw_len + pPmb->ueip_len +
                pPmb->rcode_len + pPmb->sess_len + (USHORT) MCCP_MESSAGE_HEADER_LEN +
                (USHORT) (MCCP_HEADER_LEN * 7);
    LogI("sizeof(int):%d,sizeof(char):%d,sizeof(short):%d", (int) sizeof(int), (int) sizeof(char),
         (int) sizeof(short));
    LogI("当前版本:%d,当前message type:%s,当前长度:%d", (pPmb->version & 0xe0) >> 5,
         ra_string[pPmb->m_type - PCR], pPmb->len);

    pMsg = (UCHAR *) malloc(sizeof(UCHAR) * (pPmb->len));

    pMsg[0] = (UCHAR) pPmb->version;
    pMsg[1] = (UCHAR) pPmb->m_type;
    *(USHORT *) (pMsg + 2) = pPmb->len;

    pMsg[4] = (UCHAR) pPmb->sess_type;
    pMsg[5] = (UCHAR) pPmb->sess_len;
    *(UINT *) (pMsg + 6) = pPmb->session_id;

    pMsg[10] = (UCHAR) pPmb->rcode_type;
    pMsg[11] = (UCHAR) pPmb->rcode_len;
    *(USHORT *) (pMsg + 12) = pPmb->rcode;

    pMsg[14] = (UCHAR) pPmb->ueip_type;
    pMsg[15] = (UCHAR) pPmb->ueip_len;
    pMsg[16] = (UCHAR) pPmb->ver_e;
    *(UINT *) (pMsg + 17) = pPmb->ue_ip;

    pMsg[21] = (UCHAR) pPmb->mpgw_type;
    pMsg[22] = (UCHAR) pPmb->mpgw_len;
    pMsg[23] = (UCHAR) pPmb->ver_m;
    *(UINT *) (pMsg + 24) = pPmb->mpgw_ip;

    pMsg[28] = (UCHAR) pPmb->port_type;
    pMsg[29] = (UCHAR) pPmb->port_len;
    *(USHORT *) (pMsg + 30) = pPmb->port;

    pMsg[32] = (UCHAR) pPmb->mcq_type;
    pMsg[33] = (UCHAR) pPmb->mcq_len;
    *(USHORT *) (pMsg + 34) = pPmb->mcq;

    pMsg[36] = (UCHAR) pPmb->teid_type;
    pMsg[37] = (UCHAR) pPmb->teid_len;
    *(UINT *) (pMsg + 38) = pPmb->tunnel_id;

    ENTER_FUNC;
    mccp_process_window(pMsg,42);;
    LogW("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    pMsg[37] = (UCHAR) 20;
    LogI("当前teid的长度:%d,值:%d", pPmb->teid_len, pPmb->tunnel_id);
    mccp_process_window(pMsg,42);;
    EXIT_FUNC;

    free(pMsg);
}

void testMutpEncode()
{
    //
    LogI("current not implement!");
}
void testMutpDecodeOK()
{
    mutp_header mutp_header1;
    mutp_header *mutpHeader = &mutp_header1;
    char *data = "123456";
    UCHAR *pMsg = NULL;
    ENTER_FUNC;
    mutpHeader->fix_header.version = 1;
    mutpHeader->fix_header.icheck = 0;
    mutpHeader->fix_header.len = 8;
    mutpHeader->fix_header.type = 9;//0~127

    mutpHeader->msg.tunnel_id = 0x20202020;

    LogI("current version \t: %d",mutpHeader->fix_header.version);
    LogI("current icheck  \t: %d",mutpHeader->fix_header.icheck);
    LogI("current len:    \t: %d",mutpHeader->fix_header.len);
    LogI("current type:   \t: %d",mutpHeader->fix_header.type);
    LogI("current tunnel  \t: %d",mutpHeader->msg.tunnel_id);
    LogI("current msg     \t: %s",data);

    pMsg = (UCHAR*)malloc(sizeof("123456")+ 8);

    memcpy(pMsg,mutpHeader,8);

    memcpy(pMsg+8,data,sizeof("123456"));

    mutp_decode_recv(NULL,pMsg,sizeof("123456")+ 8,TRUE);
    EXIT_FUNC;
}

void testMutpDecodeVersionError()
{
    mutp_header mutp_header1;
    mutp_header *mutpHeader = &mutp_header1;
    char *data = "123456";
    UCHAR *pMsg = NULL;
    ENTER_FUNC;
    mutpHeader->fix_header.version = 2;
    mutpHeader->fix_header.icheck = 0;
    mutpHeader->fix_header.len = 8;
    mutpHeader->fix_header.type = 9;//0~127

    mutpHeader->msg.tunnel_id = 0x20202020;

    LogI("current version \t: %d",mutpHeader->fix_header.version);
    LogI("current icheck  \t: %d",mutpHeader->fix_header.icheck);
    LogI("current len:    \t: %d",mutpHeader->fix_header.type);
    LogI("current tunnel  \t: %d",mutpHeader->msg.tunnel_id);
    LogI("current msg     \t: %s",data);

    pMsg = (UCHAR*)malloc(sizeof("123456")+ 8);

    memcpy(pMsg,mutpHeader,8);

    memcpy(pMsg+8,data,sizeof("123456"));

    mutp_decode_recv(NULL,pMsg,sizeof("123456")+ 8,TRUE);
    EXIT_FUNC;
}

void testMutpDecodeVersionIcheck()
{
    mutp_header mutp_header1;
    mutp_header *mutpHeader = &mutp_header1;
    char *data = "123456";
    UCHAR *pMsg = NULL;
    ENTER_FUNC;
    mutpHeader->fix_header.version = 1;
    mutpHeader->fix_header.icheck = 1;
    mutpHeader->fix_header.len = 8;
    mutpHeader->fix_header.type = 9;//0~127

    mutpHeader->msg.tunnel_id = 0x20202020;

    LogI("current version \t: %d",mutpHeader->fix_header.version);
    LogI("current icheck  \t: %d",mutpHeader->fix_header.icheck);
    LogI("current len:    \t: %d",mutpHeader->fix_header.type);
    LogI("current tunnel  \t: %d",mutpHeader->msg.tunnel_id);
    LogI("current msg     \t: %s",data);

    pMsg = (UCHAR*)malloc(sizeof("123456")+ 8);

    memcpy(pMsg,mutpHeader,8);

    memcpy(pMsg+8,data,sizeof("123456"));

    mutp_decode_recv(NULL,pMsg,sizeof("123456")+ 8,TRUE);
    EXIT_FUNC;
}

void testMutpDecodeLenError()
{
    mutp_header mutp_header1;
    mutp_header *mutpHeader = &mutp_header1;
    char *data = "123456";
    UCHAR *pMsg = NULL;
    ENTER_FUNC;
    mutpHeader->fix_header.version = 1;
    mutpHeader->fix_header.icheck = 0;
    mutpHeader->fix_header.len = 6;
    mutpHeader->fix_header.type = 9;//0~127

    mutpHeader->msg.tunnel_id = 0x20202020;

    LogI("current version \t: %d",mutpHeader->fix_header.version);
    LogI("current icheck  \t: %d",mutpHeader->fix_header.icheck);
    LogI("current len:    \t: %d",mutpHeader->fix_header.type);
    LogI("current tunnel  \t: %d",mutpHeader->msg.tunnel_id);
    LogI("current msg     \t: %s",data);

    pMsg = (UCHAR*)malloc(sizeof("123456")+ 8);

    memcpy(pMsg,mutpHeader,8);

    memcpy(pMsg+8,data,sizeof("123456"));

    mutp_decode_recv(NULL,pMsg,sizeof("123456")+ 8,TRUE);
    EXIT_FUNC;
}

void testMutpDecodeTunnel_error()
{
    mutp_header mutp_header1;
    mutp_header *mutpHeader = &mutp_header1;
    char *data = "123456";
    UCHAR *pMsg = NULL;
    ENTER_FUNC;
    mutpHeader->fix_header.version = 1;
    mutpHeader->fix_header.icheck = 0;
    mutpHeader->fix_header.len = 8;
    mutpHeader->fix_header.type = 9;//0~127

    mutpHeader->msg.tunnel_id = 0x20202022;

    LogI("current version \t: %d",mutpHeader->fix_header.version);
    LogI("current icheck  \t: %d",mutpHeader->fix_header.icheck);
    LogI("current len:    \t: %d",mutpHeader->fix_header.type);
    LogI("current tunnel  \t: %d",mutpHeader->msg.tunnel_id);
    LogI("current msg     \t: %s",data);


    pMsg = (UCHAR*)malloc(sizeof("123456")+ 8);

    memcpy(pMsg,mutpHeader,8);

    memcpy(pMsg+8,data,sizeof("123456"));

    mutp_decode_recv(NULL,pMsg,sizeof("123456")+ 8,TRUE);
    EXIT_FUNC;
}

void testWithTheCorrectFlow()
{
    UINT8 flow[][42]={
            /* 0 华为给定的PCA流*/
            {0x20,0x66,0x00,0x17,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03},
            /* 1 正常的PCA流*/
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            /* 2 PCA len > normal len*/
            {0x20,0x66,0x00,0x2d,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            /* 3 PCA len < normal len*/
            {0x20,0x66,0x00,0x29,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            /********** type error **********/
            //4 PUR  *
            {0x20,0x67,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            // 5 PUA  *
            {0x20,0x68,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            // 6 PCR  *
            {0x20,0x65,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            // 7 DSR  *
            {0x20,0x69,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            // 8 DSA
            {0x20,0x6a,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            /********** type error **********/
            // 9 版本错误测试
            {0x40,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //10 sessoin id < normal len       * 这个错误会导致整个session id的包不识别
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x05,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //11 session id len < normal len   *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x03,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            // 12 session id 不匹配测试，需要修改global 的session id 的值
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            // 13 result code 长度错误                                              *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x03,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            /******************************************************************************/
            //  14 result 错误码 正常返回                                                   *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x01,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x02,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x03,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x04,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x05,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x06,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x07,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x08,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x09,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x0a,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x0b,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            /***********************************************************************************/
     //24   //tunnel len > normal len                                                                   *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x05,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
     //25   //tunnel len < normal len                                                                   *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x03,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //mpgw ip len error                                                                                                                      *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x04,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //mpgw ip version error                                                                                                                 *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x40,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //mpgw port len < normal len                                                                                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x01,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //mpgw port len > normal len                                                                                                                                            *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x03,0xf3,0x24,0x0f,0x00,0x05,0x80,0x21,0x21,0x12,0x12},
            //UE IP len error                                                                                                                                                                               *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x06,0x80,0x21,0x21,0x12,0x12},
            //UE IP version error                                                                                                                                                                                *
            {0x20,0x66,0x00,0x2c,0x01,0x00,0x04,0x12,0x34,0x56,0x78,0x04,0x00,0x02,0x00,0x00,0x0e,0x00,0x04,0x00,0xa6,0x00,0x03,0x0b,0x00,0x05,0x80,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0xf3,0x24,0x0f,0x00,0x05,0x40,0x21,0x21,0x12,0x12},
    };
    int ret,i = 0;
    ENTER_FUNC;
    g_session_id = 0x12345678;
    //1. 测试华为给定的PCA的流
//    LogI("-----------------------------------%d---------------------------------------",0);
//    mccp_process_window(flow[0],23);
//    LogI("-----------------------------------%d---------------------------------------",0);
    //2. 测试正常的PCA流
//    LogI("-----------------------------------\t%d\t---------------------------------------",1);
//    mccp_process_window(flow[1],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",1);
    //3. 测试 message 长度不一致导致的问题
//    LogI("-----------------------------------\t%d\t---------------------------------------",2);
//    mccp_process_window(flow[2],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",2);
//    LogI("-----------------------------------\t%d\t---------------------------------------",3);
//    mccp_process_window(flow[3],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",3);
    //4. 测试不同的返回消息的处理情况
//    for(i = 4;i< 3 + 6;i++)
//    {
//        LogI("-----------------------------------\t%d\t---------------------------------------",i);
//        mccp_process_window(flow[i],44);
//        LogI("-----------------------------------\t%d\t---------------------------------------",i);
//    }
    //5. 测试mccp message版本错误
//    LogI("-----------------------------------\t%d\t---------------------------------------",9);
//    mccp_process_window(flow[9],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",9);
    //6. 测试session id的长度
//    LogI("-----------------------------------\t%d\t---------------------------------------",10);
//    mccp_process_window(flow[10],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",10);
//    LogI("-----------------------------------\t%d\t---------------------------------------",11);
//    mccp_process_window(flow[11],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",11);
    //7. 测试session id 不匹配的情况
//   g_session_id = 0x2345678;
//    LogI("-----------------------------------\t%d\t---------------------------------------",12);
//    mccp_process_window(flow[12],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",12);
//    g_session_id = 0x12345678;
    //8. result code 长度错误
//    LogI("-----------------------------------\t%d\t---------------------------------------",13);
//    mccp_process_window(flow[13],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",13);
    //9. result code 各种类型的代码值
//    for(i = 14; i< 13 + 12;i++)
//    {
//        LogI("-----------------------------------\t%d\t---------------------------------------",i);
//        mccp_process_window(flow[i],44);
//        LogI("-----------------------------------\t%d\t---------------------------------------",i);
//    }
    //10. tunnel id的长度问题
//    LogI("-----------------------------------\t%d\t---------------------------------------",25);
//    mccp_process_window(flow[25],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",25);


//    LogI("-----------------------------------\t%d\t---------------------------------------",26);
//    mccp_process_window(flow[26],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",26);
    //11. mpgw ip len
//   LogI("-----------------------------------\t%d\t---------------------------------------",27);
//    mccp_process_window(flow[27],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",27);
//    //12. mpgw ip version
//
//     LogI("-----------------------------------\t%d\t---------------------------------------",28);
//    mccp_process_window(flow[28],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",28);
//    //13. mpgw port len
//    LogI("-----------------------------------\t%d\t---------------------------------------",29);
//    mccp_process_window(flow[29],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",29);
//
//    LogI("-----------------------------------\t%d\t---------------------------------------",30);
//    mccp_process_window(flow[30],44);
//    LogI("-----------------------------------\t%d\t---------------------------------------",30);
    //14. ue ip len

    LogI("-----------------------------------\t%d\t---------------------------------------",31);
    mccp_process_window(flow[31],44);
    LogI("-----------------------------------\t%d\t---------------------------------------",31);
    //15. ue ip version
    LogI("-----------------------------------\t%d\t---------------------------------------",32);
    mccp_process_window(flow[32],44);
    LogI("-----------------------------------\t%d\t---------------------------------------",32);
/*
*/
/**************************************************************************************************************/
//    for( i = 1;i< sizeof(flow)/sizeof(flow[1]);i++)
//    {
//        LogI("-----------------------------------%d---------------------------------------",i);
//        g_session_id = 0x12345678;
//        if(i == 12)
//        {
//            g_session_id = 0x23456789;
//        }
//        //LogI("当前长度:%d",sizeof(flow[i]));
//        mccp_process_window(flow[i],44);
//        LogI("-----------------------------------%d---------------------------------------",i);
//    }
    //mccp_process_window(flow,sizeof(flow));
    EXIT_FUNC;
}


void testmutpSend()
{
    unsigned char flow[][14] = {
            //1.正常的数据包
            {0x20,0x00,0x00,0x08,0x12,0x12,0x12,0x12,0x31,0x32,0x33,0x34,0x35,0x00},
            //2. 版本测试
            {0x40,0x00,0x00,0x08,0x12,0x12,0x12,0x12,0x31,0x32,0x33,0x34,0x35,0x00},
            //3. 长度测试
            {0x20,0x00,0x00,0x09,0x12,0x12,0x12,0x12,0x31,0x32,0x33,0x34,0x35,0x00},
            //4. 测试identity check
            {0x21,0x00,0x00,0x08,0x12,0x12,0x12,0x12,0x31,0x32,0x33,0x34,0x35,0x00},
            //5. tunnel id not match
            {0x20,0x00,0x00,0x08,0x12,0x22,0x12,0x12,0x31,0x32,0x33,0x34,0x35,0x00},
    };
    int i = 0;
    for(i = 0;i< sizeof(flow)/sizeof(*flow);i++)
//    for(i = 0;i< 5;i++)
    {
        LogW("================================================================");
        mutp_decode_recv(NULL,flow[i],sizeof(*flow),TRUE);
//        mutp_decode_recv(flow[i],14);
    }
}