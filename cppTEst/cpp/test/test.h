//
// Created by ts on 17-4-12.
//

#ifndef MYAPPLICATION_TEST_H
#define MYAPPLICATION_TEST_H

#include <linux/in.h>
#include "../tools/tools.h"
typedef struct __pca_message_body{
    UCHAR version;//0x20
    UCHAR m_type;//102
    USHORT len;// 整个数据包的长度

    /*============session id============*/
    UCHAR sess_type;// 1
    UCHAR sess_len;//4
    UINT  session_id;//12345

    /*=============Rresult code===============*/
    UCHAR rcode_type;// 4
    UCHAR rcode_len;//2
    USHORT rcode;
    /*=============UE IP===============*/
    UCHAR ueip_type;// 1
    UCHAR ueip_len;//5
    UCHAR ver_e;//0x80,128
    UINT ue_ip;//inet_addr 生成
    /*=============MPGW IP===============*/
    UCHAR mpgw_type;// 1
    UCHAR mpgw_len;//5
    UCHAR ver_m;//0x80
    UINT mpgw_ip;//inet_addr 生成
    /*=============MPGW Port===============*/
    UCHAR port_type;// 1
    UCHAR port_len;//2
    USHORT port;//12345
    /*=============MCQ===============*/
    UCHAR mcq_type;// 1
    UCHAR mcq_len;//2
    USHORT mcq;//50
    /*=============TEID===============*/
    UCHAR teid_type;// 1
    UCHAR teid_len;//4
    UINT  tunnel_id;//123456
}PMB;
#ifdef __cplusplus
extern "C" {
#endif
/*========================================================*/
void testDecodeSessionId();

void testDecodeResultCode();

void testDecodeUeIp();

void testDecodeMpgwPort();

void testDecodeMpgwIp();

void testDecodeMcq();

void testDecodeTeId();

void showMessageType(int code);
/*========================================================*/
void testMutpStart();//测试mutp 这个函数不能用，socket创建不和法
/*========================================================*/
void testPCA_OK();
void testPCA_version_error();
void testPCA_message_type_error();
void testPCA_len_error();
void testPCA_session_id_len_error();
void testPCA_session_id_error();
void testPCA_result_code_len_error();
void testPCA_error_result_code();
void testPCA1_result_code_error();
void testPCA_UE_IP_VER_error();
void testPCA_UE_IP_error();
void testPCA1_MPGW_IP_ver_error();
void testPCA1_MPGW_IP_error();
void testPCA_mpgw_len_error();
void testPCA_mpgw_port_error();
void testPCA_mcq_len_error();
void testPCA_tunnel_id_len_error();

void testMutpEncode();
void testMutpDecodeOK();
void testMutpDecodeVersionError();
void testMutpDecodeVersionIcheck();
void testMutpDecodeLenError();
void testMutpDecodeTunnel_error();
void testWithTheCorrectFlow();
void testmutpSend();
#ifdef __cplusplus
}
#endif
#endif //MYAPPLICATION_TEST_H
