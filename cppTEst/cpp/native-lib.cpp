#include "tools/tools.h"
#include "test/test.h"
#include "vpn_tun/vpn_tun_if.h"
#include <arpa/inet.h>
#include "tunnel/tunnel.h"
#include <iostream>
#include <lwip/module.h>
#include <iperf_main.h>
#include "heartbeat/heartbeat.h"
#if !LINUX_PLATFORM
#include <jni.h>
#endif
#if HEARTBEAT_SUPPORT_v02
#include "heartbeat/Heartbeat_v02.h"
#endif
extern int tunUp;
extern mptcp_data_init_V01 gMPTCP_config;
int is_iperf_eixt = 1;

#include "common.h"

extern "C" JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_setLTEFd(JNIEnv *env,
                                                               jobject instance,
                                                               jint fd) {

    // TODO

}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_setWifiFd(JNIEnv *env,
                                                                jobject instance,
                                                                jint fd) {

    // TODO

}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_setWifiIp(JNIEnv *env,
                                                                jobject instance,
                                                                jstring address) {
    char *ip = jstringTostring(env,address );
    gMPTCP_config.wifiIp.addr = htonl(inet_addr(ip));
    mutp_setWifiAddr(ip);
#if WIFI_LTE_SWITCH
    set_wifi_ip(inet_addr(ip));
#endif
    LogI("wifi address:%s", ip);
    free(ip);
}

//void* startCreateInThread(void* data)
//{
//    mutp_creat_socket((char*)data,WIFI);
//    free(data);
//}
extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_setLTEIp(JNIEnv *env,
                                                               jobject instance,
                                                               jstring address) {

    // TODO
    char *ip = jstringTostring(env, address);
    gMPTCP_config.lteIp.addr = htonl(inet_addr(ip));
    mutp_setLteAddr(ip);
    set_lte_ip(inet_addr(ip));
    LogI("lte address:%d",gMPTCP_config.lteIp.addr);
    LogI("lte address:%s", ip);
    free(ip); //free the memory
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_notifyWifiConnect(JNIEnv *env,
                                                                        jobject instance,
                                                                        jint isConnected,
                                                                        jstring ips) {
    char *ip = NULL;
    if (isConnected == 1) {
        if (ips != NULL) {
            ip = jstringTostring(env, ips);
            gMPTCP_config.wifiIp.addr = inet_addr(ip);
            gMPTCP_config.wpriority = 2;
            LogW("WIFI open");
            mutp_setWifiAddr(ip);
        } else {
            LogE("the wifi have been close");
            isSetWifiAddr = 0;
            gMPTCP_config.wpriority = 0;
            /*close_all_wifi_socket();*/
			mutp_close_wifi_or_lte(1);
            LogW("WIFI CLOSE");
            return;
        }
    } else {
        LogE("the wifi have been close");
        isSetWifiAddr = 0;
        gMPTCP_config.wpriority = 0;
        /*close_all_wifi_socket();*/
		mutp_close_wifi_or_lte(1);
        LogW("WIFI CLOSE");
        return;
    }
#if HEARTBEAT_SUPPORT_v02
    setHeartBeatStrategyByNetworkChange(isSetLteAddr,isSetWifiAddr);
#endif
    free(ip);
    ip = NULL;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_notifyLTEConnect(JNIEnv *env,
                                                      jobject instance,
                                                      jint isConnected,
                                                      jstring ips) {
#if !WIFI_LTE_SWITCH
    // TODO
    if (isConnected == 0) {
        /** orgin **/
        /*mutp_destory();
		icmp_destroy();*/
		mutp_all_instance_destory();
        //
        isSetLteAddr = 0;
    } else if (isConnected == 1) {
//        gMPTCP_config.wifi_src_addr.addr = (u32_t) htonl(inet_addr(ip));
        gMPTCP_config.lpriority = 1;
        isSetLteAddr = 1;
    }
#else
    char *ip = NULL;
    if (isConnected == 1) {
        if (ips != NULL) {
            ip = jstringTostring(env, ips);
            gMPTCP_config.lteIp.addr = inet_addr(ip);
            gMPTCP_config.lpriority = 1;
            LogW("lte open");
            mutp_setLteAddr(ip);
        } else {
            LogE("the lte have been close");
            isSetLteAddr = 0;
            gMPTCP_config.lpriority = 0;
            /*close_all_lte_socket();*/
            mutp_close_wifi_or_lte(0);
            LogW("lte CLOSE");
            return;
        }
    } else {
        LogE("the lte have been close");
        isSetLteAddr = 0;
        gMPTCP_config.lpriority = 0;
        /*close_all_lte_socket();*/
        mutp_close_wifi_or_lte(0);
        LogW("lte CLOSE");
        return;
    }
#if HEARTBEAT_SUPPORT_v02
    setHeartBeatStrategyByNetworkChange(isSetLteAddr,isSetWifiAddr);
#endif
    free(ip);
    ip = NULL;
#endif
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_switchHeartBeat(
        JNIEnv *env,
        jobject,
        jint beat){
#if HEARTBEAT_SUPPORT_v02
		switchHeartOpenClose(beat);
#endif
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_native_1rsc_1init(
        JNIEnv *env,
        jobject /* this */,
        jint fd) {
    gMPTCP_config.tunnel_FD = fd;
    ENTER_FUNC;

    if( 0 != tunif_init(&gMPTCP_config,env)) {
        //TODO: destroy MPTCP protocol stack
        return;
    }
    EXIT_FUNC;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_tunnelAuth(
        JNIEnv *env,
        jobject /* this */,
        jint fd) {
    int error = 0/*= tunnelAuth(fd)*/;
    return error;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_mptcpEnd(
        JNIEnv *env,
        jobject /* this */) {
    LogI("stop thread");
    stillRun = 0;//氓聛聹忙颅垄wififd
    //mptcp_end_loop();
    mccp_destory();
    if (ppca_s->mccp_auth == TRUE)
    {
        tunif_end_loop();
        //mutp_all_instance_destory();
    }

    //env->DeleteGlobalRef(gJavaObj);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_startMutp(
        JNIEnv *env,
        jobject /* this */
)
{
    tunif_end_loop();
    int ret =  0;//mutp_start_create_socket();
    return ret;
}

void testMethod() {
    ENTER_FUNC;
    /*============娴嬭瘯mutp==============*/

    /*============娴嬭瘯mutp==============*/

    /*=============娴嬭瘯鍩烘湰鍑芥暟==============*/

//    testDecodeSessionId();
//    testDecodeMcq();
//    testDecodeMpgwIp();
//    testDecodeMpgwPort();
//    testDecodeUeIp();
//    testDecodeResultCode();
//    testDecodeTeId();

    /*=============娴嬭瘯鍩烘湰鍑芥暟==============*/

    /*==========测试PCA的各种数据报文格�?============*/
    //testWithTheCorrectFlow();
//     testPCA_OK();
//     testPCA_version_error();
//     testPCA_message_type_error();
//     testPCA_len_error();
    //testPCA_session_id_error();
//     testPCA_result_code_len_error();
//     testPCA_error_result_code();
//     testPCA1_result_code_error();
//    testPCA_UE_IP_VER_error();
//     testPCA_UE_IP_error();
//     testPCA1_MPGW_IP_ver_error();
//     testPCA1_MPGW_IP_error();
//     testPCA_mpgw_len_error();
//     testPCA_mpgw_port_error();
//     testPCA_mcq_len_error();
//     testPCA_tunnel_id_len_error();


    EXIT_FUNC;
}
/*int mccp_init(char *imsi,char *imei,char *mac,char *auth_server_ip,int port)*/
extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getNativeWorkMode(JNIEnv *env,
                                                                        jobject instance) {

    // TODO
#if LWIP_PERFORMANCE_TEST_ENABLE_VETH0
    return 1;
#else
    return 0;
#endif
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_isNativeMptcpInit(JNIEnv *env,
                                                                        jobject instance) {

    // TODO
    return gMPTCP_config.is_mptcp_init;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_setAuthInfo(
        JNIEnv *env,
        jobject /* this */,
        jstring imsi,
        jstring imei,
        jstring mac,
        jstring auth_server_ip,
        jint port,
        jobject thiz
) {
    //   Session ID  随机�?  (认证几次�?
    //   IMSI  长度  15
    //   IMEI  长度  15
    //   MAC   长度 48
    int ret = 0;

    memset(&gMPTCP_config, 0, sizeof(gMPTCP_config));
    char *pMac = NULL;
    char *pImei = NULL;
    stillRun = 1;//鍋滄wififd
    if (imsi == NULL || auth_server_ip == NULL) {
        LogE("current argument is not correct! file:%s line %d", __FILE__, __LINE__);
        return -1;
    }
    //mac = "12345678a4f5";
    char *pImsi = jstringTostring(env, imsi);
    if(imei != NULL)
    pImei = jstringTostring(env, imei);
    if(mac != NULL)
    pMac = jstringTostring(env, mac);
    char *pAuthSer = jstringTostring(env, auth_server_ip);
    if (gJavaObj != NULL) {
        env->DeleteGlobalRef(gJavaObj);
    }
    gJavaObj = env->NewGlobalRef(thiz);

    global_init_once();

	HeartBeat_Mccp_RegistrationExitSignal();
    ret = mccp_init(pImsi, pImei, pMac, pAuthSer, port);
    //ret = mccp_init(pImsi, NULL, pMac, pAuthSer, port);
    if (ret != 0) {
        goto End;
    }
#if HEARTBEAT_SUPPORT_v02
    /* heart beat times and time interval init*/
    HeartBeatInitDefaultTime();
#endif
    ret = mccp_auth();
    if (ret != 0) {
        goto End;
    }
    /* ====== 娴嬭瘯浠ｇ爜 ======*/
    //UINT8 buff[]={};
    //mccp_process_window();

    //testMethod();//
    /* ====== 娴嬭瘯浠ｇ爜 ======*/
    End:
    //閲婃斁jstringTostring涓彲浠ュ悓鏃舵墦寮€鐩稿簲鐨剆ocket
    FREE(pImsi);
    FREE(pImei);
    FREE(pMac);
    FREE(pAuthSer);
    return ret;
}
/**
 * 寮€鍚浉搴旂殑璁よ瘉
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_startAuth(
        JNIEnv *env,
        jobject) {
    //开始认�?
    //mccp_auth();
    //used for test code

}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_setHeartBeatTimes(JNIEnv *env, jobject obj, jint time){

#if HEARTBEAT_SUPPORT
    heartbeat_set_timesval(time);
#endif
#if HEARTBEAT_SUPPORT_v02
    setBeatTimes(time);
#endif
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_setHeartBeatInteval(JNIEnv *env, jobject obj, jint inteval){
#if HEARTBEAT_SUPPORT
    heartbeat_set_timeval(inteval);
#endif
#if HEARTBEAT_SUPPORT_v02
    setBeatTimeInterval(inteval);
#endif
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_hagError(JNIEnv *env, jobject obj, jint fd){
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_hagOK(JNIEnv *env, jobject obj, jint fd){
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getWifiDownPkgNum(JNIEnv *env, jobject obj){

  int data = 0;
  mutp_get_dataflow_bytype(WIFI_DOWN_PACKAGE,&data);

  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getWifiUpPkgNum(JNIEnv *env, jobject obj){
  int data = 0;
  mutp_get_dataflow_bytype(WIFI_UP_PACKAGE,&data);

  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getWifiDownBytes(JNIEnv *env, jobject obj){
  int data = 0;
  mutp_get_dataflow_bytype(WIFI_DOWN_BYTES,&data);

  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getWifiUpBytes(JNIEnv *env, jobject obj){

  int data = 0;
  mutp_get_dataflow_bytype(WIFI_UP_BYTES,&data);

  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getLteDownPkgNum(JNIEnv *env, jobject obj){
  int data = 0;
  mutp_get_dataflow_bytype(LTE_DOWN_PACKAGE,&data);

  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getLteUpPkgNum(JNIEnv *env, jobject obj){
  int data = 0;
  mutp_get_dataflow_bytype(LTE_UP_PACKAGE,&data);

  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getLteDownBytes(JNIEnv *env, jobject obj){
  int data = 0;
  mutp_get_dataflow_bytype(LTE_DOWN_BYTES,&data);
  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getLteUpBytes(JNIEnv *env, jobject obj){

  int data = 0;
  mutp_get_dataflow_bytype(LTE_UP_BYTES,&data);
  return data;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getLteUpBytesInUdp(JNIEnv *env, jobject obj){
	int data = 0;
	 mutp_get_dataflow_bytype(UDP_LTE_UP_BYTES,&data);
	
	 return data;

}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getLteDownBytesInUdp(JNIEnv *env, jobject obj){

 int data = 0;
 mutp_get_dataflow_bytype(UDP_LTE_DOWN_BYTES,&data);

 return data;

}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getWifiUpBytesInUdp(JNIEnv *env, jobject obj){

 int data = 0;
 mutp_get_dataflow_bytype(UDP_WIFI_UP_BYTES,&data);

 return data;

}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_getWifiDownBytesInUdp(JNIEnv *env, jobject obj){

  int data = 0;
  mutp_get_dataflow_bytype(UDP_WIFI_DOWN_BYTES,&data);

  return data;

}

/*pcap 抓包标志， 0：抓全部， 1：只抓头*/
unsigned char       g_pcap_header_only = 0;
const unsigned int  g_pcap_len = 96;

extern "C"
JNIEXPORT jfloat JNICALL
Java_com_mptcpsdk_natives_VpnNative_getWifiRTT(JNIEnv *env, jobject obj){
    float number = rand() % 101;
    return number;
}

extern "C"
JNIEXPORT jfloat JNICALL
Java_com_mptcpsdk_natives_VpnNative_getLteRTT(JNIEnv *env, jobject obj){
    float number = rand() % 101;
    return number;
}

extern "C"
JNIEXPORT void JNICALL
        Java_com_mptcpsdk_natives_VpnNative_openPcap(JNIEnv *env,
                                                     jobject obj,
                                                     jstring path,
                                                     jstring cmdline){
#if LWIP_PCAP_SUPPORT
    char pcap_file_name[512];
    char *pPath = NULL;
    int i;
    
    /*only one instance work when pcap is setting*/
	if(vpn_pcap_fd >0 )
		return ;

    char *cmdline_str = jstringTostring(env, cmdline);
    if(cmdline_str == NULL)
        return;

    if(0 != strstr(cmdline_str, "-H")) {
        g_pcap_header_only = 1;
    } else{
        g_pcap_header_only = 0;
    }


    pPath = jstringTostring(env,path);
    if(pPath == NULL){
        vpn_pcap_fd = tun_pcap_init((char*)"/sdcard/Android/data/pcap");
        return;
    }
    //__android_log_print(ANDROID_LOG_DEBUG,"Vpn","%s:%d pPath%s",__func__,__LINE__,pPath);
    memset(pcap_file_name, 0x0,512);
	strcpy(pcap_file_name, pPath);
    time_t t = time(NULL);
	char buff1[32]={0};
	strftime(buff1, sizeof(buff1), "%Y-%m-%d-%H%M%S", localtime(&t));
    LogE("tunif_init strftime=%s",buff1);
	for(i=0; i<strlen(buff1);i++){
		if(buff1[i] == '\\' || buff1[i] == '/')
			buff1[i] = '-';
	}
	strcat(pcap_file_name,"/pcap-");
	strcat(pcap_file_name,buff1);
	strcat(pcap_file_name, ".cap");
    vpn_pcap_fd = tun_pcap_init(pcap_file_name);
    FREE(pPath);
    
    FREE(cmdline_str);
#endif
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_closePcap(JNIEnv *env,
                                              jobject obj){
#if LWIP_PCAP_SUPPORT
    tun_pcap_close(vpn_pcap_fd);
#endif
}

extern int LOGOpenOrClose;

/*
### log_level

- debug
- info
- warn
- error
- fatal

Ex:
```--debug-all --warn-all```

### log_module

- proxy
- stack
- tunnel
- sdk
- iperf
- mccp
- udp
- netif
- heartbeat
- vpn_tun
- stk_etharp
- stk_netif
- stk_pbuf
- stk_apilib
- stk_apimsg
- stk_socket
- stk_inet
- stk_ip
- stk_ip_reass
- stk_raw
- stk_mem
- stk_memp
- stk_sys
- stk_timers
- stk_tcp
- stk_tcp_input
- stk_fr
- stk_tcp_rto
- stk_tcp_cwnd
- stk_tcp_wnd
- stk_tcp_output
- stk_tcp_rst
- stk_tcp_qlen
- stk_tcpip
- stk_mp_txrx
- stk_mp_fin
- stk_mp
- stk_err_logging
- stk_mp_txrx_dtl
- stk_mp_proxy
- stk_tcp_two_stack
- stk_traffic
- stk_stream_all
- stk_sack

usage :
```--log_module-[log_level/all]```
Ex:
```--proxy-debug --stack-info --heartbeat-all```
*/

extern "C"
JNIEXPORT void JNICALL
Java_com_mptcpsdk_natives_VpnNative_openLog(JNIEnv *env, jobject obj,jstring cmdline) {

    //char *log_cmd_str = "--proxy-info --proxy-debug --sdk-debug --iperf-debug --stk_tcp_input-debug --debug-all";

    /*每次设置都使用默认值重新初始化日志控制数组*/
    memcpy(g_log_level_ctrl, g_log_level_ctrl_def, sizeof(g_log_level_ctrl));

    char *log_cmd_str = jstringTostring(env, cmdline);
    if(log_cmd_str == NULL)
        return;

/*首先按模块进行日志级别处理*/
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
    if(0 != strstr(log_cmd_str, module_arg"-debug")){ \
        g_log_level_ctrl[E_LOG_LEV_DEBUG][module] = 1; \
    }
    LOG_MODULES
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
    if(0 != strstr(log_cmd_str, module_arg"-info")){ \
        g_log_level_ctrl[E_LOG_LEV_INFO][module] = 1; \
    }
    LOG_MODULES
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
    if(0 != strstr(log_cmd_str, module_arg"-warn")){ \
        g_log_level_ctrl[E_LOG_LEV_WARN][module] = 1; \
    }
    LOG_MODULES
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
    if(0 != strstr(log_cmd_str, module_arg"-error")){ \
        g_log_level_ctrl[E_LOG_LEV_ERR][module] = 1; \
    }
    LOG_MODULES
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
    if(0 != strstr(log_cmd_str, module_arg"-fatal")){ \
        g_log_level_ctrl[E_LOG_LEV_FATAL][module] = 1; \
    }
    LOG_MODULES
#undef LOG_MOD_ITEM

        /*按模块级别进行日志处理*/
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
    if(0 != strstr(log_cmd_str, module_arg"-all")){ \
        g_log_level_ctrl[E_LOG_LEV_DEBUG][module] = 1; \
        g_log_level_ctrl[E_LOG_LEV_INFO][module] = 1; \
        g_log_level_ctrl[E_LOG_LEV_WARN][module] = 1; \
        g_log_level_ctrl[E_LOG_LEV_ERR][module] = 1; \
        g_log_level_ctrl[E_LOG_LEV_FATAL][module] = 1; \
    }
    LOG_MODULES
#undef LOG_MOD_ITEM


    /*按日志级别对所有模块进行处理*/
    if (0 != strstr(log_cmd_str, "--debug-all")) {
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
        g_log_level_ctrl[E_LOG_LEV_DEBUG][module] = 1;
        LOG_MODULES
#undef LOG_MOD_ITEM
    }

    if (0 != strstr(log_cmd_str, "--info-all")) {
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
        g_log_level_ctrl[E_LOG_LEV_INFO][module] = 1;
        LOG_MODULES
#undef LOG_MOD_ITEM
    }

    if (0 != strstr(log_cmd_str, "--warn-all")) {
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
        g_log_level_ctrl[E_LOG_LEV_WARN][module] = 1;
        LOG_MODULES
#undef LOG_MOD_ITEM
    }

    if (0 != strstr(log_cmd_str, "--error-all")) {
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
        g_log_level_ctrl[E_LOG_LEV_ERR][module] = 1;
        LOG_MODULES
#undef LOG_MOD_ITEM
    }

    if (0 != strstr(log_cmd_str, "--fatal-all")) {
#define LOG_MOD_ITEM(module, module_str, module_arg, debug, info, warn, error, fatal)  \
        g_log_level_ctrl[E_LOG_LEV_FATAL][module] = 1;
        LOG_MODULES
#undef LOG_MOD_ITEM
    }

    free(log_cmd_str);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_iperfMptcpMain(
        JNIEnv *env,
        jobject /* this */,
        jobject javaObj,
        jobjectArray strArray) {
    int ret;
    jstring jstr;
    jsize len = env->GetArrayLength(strArray);
    char **pIperfCmd = (char **) malloc(len*sizeof(char *));
    if(NULL ==  pIperfCmd){
        LogE("fail to malloc pIperfCmd");
        return 1;
    }

    for (int i=0 ; i<len; i++) {
        jstr = (jstring) env->GetObjectArrayElement(strArray, i);
        pIperfCmd[i] = (char *) env->GetStringUTFChars(jstr, 0);
    }

    iperfJavaObj = env->NewGlobalRef(javaObj);

	LogD("start iperf_mptcp_main in native_lib ");
	ret = iperf_mptcp_main(len, pIperfCmd);
    free(pIperfCmd);
    pIperfCmd = NULL;
    is_iperf_eixt = 0;
    return ret;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mptcpsdk_natives_VpnNative_iperfMptcpStop(
            JNIEnv *env,
            jobject /* this */) {

    int ret = 0;
    LogD("start iperfMptcpStop() in native_lib ");
    is_iperf_eixt = 1;
    ret = iperf_mptcp_stop();
    LogD("end to iperfMptcpStop() in native_lib, ret=%d", ret);
    return ret;
}
