#ifndef __MCCP_IF_H__
#define __MCCP_IF_H__

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include "lwip/lwipopts.h"
#if !LINUX_PLATFORM
#include <android/log.h>
#endif
#include <sys/types.h>

#include "../tools/common.h"
#include "../tools/tools.h"

#define MCCP_HEADER_LEN 3
#define MCCP_MESSAGE_HEADER_LEN 4
#define MCCP_MAX_RETRY 5
#define MCCP_VERSION 1
#define MCCP_MAX_PACKET_LEN 1024

extern UINT32 g_session_id;
#ifndef FREE
#define FREE(X)\
 if( (X) != NULL)\
 {\
  free((X)); \
  (X) = NULL; \
 }
#endif
#define FREETLV(X) \
 if( (X) != NULL) \
 { \
  FREE((X)->data); \
  free((X)); \
  (X) = NULL; \
 } \

#define AllocPtlvFail(x, y) \
 if((x) == NULL) \
 { \
  LogE((y)); \
  return NULL; \
 }


#define AllocPtlvDataFail(x, y) \
 if((x)->data == NULL) \
 { \
  LogE((y));\
  FREE((x)); \
  return NULL;\
 }

typedef enum Auth_State {
    Auth_Fail,
    Auth_Success,
    Auth_Close
} AuthState;

typedef enum __mccp_result_code {
    MCCP_SUCCESS = 0,    //success
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
    MCCP_RESERVED,     //used for reserved
    MCCP_MAX_RESULT_CODE = MCCP_RESERVED
} mccp_result_code;

typedef struct __pcr {
    UINT32 session_id;
    char mac[12];
    char imsi[16];
    char imei[16];
    BOOL mccp_is_ready;
} PCR_S;

typedef struct __pca {
    UINT32 session_id;
    UINT32 mccp_ue_ip;
    UINT32 mccp_mpgw_ip;
#ifdef PCA_COMPATIBLE
    UINT32 mccp_mpgw_ip1;
#endif
    UINT16 mccp_mpgw_port;
    UINT16 mccp_max_quantity;
    UINT32 mccp_tunnel_id;
    BOOL mccp_auth;
    mccp_result_code result_code;
} PCA_S;

typedef enum message_type {
    PCR = 101, //policy control request
    PCA,   //policy control answer
    PUR,   //policy update request
    PUA,   //policy update answer
    DSR,      //delete session request
    DSA,       //delete session Answer
    MAX_MESSAGE_TYPE = DSA
} MType;


typedef enum __ie_type {
    SID = 1,    //session id
    TERMINATION_CAUSE, //
    DISCONNECT_CAUSE, //
    RCODE,    //result code
    MSISDN,    //
    IMSI,
    IMEI,
    MAC,
    WHITELIST,
    QOS,
    MPGW_IP,
    MPGW_PORT,
    MCQ,
    TEID,
    UE_IP,
    T_TYPE,
    BUTT,
    MAX_IE_TYPE = BUTT
} IEType;

typedef enum __Cond {
    MUST,
    OPTION,
    COND
} Cond;
typedef struct __OpOF {
    IEType ie;
    Cond cond;
} OpOF;
typedef struct __mccp_flow {
    MType mess;
    OpOF flow[10];
} Mccp_flow;
typedef struct __tlv {
    UINT8 type;    //type
    UINT16 len;   //length
    UINT8 *data; //data
} mccp_tlv;

typedef struct __mccp_message_header {
    UINT8 spare:5;
    UINT8 version:3;
    UINT8 type;
    UINT16 len;
} mccp_message_header;

typedef struct __pcr_header {
    mccp_tlv sid;
    mccp_tlv imsi;
    mccp_tlv imei;
    mccp_tlv mac;
} PCR_Header;

typedef struct __pca_header {
    mccp_tlv sid; //session id
    mccp_tlv rcode; //result code
    mccp_tlv uip; //ue ip
    mccp_tlv mip; //mpgw ip
    mccp_tlv mport; //mpgw port
    mccp_tlv mcq;   //max connect quantity
    mccp_tlv tid;   //tunnel id
} PCA_Header;


#ifdef __cplusplus
extern "C" {
#endif
extern PCA_S *ppca_s;

int mccp_init(char *imsi, char *imei, char *mac, char *auth_server_ip, int port);

void HeartBeat_Mccp_RegistrationExitSignal();

int mccp_initWithUE(char *mac, char *imsi, char *imei);

int mccp_auth();

UINT32 mccp_create_session_id();

mccp_tlv *encode_session_id();

mccp_tlv *encode_imsi();

mccp_tlv *encode_imei();

mccp_tlv *encode_mac();

int translate_str_to_int_array(UINT8 *array, char *str, int len);

int translate_array_to_bcd_code(UINT8 *value, UINT8 *value_data, int len);

int translate_array_to_bcd_code(UINT8 *value, UINT8 *value_data, int len);

UINT8 translate_two_num_to_bcd_code_in_order(UINT8 low, UINT8 high);

UINT8 translate_two_num_to_bcd_code(UINT8 low, UINT8 high);


mccp_result_code decode_result_code(mccp_tlv *prcode);

mccp_message_header *decode_message_header(UINT8 *pMsg, ssize_t len);

mccp_tlv *decode_mccp_tlv(UINT8 *pMsg, int offset_len);

UINT32 decode_session_id(mccp_tlv *psid);

UINT32 decode_ue_ip(mccp_tlv *puIp);

UINT32 decode_mpgw_ip(mccp_tlv *pMIp);

UINT32 decode_tunnel_id(mccp_tlv *pTid);

UINT16 decode_mpgw_port(mccp_tlv *pMport);

UINT16 decode_max_connect_quantity(mccp_tlv *pMcq);

void *mccp_send_value(void *data);

void *mccp_process_window(UINT8 *pMsg, ssize_t len);

int mccp_destory();

void mccp_handle_pca_message(UINT8 *pMsg, mccp_message_header *pMessageHeader);

void setAuthState(AuthState state, UINT32 mpgwIp, int port);

void set_lte_ip(UINT32 addr);

#if WIFI_LTE_SWITCH
void set_wifi_ip(UINT32 addr);
#endif
#ifdef __cplusplus
}
#endif

#endif
