#include "mccp.h"
/*===========================================================*/
#include "lwip/lwipopts.h"
#include "../tunnel/tunnel.h"
#include "../vpn_tun/vpn_tun_if.h"
#include "../tools/irandom.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include "lwip/sys.h"
#if LINUX_PLATFORM
#include <unistd.h>
#define gettid getpid
#endif
#if HEARTBEAT_SUPPORT_v02
#include "../heartbeat/Heartbeat_v02.h"
#endif

#undef LOG_MODULE_CURRENT
#define LOG_MODULE_CURRENT  E_LOG_MODULE_MCCP
/*===========================================================*/
//===================================================
/*===========================mpd-tc GLOBAL VARIABLE Start =======================================*/
PCR_S *ppcr_s = NULL;//used for ppcr
PCA_S pca_s;
PCA_S *ppca_s = &pca_s;
int mccp_socket = -1;//used for transmisstion the auth info
UINT8 *sendData = NULL;
int requestLen = 0;
UINT32 g_session_id = 0;
UINT32 index_of_sid = 0;
pthread_attr_t attr;
pthread_t send_thread;
static pthread_t heartbeat_mccp_thread = 0;

uint32_t lte_ip;
#if WIFI_LTE_SWITCH
uint32_t wifi_ip;
u16_t wifi_port = 0;
uint32_t isBindLte = 0;
uint32_t isBindWifi = 0;
#endif
u16_t lte_port = 0;
struct sockaddr_in s_addr;
char mccp_result_code_msg[][50] = {
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


/*
used for test
int port= 8080;
int server_ip[16]="192.168.0.1";
*/
/***
 * 下方的数组使用MAX_IE_TYPE 作为结束符号
 */

Mccp_flow *mFlow = NULL;
extern mptcp_data_init_V01 gMPTCP_config;

void *heartbeat_mccp_sends_value(void *data);
/*===========================mpd-tc GLOBAL VARIABLE END =======================================*/

int translate_array_to_bcd_code_in_order(UINT8 *value, UINT8 *value_data, int len);

//===================================================
/**
 * 认证信息的初始化
 * @param imsi
 * @param imei
 * @param mac
 * @param auth_server_ip 认证服务器的ip地址
 * @param port          认证服务器的port
 * @return 认证信息是否初始化完??
 */
/*===========================================================================

  FUNCTION
  mccp_init

  DESCRIPTION
  use this function to init the de mccp module

  PARAMETERS
  char *imsi,           imsi of the ue
  char *imei,           imei of the ue
  char *mac,            mac of the ue
  char *auth_server_ip, the auth server ip
  int port              the auth server port

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES

  SIDE EFFECTS
  if the function fails,the tun can't be up.
===========================================================================*/
int mccp_init(char *imsi, char *imei, char *mac, char *auth_server_ip, int port) {
    int ret = 0;
    ENTER_FUNC;
    if (imsi == NULL || auth_server_ip == NULL || port < 1024) {
        LogE("the argument of fuction %s is invalid.imsi:%s,imei:%s,mac:%s,auth_server_ip:%s,port:%d",
             __func__, imsi, imei, mac, auth_server_ip, port);
        goto End;
    }
    ret = mccp_initWithUE(mac, imsi, imei);
    if (ret != 0) {
        goto End;
    }

    memset(ppca_s, 0, sizeof(PCA_S));

#if !WIFI_LTE_SWITCH
    LogD("bind LTE to send PCR success");
    if (bindNetworkToHandlePacketThoughtJavaInMain(NULL, 1, 0) != 0) {
        LogE("bind lte to handle PCR message failse");
        goto End;
    }
#else
    if (isSetLteAddr) {
        if (bindNetworkToHandlePacketThoughtJavaInMain(NULL, 1, 0) == 0) {
            isBindLte = 1;
            isBindWifi = 0;
            LogE("bind LTE interface to send PCR message");
        } else {
            LogE("bind lte to handle PCR message failse");
            goto End;
        }
    }else if (isSetWifiAddr && !isSetLteAddr) {
        if (bindNetworkToHandlePacketThoughtJavaInMain(NULL, 0, 1) == 0) {
            isBindWifi = 1;
            isBindLte = 0;
            LogE("bind wifi interface to send PCR message");
        } else {
            LogE("bind wifi to handle PCR message failse");
            goto End;
        }
    }
#endif

    mccp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (mccp_socket < 0) {
        LogE("create socket failed:%s", strerror(errno));
        goto End;
    }
    struct sockaddr_in local_addr;
    memset(&local_addr,0,sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = 0;
#if !WIFI_LTE_SWITCH
    local_addr.sin_addr.s_addr = lte_ip;
#else
    LogE("isBindWifi:%d isBindLte:%d",isBindWifi,isBindLte);
    if(isBindLte) {
        local_addr.sin_addr.s_addr = lte_ip;
    }else if(isBindWifi) {
        local_addr.sin_addr.s_addr = wifi_ip;
    }
#endif
    LogE("lte ip address:%d lte_ip:%d wifi_ip:%d", local_addr.sin_addr.s_addr, lte_ip, wifi_ip);
    ret = bind(mccp_socket, (struct sockaddr *) &local_addr, sizeof(local_addr));
    if (ret != 0) {
        LogE("Bind to LTE to send PCR, but bind fails.:%s", strerror(errno));
        close(mccp_socket);
        mccp_socket = -1;
        goto End;
    }

#if !WIFI_LTE_SWITCH
    if(bindNetworkToHandlePacketThoughtJavaInMain(NULL,1,0) != 0)
    {
        LogE("bind lte to handle PCR message failse");
        goto End;
    }
#else
    if(isBindLte) {
        if(bindNetworkToHandlePacketThoughtJavaInMain(NULL,1,0) != 0)
        {
            LogE("bind lte to handle PCR message failse");
            goto End;
        }
    }else if(isBindWifi) {
        if(bindNetworkToHandlePacketThoughtJavaInMain(NULL,0,1) != 0)
        {
            LogE("bind wifi to handle PCR message failse");
            goto End;
        }
    }
#endif

#if !WIFI_LTE_SWITCH
    lte_port = local_addr.sin_port;
#else
    if(isBindLte) {
        lte_port = local_addr.sin_port;
    }else if(isBindWifi) {
        wifi_port = local_addr.sin_port;
    }
#endif

    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    s_addr.sin_addr.s_addr = inet_addr(auth_server_ip);

    ppcr_s->mccp_is_ready = TRUE;
    ppca_s->mccp_auth = FALSE;

    EXIT_FUNC;
    return 0;
    End:
    EXIT_FUNC;
    return -1;
}

/**
 * 初始化认证时需要发送的一系列与手机相关的参数
 * @param mac
 * @param imsi
 * @param imei
 * @return 参数是否OK
 */
/*===========================================================================

  FUNCTION
  mccp_initWithUE

  DESCRIPTION
  init with the ue info,the mccp need imsi imei,and mac

  PARAMETERS
  char *mac,   the mac address
  char *imsi,  the imsi of ue
  char *imei   the imei of the ue
  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
  if this function fails the tun iface can't be up.
===========================================================================*/
int mccp_initWithUE(char *mac, char *imsi, char *imei) {
    int ret = 0;

    ENTER_FUNC;
    if (imsi == NULL) {
        LogE("current function is mccp_init,the argument is invalid");
        ret = -1;
        goto End;
    }
    ppcr_s = (PCR_S *) malloc(sizeof(PCR_S));
    memset(ppcr_s, 0, sizeof(PCR_S));

    //init mac
    if (mac != NULL) {
        memcpy(ppcr_s->mac, mac, sizeof(ppcr_s->mac));// the length may to long
    }
    //init imsi
    memcpy(ppcr_s->imsi, imsi, sizeof(ppcr_s->imsi));
    //init imei
    if (imei != NULL) {
        memcpy(ppcr_s->imei, imei, sizeof(ppcr_s->imei));
    }
    ppcr_s->session_id = mccp_create_session_id();
    g_session_id = ppcr_s->session_id;
    if (imsi != NULL) {
        LogD("mccp init the mac %s imei %s imsi %s", mac, imei, imsi);
    } else {
        LogE("mccp init the mac %s imei %p imsi %s", mac, imei, imsi);
    }

    EXIT_FUNC;
    return ret;
    End:
    EXIT_FUNC;
    FREE(ppcr_s);
    return ret;
}

/*===========================================================================

  FUNCTION
  mccp_auth

  DESCRIPTION
  use this function to auth

  PARAMETERS
  None

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  if this function fails the tun iface can't be up.
===========================================================================*/
int mccp_auth() {
    int ret = 0;
    UINT8 recv[MCCP_MAX_PACKET_LEN] = {0};
    UINT8 *temp = NULL;
    UINT32 offset_len = 0;
    UINT8 version = 1;
    PCR_Header pcrHv;
    PCR_Header *pcrHeader = &pcrHv;
    PCR_Header *pcrTempHeader = NULL;
    int i = 0;
    int number = 4; //sid ,imsi imei,mac header len number

    mccp_tlv *pSid = NULL;
    mccp_tlv *pImsi = NULL;
    mccp_tlv *pImei = NULL;
    mccp_tlv *pMac = NULL;

    PCA_Header pcaHv;
    PCA_Header *pcaHeader = &pcaHv;


    mccp_message_header mmHeader;
    mccp_message_header *pmHeader = &mmHeader;

    ENTER_FUNC;
    requestLen = 0;//len initial
    if (ppcr_s == NULL || ppcr_s->mccp_is_ready == FALSE) {
        LogE("ppcr_s is a null pointer or PCR is not ready");
        return -1;
    }
    LogD("mccp auth start");

    memset(pmHeader, 0, sizeof(mmHeader));
    version = MCCP_VERSION;
    pmHeader->version = MCCP_VERSION;
    pmHeader->type = PCR;
    pmHeader->len = 0; //init the header,the len will be init later.

    pSid = encode_session_id();
    pImei = encode_imei();
    pImsi = encode_imsi();
    pMac = encode_mac();

    if (pSid == NULL || pImsi == NULL) {
        LogE("one or more than one in encode the session id ,Imsi ,Imei and Mac is fail");
        // there we neeed to free the data
        ret = -1;
        goto End;
    }

    memset(pcrHeader, 0, sizeof(PCR_Header));

    memcpy(&(pcrHeader->sid), pSid, sizeof(pcrHeader->sid));
    LogD("sid len: %d", ntohs(pcrHeader->sid.len));
    if (pMac != NULL) {
        memcpy(&(pcrHeader->mac), pMac, sizeof(pcrHeader->mac));
        LogI("mac len:%d", ntohs(pcrHeader->mac.len));
    } else {
        number--;//MCCP_header number -1
    }
    memcpy(&(pcrHeader->imsi), pImsi, sizeof(pcrHeader->imsi));
    LogD("imsi len:%d", ntohs(pcrHeader->imsi.len));
    if (pImei != NULL) {
        memcpy(&(pcrHeader->imei), pImei, sizeof(pcrHeader->imei));
        LogI("imei len:%d", ntohs(pcrHeader->imei.len));
    } else {
        number--; //MCCP_header number -1
    }
    LogD("number :%d", number);
    requestLen =
            MCCP_MESSAGE_HEADER_LEN + MCCP_HEADER_LEN * number + ntohs (pSid->len) +
            (pImei == NULL ? 0 : ntohs (pImei->len)) +
            ntohs (pImsi->len) + (pMac == NULL ? 0 : ntohs (pMac->len));
    pmHeader->len = htons(requestLen);
    LogD("the length of PCR :%d", requestLen);
    LogD("the version of PCR :%d", pmHeader->version);

    //malloc the data buff used to send auth info
    sendData = (UINT8 *) malloc(sizeof(UINT8) * requestLen);
    if (sendData == NULL) {
        // there we neeed to free the data and imei imsi and so on
        ret = -1;
        goto End;
    }

    temp = sendData;

    //1. copy the data of message header
    memcpy(temp, pmHeader, sizeof(mccp_message_header));
    temp += sizeof(mccp_message_header);
    //2. session id
    *temp++ = pSid->type;
    *(USHORT *) (temp) = pSid->len;
    temp += MCCP_HEADER_LEN - 1;
    index_of_sid = temp - sendData;
    memcpy(temp, pSid->data, ntohs(pSid->len));
    temp += ntohs(pSid->len);
    //LogI("session id len: %d",ntohs(pSid->len));
    //3. imsi
    *temp++ = pImsi->type;
    *(USHORT *) (temp) = pImsi->len;
    temp += MCCP_HEADER_LEN - 1;

    memcpy(temp, pImsi->data, ntohs(pImsi->len));
    temp += ntohs(pImsi->len);
    LogD("imsi len: %d", ntohs(pImsi->len));
    //4. Imei
    if (pImei != NULL) {
        *temp++ = pImei->type;
        *(USHORT *) (temp) = pImei->len;
        temp += MCCP_HEADER_LEN - 1;

        memcpy(temp, pImei->data, ntohs(pImei->len));
        temp += ntohs(pImei->len);
        LogI("imei: %d", ntohs(pImei->len));
    }
    //5. Mac
    if (pMac != NULL) {
        //5. mac
        *temp++ = pMac->type;
        *(USHORT *) (temp) = pMac->len;
        temp += MCCP_HEADER_LEN - 1;
        memcpy(temp, pMac->data, ntohs(pMac->len));
        temp += ntohs(pMac->len);
        LogI("session id len: %d", ntohs(pMac->len));
    }
    LogD("copy data to send data over");

    for (i = 0; i < requestLen; i++) {
        LogI("the %d bit value is :%X", i, sendData[i]);
    }
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    LogI("mccp_send_value ");
    pthread_create(&send_thread, &attr, mccp_send_value, NULL);
#if HEARTBEAT_SUPPORT_v02
    HeartBeatInitDefaultTime();
#endif
    End:
    FREE(ppcr_s);
    FREETLV(pSid);
    FREETLV(pImsi);
    FREETLV(pImei);
    FREETLV(pMac);
    EXIT_FUNC;
    return ret;
}

/*===========================================================================

  FUNCTION
  mccp_create_session_id

  DESCRIPTION
  create a session id different with the before

  PARAMETERS
  None

  RETURN VALUE
  if return 0, call this function fails
  return the session id

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
UINT32 mccp_create_session_id() {
    UINT32 id = 0;
    //time 2^22 = 4194304
    UINT32 time_mask = 0x2FFFFF;
    UINT32 random_mask = 0x02FF;

    static UINT32 static_random = 0;

    UINT32 random = 0;
    UINT32 mills = (UINT32) time(NULL);

    ENTER_FUNC;
    id += ((mills & time_mask) << 10);
    RAN:
    srand((unsigned int) time(NULL));
    random =  (UINT32)(read_random()% 1024);
    if (random == static_random) {
        static_random = random;
        sleep(1);
        goto RAN;
    }
    static_random = random;
    id += (random & random_mask);
    LogD("current session id : %X || %d", id, id);
    EXIT_FUNC;
    return htonl(id);
}

/*===========================================================================

  FUNCTION
  encode_session_id

  DESCRIPTION
  encode the session id to a tlv format

  PARAMETERS
  None

  RETURN VALUE
  The tlv format of the session id

  DEPENDENCIES
  if the mccp is ready equals false, this function will be fails.

  SIDE EFFECTS
===========================================================================*/
mccp_tlv *encode_session_id() {
    mccp_tlv *pTlv = NULL;

    ENTER_FUNC;

    if (ppcr_s == NULL || ppcr_s->mccp_is_ready == FALSE) {
        LogE("we need do mccp init");
        return NULL;
    }

    pTlv = (mccp_tlv *) malloc(sizeof(mccp_tlv));
    AllocPtlvFail(pTlv, "encode malloc the session id fails");
    memset(pTlv, 0, sizeof(mccp_tlv));
    pTlv->data = (UINT8 *) malloc(sizeof(UINT8) * 4);//session id 4 byte
    AllocPtlvDataFail(pTlv, "alloc the session id data fails");

    memset(pTlv, 0, sizeof(ppcr_s->session_id));
    pTlv->len = htons(sizeof(ppcr_s->session_id));
    pTlv->type = SID;
    LogD("current session id:%d | %X", ppcr_s->session_id, ppcr_s->session_id);
    ppcr_s->session_id = htonl(ppcr_s->session_id);
    memcpy(pTlv->data, &(ppcr_s->session_id), sizeof(UINT8) * 4); //we need to copy the value
    LogD("current session id TLV len:%X", pTlv->len);
    EXIT_FUNC;
    return pTlv;
}

/*===========================================================================

  FUNCTION
  encode_imsi

  DESCRIPTION
  encode the imsi to a tlv format

  PARAMETERS
  None

  RETURN VALUE
  The tvl format for imsi

  DEPENDENCIES
  if the mccp is ready equals false, this function will be fails.

  SIDE EFFECTS
===========================================================================*/
mccp_tlv *encode_imsi() {
    mccp_tlv *pTlv = NULL;
    UINT8 imsi[16] = {0};
    UINT8 imsi_data[8] = {0};
    int ret = 0;

    ENTER_FUNC;

    if (ppcr_s == NULL || ppcr_s->mccp_is_ready == FALSE) {
        LogE("we need do mccp init");
        return NULL;
    }
    pTlv = (mccp_tlv *) malloc(sizeof(mccp_tlv));
    AllocPtlvFail(pTlv, "encode malloc the session id fails");
    memset(pTlv, 0, sizeof(mccp_tlv));
    pTlv->data = (UINT8 *) malloc(sizeof(UINT8) * 8);//imsi is 15 byte,use BCD code to 8 byte
    AllocPtlvDataFail(pTlv, "alloc the session id data fails");


    memset(imsi, 0xf, 16);
    memset(imsi_data, 0, 8);
    memset(pTlv->data, 0, 8);

    ret = translate_str_to_int_array(imsi, ppcr_s->imsi, 16);
    if (ret != 0) {
        FREETLV(pTlv);
        return pTlv;
    }
    ret = translate_array_to_bcd_code(imsi, imsi_data, (sizeof(imsi) + 1) / 2);
    if (ret != 0) {
        FREETLV(pTlv);
        return pTlv;
    }
    pTlv->len = htons(8);
    pTlv->type = IMSI;
    memcpy(pTlv->data, imsi_data, 8);
    LogD("current imsi len:%X", pTlv->len);
    EXIT_FUNC;
    return pTlv;
}

/*===========================================================================

  FUNCTION
  encode_imei

  DESCRIPTION
  encode the imei to a tlv format

  PARAMETERS
  None

  RETURN VALUE
  The tvl format for imei

  DEPENDENCIES
  if the mccp is ready equals false, this function will be fails.

  SIDE EFFECTS
  None
===========================================================================*/
mccp_tlv *encode_imei() {
    mccp_tlv *pTlv = NULL;
    UINT8 imei[16] = {0};
    UINT8 imei_data[8] = {0};
    int ret = 0;

    ENTER_FUNC;
    if (ppcr_s == NULL || ppcr_s->mccp_is_ready == FALSE) {
        LogE("we need do mccp init");
        return NULL;
    }
    if (ppcr_s->imei[0] == '\0') {
        LogE("imei is null");
        return NULL;
    }
    pTlv = (mccp_tlv *) malloc(sizeof(mccp_tlv));
    AllocPtlvFail(pTlv, "encode malloc the session id fails");
    memset(pTlv, 0, sizeof(mccp_tlv));
    pTlv->data = (UINT8 *) malloc(sizeof(UINT8) * 8);//imsi is 15 byte,use BCD code to 8 byte
    //AllocPtlvDataFail(pTlv,"alloc the session id data fails");
    if (pTlv->data == NULL) {
        FREE(pTlv);
        LogE("alloc the imei data fails");
        goto End;
    }

    memset(imei, 0xf, 16);
    memset(imei_data, 0, 8);
    memset(pTlv->data, 0, 8);

    ret = translate_str_to_int_array(imei, ppcr_s->imei, 16);
    if (ret != 0) {
        FREETLV(pTlv);
        LogE("alloc space fail in func %s", __func__);
        return pTlv;
    }
    ret = translate_array_to_bcd_code(imei, imei_data, (sizeof(imei) + 1) / 2);
    if (ret != 0) {
        FREETLV(pTlv);
        return pTlv;
    }
    pTlv->len = htons(8);
    pTlv->type = IMEI;
    memcpy(pTlv->data, imei_data, 8);

    LogD("current imei TLV len:%X", pTlv->len);
    EXIT_FUNC;

    return pTlv;
    End:
    EXIT_FUNC;
    return NULL;
}

/*===========================================================================

  FUNCTION
  encode_mac

  DESCRIPTION
  encode the mac to a tlv format

  PARAMETERS
  None

  RETURN VALUE
  The tvl format for mac

  DEPENDENCIES
  if the mccp is ready equals false, this function will be fails.

  SIDE EFFECTS
  None

===========================================================================*/
mccp_tlv *encode_mac() {
    mccp_tlv *pTlv = NULL;
    UINT8 mac[12] = {0};
    UINT8 mac_data[6] = {0};
    int ret = 0;

    ENTER_FUNC;

    if (ppcr_s == NULL || ppcr_s->mccp_is_ready == FALSE) {
        LogE("we need do mccp init");
        return NULL;
    }
    if (ppcr_s->mac[0] == '\0') {
        LogE("mac is null");
        return NULL;
    }
    pTlv = (mccp_tlv *) malloc(sizeof(mccp_tlv));
    AllocPtlvFail(pTlv, "encode malloc the session id fails");
    memset(pTlv, 0, sizeof(mccp_tlv));
    pTlv->data = (UINT8 *) malloc(sizeof(UINT8) * 6);//imsi is 15 byte,use BCD code to 8 byte
    AllocPtlvDataFail(pTlv, "alloc the session id data fails");

    memset(mac, 0, 12);
    memset(mac_data, 0, 6);
    memset(pTlv->data, 0, 6);

    ret = translate_str_to_int_array(mac, ppcr_s->mac, 12);
    if (ret != 0) {
        FREETLV(pTlv);
        return pTlv;
    }
    ret = translate_array_to_bcd_code_in_order(mac, mac_data, (sizeof(mac) + 1) / 2);
    if (ret != 0) {
        FREETLV(pTlv);
        return pTlv;
    }
    pTlv->len = htons(6);
    pTlv->type = MAC;
    memcpy(pTlv->data, mac_data, 6);
    LogD("current mac TLV len:%X", pTlv->len);
    EXIT_FUNC;
    return pTlv;
}

/*===========================================================================

  FUNCTION
  translate_str_to_int_array

  DESCRIPTION
  translate a string to a (int value)array

  PARAMETERS
  UINT8 *array  (int value)array
  char *str     the string
  int len       the len of the string

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  attention: the array len need >= len of the string

  SIDE EFFECTS
  None
===========================================================================*/
int translate_str_to_int_array(UINT8 *array, char *str, int len) {
    int ret = 0;
    int i = 0;
    ENTER_FUNC;
    if (array == NULL || str == NULL || len < 0) {
        LogE("the argument of %s is invalid,array:%p,str:%s,len:%d", __func__, array, str, len);
        return -1;
    }
    for (i = 0; i < len; i++) {
        if (str[i] >= '0' && str[i] <= '9')
            array[i] = str[i] - '0';
        else if (str[i] >= 'a' && str[i] <= 'f')
            array[i] = str[i] - 'a' + 10;
        else if (str[i] >= 'A' && str[i] <= 'F')
            array[i] = str[i] - 'A' + 10;
        LogD("The %d of the int array:%d", i, array[i]);
    }
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
  translate_array_to_bcd_code

  DESCRIPTION
  translate the int value to the bcd code array

  PARAMETERS
  UINT8 *value          the value is the int value array
  UINT8 *value_data     the value data is the destination of the bcd code
  int len               the len of the bcd code

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  the value_data len is half to value array.

  SIDE EFFECTS
  None
===========================================================================*/
int translate_array_to_bcd_code(UINT8 *value, UINT8 *value_data, int len) {
    int ret = 0;
    int i = 0;
    ENTER_FUNC;
    if (value == NULL || value_data == NULL || len < 0) {
        LogE("the argument of %s is invalid,value:%p,value_data:%p,len:%d", __func__, value,
             value_data, len);
        return -1;
    }
    for (i = 0; i < len; i++) {
        value_data[i] = translate_two_num_to_bcd_code(value[2 * i], value[2 * i + 1]);
        LogD("the %d of bcd code:%X", i, value_data[i]);
    }
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
    translate_array_to_bcd_code_in_order

  DESCRIPTION
    translate the string to a bcd code

  PARAMETERS
    UINT8 *value            input string  (len = 2n)
    UINT8 *value_data       output str    (len = n)
    int len                 output str len (len = n)

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int translate_array_to_bcd_code_in_order(UINT8 *value, UINT8 *value_data, int len) {
    int ret = 0;
    int i = 0;
    ENTER_FUNC;
    if (value == NULL || value_data == NULL || len < 0) {
        LogE("the argument of %s is invalid,value:%p,value_data:%p,len:%d", __func__, value,
             value_data, len);
        return -1;
    }
    for (i = 0; i < len; i++) {
        value_data[i] = translate_two_num_to_bcd_code_in_order(value[2 * i], value[2 * i + 1]);
        LogD("the %d of bcd code:%X", i, value_data[i]);
    }
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
  translate_two_num_to_bcd_code

  DESCRIPTION
  use this function to make 2 number(0~15) to merge to a 8 bit number
  it will make 2 and 5 to 52

  PARAMETERS
  UINT8 low     it's the low bit of the number
  UINT8 high    it's the hight bit of the number

  RETURN VALUE
  return the merge number

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
UINT8 translate_two_num_to_bcd_code(UINT8 low, UINT8 high) {
    return (low & 0x0f) + (high << 4);
}

/*===========================================================================

  FUNCTION
  translate the number to bcd code in other order

  DESCRIPTION
  use this function to make 2 number(0~15) to merge to a 8 bit number
  it will make 2 and 5 to 25

  PARAMETERS
  UINT8 low     it's the high bit of the number
  UINT8 high    it's the low bit of the number

  RETURN VALUE
  return the merge number

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
UINT8 translate_two_num_to_bcd_code_in_order(UINT8 low, UINT8 high) {
    return (high & 0x0f) + (low << 4);
}

/*===========================================================================

  FUNCTION
  decode_result_code

  DESCRIPTION
  decode the tlv type as the result code

  PARAMETERS
  mccp_tlv *prcode

  RETURN VALUE
  the result code of the auth

  DEPENDENCIES
  we have decode the type.

  SIDE EFFECTS
  None
===========================================================================*/
mccp_result_code decode_result_code(mccp_tlv *prcode) {
    mccp_result_code code = MCCP_MAX_RESULT_CODE;

    ENTER_FUNC;
    if (prcode == NULL || prcode->type != RCODE || prcode->data == NULL) {
        LogE("when decode result code,we need a commplete tlv value");
        goto End;
    }
    if (prcode->len != 2) {
        LogE("result code len error!");
    }
    //memcpy(&code, prcode->data, prcode->len);
    code = (mccp_result_code)ntohs(*(USHORT *) prcode->data);
    //code = *(UINT8*)(prcode->data);
    LogD("currrent result code:%d", code);
    if (code > MCCP_MAX_RESULT_CODE) {
        LogE("current code is not support");
        goto End;
    }
    LogD("current result code:%s", mccp_result_code_msg[code]);
    End:
    EXIT_FUNC;
    return code;

}

/*===========================================================================

  FUNCTION
  decode_message_header

  DESCRIPTION
  decode the msg header.

  PARAMETERS
  UINT8 *pMsg   the message
  ssize_t len  the message len

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  decode the message header when we have recv the PCA message from the work

  SIDE EFFECTS
  None
===========================================================================*/
mccp_message_header *decode_message_header(UINT8 *pMsg, ssize_t len) {
    mccp_message_header *pHeader = NULL;
    ENTER_FUNC;
    if (pMsg == NULL) {
        LogE("invalid pMsg for message header");
        goto End;
    }
    pHeader = (mccp_message_header *) malloc(sizeof(mccp_message_header));
    if (pHeader == NULL) {
        LogE("the error is not ok,may pHeader == NULL");
        return NULL;
    }
    memset(pHeader, 0, sizeof(mccp_message_header));
    pHeader->version = (pMsg[0] & 0xe0) >> 5;
    pHeader->type = pMsg[1];
    pHeader->len = ntohs(*(USHORT*)(pMsg+ 2));
    if (pHeader->len != len)
    {
        LogE("the len error,len must in 0 ~ %d,but current len: %d", (int) len, pHeader->len);
        FREE(pHeader);
        return NULL;
    }
    if (pHeader->version != MCCP_VERSION) {
        LogE("current version is %d,but current we don't support", pHeader->version);
        FREE(pHeader);
        return NULL;
    }
    LogD("current MCCP version %d", pHeader->version);
    EXIT_FUNC;
    return pHeader;
    End:
    EXIT_FUNC;
    return pHeader;
}

/*===========================================================================

  FUNCTION
  decode_mccp_tlv

  DESCRIPTION
  According to the offset len ,decode the msg as tlv.

  PARAMETERS
  UINT8 *pMsg       the msg need to be decode
  int offset_len    the offset of the msg,we can get the start of the msg.

  RETURN VALUE
  the tlv decode from the pMsg

  DEPENDENCIES
  recv the msg,decode the message header then decode the tlv.

  SIDE EFFECTS
  None
===========================================================================*/
mccp_tlv *decode_mccp_tlv(UINT8 *pMsg, int offset_len) {
    mccp_tlv *pTlv = NULL;
    UINT8 *pTemp = NULL;

    if (pMsg == NULL || offset_len < 0) {
        LogE("the argument of %s is invalid,pMsg:%p,offset_len:%d", __func__, pMsg, offset_len);
        goto End;
    }
    pTlv = (mccp_tlv *) malloc(sizeof(mccp_tlv));

    if (pTlv == NULL) {
        LogE("the space is not enough!");
        goto End;
    }
    memset(pTlv, 0, sizeof(mccp_tlv));

    pTemp = pMsg + offset_len;

    //memcpy(pTlv,pTemp,MCCP_HEADER_LEN);
    pTlv->type = (IEType) pTemp[0];
    pTlv->len = ntohs(*(USHORT *) (pTemp + 1));
    pTlv->data = (UINT8 *) malloc(pTlv->len);
    if (pTlv->data == NULL) {
        LogE("the space is not enough!");
        FREE(pTlv);
        goto End;
    }
    memset(pTlv->data, 0, pTlv->len);
    memcpy(pTlv->data, pTemp + MCCP_HEADER_LEN, pTlv->len);

    EXIT_FUNC;
    return pTlv;
    End:
    EXIT_FUNC;
    return pTlv;
}

/*===========================================================================

  FUNCTION
  decode_session_id

  DESCRIPTION
  decode the tlv as the session id

  PARAMETERS
  mccp_tlv *psid

  RETURN VALUE
  return the session id of the tlv

  DEPENDENCIES
  the Tlv message have correct message type and value

  SIDE EFFECTS
  None
===========================================================================*/
UINT32 decode_session_id(mccp_tlv *psid) {
    UINT32 id = 0;
    ENTER_FUNC;
    if (psid == NULL || psid->type != SID || psid->data == NULL) {
        LogE("the argument of func %s is not invalid,psid:%p,pSid->data:%p", __func__, psid,
             psid->data);
        goto End;
    }
    if (psid->len < 4) {
        LogE("current len is a error len:%d", psid->len);
        goto End;
    }
    id = ntohl(*(UINT32 *) (psid->data));

    LogD("decode_session_id current session id : %d |0x%X", htonl(id), htonl(id));
//    if( id != g_session_id)
//    {
//        LogE("session id is not match");
//        return 0;
//    }
    EXIT_FUNC;
    return id;
    End:
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
  decode_ue_ip

  DESCRIPTION
  decode the tlv as ue ip

  PARAMETERS
  mccp_tlv *puIp

  RETURN VALUE
  the ue ip of the message of the tlv

  DEPENDENCIES
  the Tlv message have correct message type and value

  SIDE EFFECTS
  None
===========================================================================*/
UINT32 decode_ue_ip(mccp_tlv *puIp) {
    UINT32 ip;
    UINT8 version = 0;
    UINT8 ipv4_mask = 0x80;
    UINT8 ipv6_mask = 0x40;
    struct in_addr addr;
    ENTER_FUNC;
    if (puIp == NULL || puIp->type != UE_IP || puIp->data == NULL) {
        LogE("the argument of func %s is not invalid,puIp:%p,FILE:%s LINE:%d", __func__, puIp,
             __FILE__, __LINE__);
        goto End;
    }
    if (puIp->len != 5 && puIp->len != 17) {
        LogE("ue ip len:%d", puIp->len);
        goto End;
    }
    version = *(UINT8 *) (puIp->data);
    if ((version & ipv4_mask) >> 7 == 1) {
        ip = *(UINT32 *) ((puIp->data) + 1);
        addr.s_addr = ip;
        LogI("decode_ue_ip current ue ip is %s", inet_ntoa(addr));
    } else {
        LogE("UE ip not a ipv4!");
        goto End;
    }
    EXIT_FUNC;
    return ip;

    End:
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
  decode_mpgw_ip

  DESCRIPTION
  decode the tlv as mpgw ip

  PARAMETERS
  mccp_tlv *pMIp

  RETURN VALUE
  the mpgw ip of the message of the tlv

  DEPENDENCIES
  the Tlv message have correct message type and value

  SIDE EFFECTS
  None
===========================================================================*/
UINT32 decode_mpgw_ip(mccp_tlv *pMIp) {
    UINT32 ip;
    UINT8 version = 0;
    UINT8 ipv4_mask = 0x80;
    UINT8 ipv6_mask = 0x40;
    struct in_addr addr;

    ENTER_FUNC;
    if (pMIp == NULL || pMIp->type != MPGW_IP || pMIp->data == NULL) {
        LogE("the argument of func %s is not invalid,pMIp:%p FILE:%s LINE:%d", __func__, pMIp,
             __FILE__, __LINE__);
        goto End;
    }
    if (pMIp->len != 5 && pMIp->len != 17) {
        LogE("mpgw ip len:%d", pMIp->len);
        goto End;
    }
    version = *(UINT8 *) (pMIp->data);
    if ((version & ipv4_mask) >> 7 == 1) {
        ip = *(UINT32 *) ((pMIp->data) + 1);
        addr.s_addr = ip;
        LogI("decode_mpgw_ip current mpgw ip is %s", inet_ntoa(addr));
    } else {
        LogE("mpgw ip not a ipv4!");
        goto End;
    }
    EXIT_FUNC;
    return ip;
    End:
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
  decode_tunnel_id

  DESCRIPTION
  decode the tlv as tunnel id

  PARAMETERS
  mccp_tlv *pTid

  RETURN VALUE
  the tunnel id of the message of the tlv

  DEPENDENCIES
  the Tlv message have correct message type and value

  SIDE EFFECTS
  None
===========================================================================*/
UINT32 decode_tunnel_id(mccp_tlv *pTid) {
    UINT32 tid;
    ENTER_FUNC;
    if (pTid == NULL || pTid->type != TEID || pTid->data == NULL) {
        LogE("the argument for this mcq is not match FILE:%s LINE:%d pTid:%p", __FILE__, __LINE__,
             pTid);
        goto End;
    }
    if (pTid->len != 4) {
        LogE("error tunnel id len:%d", pTid->len);
        goto End;
    }
    tid = *(UINT32 *) (pTid->data);
    tid = ntohl(tid);
    LogD("decode_tunnel_id current tunnel id is 0x%X || %d", tid, tid);
    EXIT_FUNC;
    return tid;
    End:
    EXIT_FUNC;
    return 0;

}

/*===========================================================================

  FUNCTION
  setAuthState

  DESCRIPTION
  set Auth state of the PCR<==>PCA

  PARAMETERS
  AuthState state    Authstate just success and fail
  UINT32 mpgwIp,     mpgw port and ip.
  int port

  RETURN VALUE
  None

  DEPENDENCIES
  when the PCA is back,and the message have been decode

  SIDE EFFECTS
  None
===========================================================================*/
void setAuthState(AuthState state, UINT32 mpgwIp, int port) {
    setAuthStateToJava(state, mpgwIp, port);
    //setAuthStateToJavaInMainThread(state,mpgwIp,port);
}

/*===========================================================================

  FUNCTION
  decode_mpgw_port

  DESCRIPTION
  decode the tlv as mpgw port

  PARAMETERS
  mccp_tlv *pMport

  RETURN VALUE
  the port of the message of the tlv

  DEPENDENCIES
  the Tlv message have correct message type and value

  SIDE EFFECTS
  None
===========================================================================*/
UINT16 decode_mpgw_port(mccp_tlv *pMport) {
    UINT16 port;
    ENTER_FUNC;
    if (pMport == NULL || pMport->type != MPGW_PORT || pMport->data == NULL) {
        LogE("the argument of pMport is not match,FILE:%s LINE:%d pMport:%p", __FILE__, __LINE__,
             pMport);
        goto End;
    }
    if (pMport->len != 2) {
        LogE("current MPGW port len error!");
        goto End;
    }
    port = *(UINT16 *) (pMport->data);
    if (port < 1024) {
        LogE("current decode port less than 1024,current port:%d", port);
        goto End;
    }
    LogD("decode_mpgw_port current port is %d", port);
    EXIT_FUNC;
    return port;
    End:
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
  decode_max_connect_quantity

  DESCRIPTION
  decode the tlv as max connnect of the quantity

  PARAMETERS
  mccp_tlv *pMcq

  RETURN VALUE
  the mcq of the message of the tlv

  DEPENDENCIES
  the Tlv message have correct message type and value

  SIDE EFFECTS
  None
===========================================================================*/
UINT16 decode_max_connect_quantity(mccp_tlv *pMcq) {
    UINT16 mcq;
    ENTER_FUNC;
    if (pMcq == NULL || pMcq->type != MCQ || pMcq->data == NULL) {
        LogE("the argument for this mcq is not match FILE:%s LINE:%d pMcq:%p", __FILE__, __LINE__,
             pMcq);
        goto End;
    }
    if (pMcq->len != 2) {
        LogE("error max connect_quantity:%d", pMcq->len);
        goto End;
    }
    mcq = *(UINT16 *) (pMcq->data);
    LogD("decode_max_connect_quantity current mcq is %d", mcq);
    EXIT_FUNC;
    return mcq;
    End:
    EXIT_FUNC;
    return 0;
}

/*===========================================================================

  FUNCTION
  mccp_send_value

  DESCRIPTION
  It's a thread function.

  PARAMETERS
  void *data

  RETURN VALUE
  void *

  DEPENDENCIES
  if auth fails,this thread function will create a new session id and send again.

  SIDE EFFECTS
  None
===========================================================================*/
void *mccp_send_value(void *data) {
    UINT8 count = 0;
    int ret = 0;
    ssize_t len = 0;
    socklen_t clen = 0;
    UINT8 buff[MCCP_MAX_PACKET_LEN] = {0};
    fd_set readset;
    struct timeval times;
    UINT32 session_id = 0;

    if (sendData == NULL || requestLen < 0) {
        LogE("if you want to run the send thread,please init the request");
        return NULL;
    }
    ENTER_FUNC;

    memset(buff, 0, MCCP_MAX_PACKET_LEN);
    memcpy(buff, sendData, requestLen);
    /*FREE(sendData);*/
    
    LogE("send the PCR(Policy Control Request Message) stillRun=%d retry count=%d mccp_socket=%d",stillRun,count,mccp_socket);
    while ((count++ < MCCP_MAX_RETRY) && (stillRun != 0)) {
        times.tv_sec = 3;
        times.tv_usec = 0;
        clen = sizeof(s_addr);
        LogE("send the PCR(Policy Control Request Message)");
        LogE("current addr:%s,clen:%d,requestLen:%d,buff:%s,socket:%d", inet_ntoa(s_addr.sin_addr),
             clen, requestLen, buff, mccp_socket);
        len = sendto(mccp_socket, buff, requestLen, 0, (struct sockaddr *) &s_addr, clen);

        if (len <= 0) {
            LogE("send error! and error=%s",strerror(errno));
            break;
        }

        FD_ZERO(&readset);
        FD_SET(mccp_socket, &readset);

        ret = select(mccp_socket + 1, &readset, NULL, NULL, &times);
        switch (ret) {
            case -1:
                LogE("select return error! and error=%s",strerror(errno));
                break;
            case 0:
                /*re create session id for retransmission*/
                LogE("select return 0! and error=%s",strerror(errno));
                if ((count != MCCP_MAX_RETRY) && (index_of_sid < MCCP_MAX_PACKET_LEN)) {
                    g_session_id = mccp_create_session_id();
                    session_id = htonl(g_session_id);
                    memcpy(buff + index_of_sid, &session_id, buff[index_of_sid - 1]);
                }
                break;
            default:
                LogE("select return > 0!");
                if (FD_ISSET(mccp_socket, &readset)) {
                    memset(buff, 0, MCCP_MAX_PACKET_LEN);
                    len = recvfrom(mccp_socket, buff, MCCP_MAX_PACKET_LEN, 0,
                                   (struct sockaddr *) &s_addr, &clen);
                    if (len == 0) {
                        LogE("the mccp socket have been shutdown");
                        goto End;
                    }
                    if (len < 0) {
                        LogE("some error have occur,and error=%s",strerror(errno));
                        goto End;
                    }
                    LogE("recv the PCA(Policy Control Answer Message)");
                    LogD("handle the result!....");
#if LWIP_PCAP_SUPPORT
#if !WIFI_LTE_SWITCH
                    tun_write_pcr_packet(sendData, requestLen, buff,len, ntohl(lte_ip),ntohs(lte_port), ntohl(s_addr.sin_addr.s_addr),ntohs(s_addr.sin_port));
#else
                    if(isBindLte) {
                        tun_write_pcr_packet(sendData, requestLen, buff,len, ntohl(lte_ip),ntohs(lte_port), ntohl(s_addr.sin_addr.s_addr),ntohs(s_addr.sin_port));
                    }
                    if(isBindWifi) {
                        tun_write_pcr_packet(sendData, requestLen, buff,len, ntohl(wifi_ip),ntohs(wifi_port), ntohl(s_addr.sin_addr.s_addr),ntohs(s_addr.sin_port));
                    }
#endif
#endif
                    mccp_process_window(buff, len);
                    goto End;
                }
                break;
        }
    }

    End:
    LogE("send the PCR(Policy Control Request Message) finish and result=%s",(ppca_s->mccp_auth == TRUE)?"OK":"FAIL");
    if(sendData != NULL){
        FREE(sendData);
        sendData = NULL;
    }
    
    if (ppca_s->mccp_auth == FALSE) {
#if MCCP_TEST
        mutp_init_Info_of_server(inet_addr("192.168.43.252"), 5558, 0x12121212);
        ppca_s->mccp_auth = TRUE;
#if LWIP_PERFORMANCE_TEST_ENABLE_VETH0
        ppca_s->mccp_mpgw_ip = inet_addr(MCCP_MPGW_IP);
#else
        ppca_s->mccp_mpgw_ip = inet_addr("192.168.43.252");
#endif
        ppca_s->mccp_mpgw_port = htons(5558);
        ppca_s->mccp_ue_ip = inet_addr("192.168.43.12");
        //LogI("current mpgw server ip: %d", inet_addr("192.168.43.157"));
        setAuthStateToJava(Auth_Success, inet_addr("192.168.43.252"), htons(5558));
#else
        mccp_destory();
        setAuthStateToJava(Auth_Fail,0,0);
#endif
    }
    EXIT_FUNC;
    return NULL;
}


void HeartBeat_Mccp_ThreadExitSignal(int nsigno)
{
#if HEARTBEAT_SUPPORT
    LogI("%s:%d enter nsigno:%d,SIGRTMIN:%d\n\r",__FUNCTION__,__LINE__,nsigno,SIGRTMIN);
    if( (SIGRTMIN+1) == nsigno )
    {
       pthread_exit(0);
    }
#endif    
}
 
 void HeartBeat_Mccp_RegistrationExitSignal()
{
#if HEARTBEAT_SUPPORT

    LogI("%s:%d enter\n\r",__FUNCTION__,__LINE__);
    struct sigaction actions;
    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = HeartBeat_Mccp_ThreadExitSignal;
    sigaction((SIGRTMIN+1), &actions, NULL);
    LogI("%s:%d exit\n\r",__FUNCTION__,__LINE__);
#endif
}
 
void HeartBeat_Mccp_KillThread(pthread_t pid)
{
#if HEARTBEAT_SUPPORT

    int ret =0;
    ret = pthread_kill(pid, 0);
    LogI("%s:%d enter pid:%d ret:%d\n\r",__FUNCTION__,__LINE__,pid,ret);
    if (ret == 0 )
    {
        pthread_kill(pid, (SIGRTMIN+1));
        pthread_join(pid, NULL);
    }
    LogI("%s:%d exit\n\r",__FUNCTION__,__LINE__);
#endif
}

void *heartbeat_mccp_sends_value(void *data) 
{
#if HEARTBEAT_SUPPORT

    UINT8 count = 0;
    int ret = 0;
    ssize_t len = 0;
    socklen_t clen = 0;
    UINT8 buff[MCCP_MAX_PACKET_LEN] = {0};
    fd_set readset;
    struct timeval times;
    int mccpSleepTime = 1;
    UINT32 session_id = 0;

    if (sendData == NULL || requestLen < 0) {
        LogE("if you want to run the send thread,please init the request");
        return NULL;
    }
    ENTER_FUNC;

    memset(buff, 0, MCCP_MAX_PACKET_LEN);
    memcpy(buff, sendData, requestLen);
    FREE(sendData);
    sendData = NULL;

   while (1) {
    
        times.tv_sec = 1;
        times.tv_usec = 0;
        clen = sizeof(s_addr);
        LogD("send the PCR(Policy Control Request Message)");
        LogD("current addr:%s,clen:%d,requestLen:%d,buff:%s,socket:%d", inet_ntoa(s_addr.sin_addr),
             clen, requestLen, buff, mccp_socket);
        len = sendto(mccp_socket, buff, requestLen, 0, (struct sockaddr *) &s_addr, clen);
        if (len <= 0) {
            LogI("send error!");
            break;
        }
        
        FD_ZERO(&readset);
        FD_SET(mccp_socket, &readset);

        ret = select(mccp_socket + 1, &readset, NULL, NULL, &times);
        switch (ret) {
            case -1:
                break;
            case 0:
                //re create session id for retransmission       
                g_session_id = mccp_create_session_id();
                session_id = htonl(g_session_id);
                memcpy(buff + index_of_sid, &session_id, buff[index_of_sid - 1]);
                break;
            default:
                if (FD_ISSET(mccp_socket, &readset)) {
                    memset(buff, 0, MCCP_MAX_PACKET_LEN);
                    len = recvfrom(mccp_socket, buff, MCCP_MAX_PACKET_LEN, 0,
                                   (struct sockaddr *) &s_addr, &clen);
                    if (len == 0) {
                        LogE("the mccp socket have been shutdown");
                    }
                    if (len < 0) {
                        LogE("some error have occur");
                    }
                    LogD("recv the PCA(Policy Control Answer Message)");
                    LogD("handle the result!....");
                    mccp_process_window(buff, len);
                }
                break;
        }

        if (ppca_s->mccp_auth == FALSE) 
        {
           sys_msleep(mccpSleepTime*1000);
           mccpSleepTime *= 2;  
           if( mccpSleepTime > 300)
           {
                mccpSleepTime = 300;
           }
        }           
     }
        
    EXIT_FUNC;
#endif
    return NULL;
}

/*===========================================================================

  FUNCTION
  mccp_process_window

  DESCRIPTION
  use this function to process the msg what we have recv

  PARAMETERS
  UINT8 *pMsg    the msg body
  ssize_t len    the msg len.

  RETURN VALUE
  the mcq of the message of the tlv

  DEPENDENCIES
  the Tlv message have correct message type and value

  SIDE EFFECTS
  None
===========================================================================*/
void *mccp_process_window(UINT8 *pMsg, ssize_t len) {
    mccp_message_header *pMessageHeader = NULL;

    if (pMsg == NULL) {
        //auth fail,server messag is null
        LogE("current recv data is NULL");
        //auth fail we need to free the resource
        return NULL;
    }
    LogD("mccp recv message and begin decode");

    pMessageHeader = decode_message_header(pMsg, len);

    if (pMessageHeader == NULL) {
        LogE("the message header is null");
        //free all data;
        return NULL;
    }
    //mFlow = mccp_flow + (pMessageHeader->type - PCR);
    switch (pMessageHeader->type) {
        case PCA:
            //handle
            LogI("handle PCA message");
            mccp_handle_pca_message(pMsg, pMessageHeader);
            break;
        case PUA:
            //current not support
            LogI("Current message PUA is Not support");
            break;
        case DSA:
            //current not support
            LogI("Current message DSA is Not support");
            break;
        case PUR:
            //current not support
            LogI("Current message PUR is Not support");
            break;
        case PCR:
            //current not support
            LogI("Current message PCR is Not support");
            break;
        case DSR:
            //current not support
            LogI("Current message DSR is Not support");
            break;
        default:
            mFlow = NULL;
            LogI("Current message is Not support");
            break;
    }

    LogD("mccp recv message and end decode");
    FREE(pMessageHeader);
    return NULL;
}

void set_lte_ip(UINT32 addr) {
    lte_ip = addr;
    LogE("addr lte ip:%d", addr);
}

#if WIFI_LTE_SWITCH
void set_wifi_ip(UINT32 addr) {
    wifi_ip = addr;
    LogD("addr wifi ip:%d", addr);
}
#endif

/*===========================================================================

  FUNCTION
  mccp_handle_pca_message

  DESCRIPTION
  handle the pca message

  PARAMETERS
  UINT8 *pMsg

  RETURN VALUE
  None

  DEPENDENCIES
  the message type == PCA

  SIDE EFFECTS
  None
===========================================================================*/
void mccp_handle_pca_message(UINT8 *pMsg, mccp_message_header *pMessageHeader) {
    mccp_tlv *pSid = NULL;
    mccp_tlv *pRcode = NULL;
    mccp_tlv *pUeIp = NULL;
    mccp_tlv *pMIp = NULL;
#ifdef PCA_COMPATIBLE
    mccp_tlv *pMIp1 = NULL;
#endif
    mccp_tlv *pMPort = NULL;
    mccp_tlv *pMcq = NULL;
    mccp_tlv *pTid = NULL;

    mccp_tlv *pTempUsed = NULL;
    int offset_len = 0;
    UINT32 sid = 0;
    UINT32 ueIp = 0;
    UINT32 mpgwIp = 0;
#ifdef PCA_COMPATIBLE
    UINT32 mpgwIp1 = 0;
#endif
    UINT32 tunnel_id = 0;
    UINT16 mpgwPort = 0;
    UINT16 mcq = 0;
    int index_of_flow = 0;

    mccp_result_code rcode = MCCP_AUTH_FAILURE;

    offset_len += MCCP_MESSAGE_HEADER_LEN;

    while (pMsg == NULL || offset_len < pMessageHeader->len) {
        pTempUsed = decode_mccp_tlv(pMsg, offset_len);
        if (pTempUsed == NULL) {
            break;
        }
        switch (pTempUsed->type) {
            case SID:
                LogI("decode the session id");
                pSid = pTempUsed;
                break;
            case RCODE:
                LogI("decode the result code");
                pRcode = pTempUsed;
                break;
            case UE_IP:
                LogI("decode the ue ip");
                pUeIp = pTempUsed;
                break;
            case MPGW_IP:
                LogI("decode the mpgw ip");
#ifndef PCA_COMPATIBLE
                pMIp = pTempUsed;
#else
                if(NULL== pMIp) {
                    pMIp = pTempUsed;
                }else {
                    pMIp1 = pTempUsed;
                }
#endif
                break;
            case MPGW_PORT:
                LogI("decode the mpgw port");
                pMPort = pTempUsed;
                break;
            case MCQ:
                LogI("decode the mac connectivity quantity");
                pMcq = pTempUsed;
                break;
            case TEID:
                LogI("decode the tunnel id");
                pTid = pTempUsed;
                break;
            default:
                LogI("current message type is not support!");
        }
        offset_len += MCCP_HEADER_LEN + pTempUsed->len;

    }

    if (pSid == NULL || pRcode == NULL) {
        LogE("The message of PCA is not commplete!,the session id and result code can't be null");
        goto End;
    }

    sid = decode_session_id(pSid);
    if (sid == 0) {
        goto End;
    }

    rcode = decode_result_code(pRcode);
    if (rcode > MCCP_MAX_RESULT_CODE) {
        goto End;
    } else if (rcode == MCCP_SUCCESS) {
        ppca_s->mccp_auth = TRUE;
    } else {
        LogE("auth error error code: %d", rcode);
        ppca_s->mccp_auth = FALSE;
    }

    ueIp = decode_ue_ip(pUeIp);

#ifndef PCA_COMPATIBLE
    mpgwIp = decode_mpgw_ip(pMIp);
#else
    if(NULL != pMIp) {
        mpgwIp = decode_mpgw_ip(pMIp);
    }
    if(NULL != pMIp1) {
        mpgwIp1 = decode_mpgw_ip(pMIp1);
    }
#endif

    mpgwPort = decode_mpgw_port(pMPort);

    mcq = decode_max_connect_quantity(pMcq);

    tunnel_id = decode_tunnel_id(pTid);

    if (pMessageHeader->len != offset_len) {
        LogE("the message len is not match,message len:%d,actual len:%d", pMessageHeader->len,
             offset_len);
        goto End;
    }
/*===========================================================*/
    if (pRcode == NULL || pRcode->type != RCODE) {
        LogE("result code error!");
        goto End;
    }
    if (sid != g_session_id) {
        LogE("the session id is error!");
        goto End;
    }
/*===========================================================*/

    ppca_s->mccp_max_quantity = mcq;
#ifndef PCA_COMPATIBLE
    ppca_s->mccp_mpgw_ip = mpgwIp;
#else
    ppca_s->mccp_mpgw_ip = mpgwIp;
    ppca_s->mccp_mpgw_ip1 = mpgwIp1;
#endif
    ppca_s->mccp_ue_ip = ueIp;
    ppca_s->session_id = sid;
    ppca_s->result_code = rcode;
    ppca_s->mccp_mpgw_port = mpgwPort;
    ppca_s->mccp_tunnel_id = tunnel_id;
    // ppca_s->mccp_auth = TRUE;
    //set result;
    LogD("auth: %s ,mcq: %d ,sid: %d ,rcode: %d , tunnel_id: %d ",
         ppca_s->mccp_auth == TRUE ? "SUCCESS" : "FAIL", mcq, sid, rcode, tunnel_id);
    struct in_addr outaddr;
    outaddr.s_addr = ueIp;
    LogD("ue ip:%s", inet_ntoa(outaddr));
    outaddr.s_addr = mpgwIp;
    LogD("mpgw ip:%s ,mpgw port:%d", inet_ntoa(outaddr), mpgwPort);
    mutp_init_Info_of_server(mpgwIp, mpgwPort, tunnel_id);
    //如果在测试时，这个函数需要注释一下，否则会导致出现bug.java env is not  in thread,but we still sh
    if(ppca_s->mccp_auth == TRUE)
        setAuthState(Auth_Success, mpgwIp, (int) mpgwPort);
    End:
    FREETLV(pSid);
    FREETLV(pRcode);
    FREETLV(pUeIp);
    FREETLV(pMIp);
    FREETLV(pMPort);
    FREETLV(pMcq);
    FREETLV(pTid);
    pTempUsed = NULL;
    
    if(ppca_s->mccp_auth == TRUE)
    {
        mccp_destory();
    }
}

/*===========================================================================

  FUNCTION
  mccp_destory

  DESCRIPTION
  when exit the msg ,we need to handle the msg.

  PARAMETERS
  None

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int mccp_destory() {

    ENTER_FUNC;
    if (mccp_socket > 0) {
        LogE("thread:%d close mccp socket", gettid());
        close(mccp_socket);
        mccp_socket = -1;
    }

    if( heartbeat_mccp_thread != 0)
    {
        HeartBeat_Mccp_KillThread(heartbeat_mccp_thread);
        heartbeat_mccp_thread = 0;        
    }
    
    EXIT_FUNC;
    return 0;
}
