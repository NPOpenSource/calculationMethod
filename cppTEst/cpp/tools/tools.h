#ifndef __TOOLS_H__
#define __TOOLS_H__
#include "lwip/lwipopts.h"
#if !LINUX_PLATFORM
#include "jni.h"
#else
#define JavaVM void
typedef void * jobject;
#define JNIEnv void
#define jstring char
#endif
#include "common.h"
#include <pthread.h>
#include <stdint.h>



extern JavaVM *gJavaVM;
extern jobject gJavaObj;
extern jobject iperfJavaObj;
extern int stillRun;
extern pthread_mutex_t mutex_lock;

typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned int UINT;

//#define __android_log_print(...) do{}while(0)

#define TUN_IP "10.0.2.0"
#define TEMP_DEBUG 0
#if TEMP_DEBUG
extern long timeoftcpsend;
extern long timeoftcprecv;
extern long cntoftcpsend;
extern long cntoftcprecv;
extern long timeofmptcpsend;
extern long timeofmptcprecv;
extern long cntofmptcpsend;
extern long cntofmptcprecv;
#endif
#ifdef __cplusplus
extern "C" {
#endif

jstring stoJstring(JNIEnv *env, const char *pat);
char *jstringTostring(JNIEnv *env, jstring jstr);
void setAuthStateToJava(int state, UINT32 mpgwIp, int port);
void setAuthStateToJavaInMainThread(int state, UINT32 mpgwIp, int port);
int protectFdFromJava(JNIEnv *env, int fd);
int bindNetworkToHandlePacketThoughtJava(int lte,int wifi);
int bindNetworkToHandlePacketThoughtJavaInMain(JNIEnv *env,int lte,int wifi);
int protectFd(JNIEnv *env,int fd);
int AttachCurrentThreadFunc(JNIEnv *env);
void DetachCurrentThreadFunc();
void  HeartBeatIsBroken_ThoughtJava(int iStatus);
void setIperfTestResultToJava(int id, int startTime, int endTime, double dBytes, double dBps, int status);
void HeartBeatErrorStateToJava(int lteState, int wifiState);
char *get_local_storage_dir(void);
int bindThreadToCpu(int cpu);
int getCurrentPid();
void setThreadName(const char* name);
void upThreadPro(pthread_t* __pthread);
uint64_t getCTime();
#if MUTP_TEST_DEBUG_OUTPUT_DATA
void printStream(char *data,int len)
#endif

#define ENTER_FUNC LogI("Thread: %d Enter the function %s",gettid(),__func__);
#define EXIT_FUNC LogI("Thread: %d Exit the function %s",gettid(),__func__);

//int create_udp_socket(const ip4_addr_p_t *src_ip);
#ifdef __cplusplus
}
#endif
#endif
