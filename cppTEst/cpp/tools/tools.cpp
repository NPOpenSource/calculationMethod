#include <android/log.h>
#include <stdio.h>
#include <malloc.h>
#include "tools.h"
#include "lwip/sys.h"
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sched.h>

#define __STDC_FORMAT_MACROS
#if LWIP_GOOGLEPAD_ENABLE
#include "exception_handler.h"
#include "minidump_descriptor.h"
#endif

JavaVM *gJavaVM;

jobject gJavaObj;
jobject iperfJavaObj;


int stillRun = 0;
#if TEMP_DEBUG
long timeoftcpsend =0;
long timeoftcprecv = 0;
long cntoftcpsend = 0;
long cntoftcprecv = 0;
long timeofmptcpsend =0;
long timeofmptcprecv =0;
long cntofmptcpsend = 0;
long cntofmptcprecv = 0;
#endif
pthread_mutex_t mutex_lock;

typedef union {
    JNIEnv *env;
    void *venv;
} UnionJNIEnvToVoid;

static const char *classPathName = "com/example/user/myapplication/service/VpnServiceManager";
static JNINativeMethod methods[] = {};
#if LWIP_GOOGLEPAD_ENABLE
static google_breakpad::ExceptionHandler *breakpad_handler = NULL;

bool DumpCallback(const google_breakpad::MinidumpDescriptor& descriptor,
                  void* context,
                  bool succeeded) {
	LogI("Dump path: %s", descriptor.path());
	return succeeded;
}

int google_breakpad_CrashHandler_setup(const char *filePath){
	google_breakpad::MinidumpDescriptor descriptor(filePath);
	breakpad_handler = new google_breakpad::ExceptionHandler(descriptor, NULL, DumpCallback, NULL, true, -1);
    return 0;
}
#endif
/*
 * Register several native methods for one class.
 */
/*===========================================================================

  FUNCTION
  registerNativeMethods

  DESCRIPTION
  use this function to register the class Method.

  PARAMETERS
  JNIEnv *env               java environment pointer
  const char *className,     the class name
  JNINativeMethod *gMethods, the metod name struct array
  int numMethods             index of the array

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;

    clazz = env->FindClass(className);
    if (clazz == NULL) {
        LogI("Native registration unable to find class %s", className);
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        LogI("RegisterNatives failed for '%s'", className);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

/*
 * Register native methods for all classes we know about.
 *
 * returns JNI_TRUE on success.
 */
/*===========================================================================

  FUNCTION
  registerNatives

  DESCRIPTION
  Register native methods for all classes we know about

  PARAMETERS
  JNIEnv *env  use the java environment to register the functions

  RETURN VALUE
  returns JNI_TRUE on success.

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
static int registerNatives(JNIEnv *env) {
//    if (!registerNativeMethods(env, classPathName, methods,
//                               sizeof(methods) / sizeof(methods[0]))) {
//        return JNI_FALSE;
//    }

    return JNI_TRUE;
}

/*===========================================================================

  FUNCTION
  JNI_OnLoad

  DESCRIPTION
  use this function to get the java vm pointer,
  and this function will be call  in the Program onload

  PARAMETERS
  the argument will be call by java vm

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  if this function fails,we can't use jni and the function of mptcp and mutp and so on..
===========================================================================*/
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    UnionJNIEnvToVoid uenv;
    uenv.venv = NULL;
    jint result = -1;
    JNIEnv *env = NULL;
	char *dir_str = NULL;

    LogI("JNI_OnLoad");
    gJavaVM = vm;
    if (vm->GetEnv(&uenv.venv, JNI_VERSION_1_4) != JNI_OK) {
        LogI("ERROR: GetEnv failed");
        goto bail;
    }
    env = uenv.env;
    //gJavaEnv = env;
    if (registerNatives(env) != JNI_TRUE) {
        LogI("ERROR: registerNatives failed");
        goto bail;
    }
    LogI("JNI_OnLoad2  ");
    result = JNI_VERSION_1_4;

#if LWIP_GOOGLEPAD_ENABLE    
		dir_str = get_local_storage_dir();
		if(dir_str != NULL)
		{
			LogW("get local dir=%s",dir_str);
			google_breakpad_CrashHandler_setup(dir_str);
			free(dir_str);
		}
		else{
			google_breakpad_CrashHandler_setup("/sdcard/Android/data/com.example.user.myapplication");
		}
#endif


    bail:
    return result;
}

/*===========================================================================

  FUNCTION
  stoJstring

  DESCRIPTION
  use this function to covert the char* To jstring

  PARAMETERS
  JNIEnv *env     java environment pointer
  char *pat       the char type pointer

  RETURN VALUE
  jstring object

  DEPENDENCIES
  this function can't be used in the file.

  SIDE EFFECTS
  None
===========================================================================*/
jstring stoJstring(JNIEnv *env, const char *pat) {
    if (env == NULL || pat == NULL) {
        LogE("the argument is NULL,please check jni env:%p,jstring jstr:%p,file:%s,Line:%d", env,
             pat, __FILE__, __LINE__);
        return NULL;
    }
    jclass strClass = env->FindClass("Ljava/lang/String;");
    jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
    jbyteArray bytes = env->NewByteArray(strlen(pat));
    env->SetByteArrayRegion(bytes, 0, strlen(pat), (jbyte *) pat);
    jstring encoding = env->NewStringUTF("utf-8");
    return (jstring) env->NewObject(strClass, ctorID, bytes, encoding);
}

//string转char
/*===========================================================================

  FUNCTION
  jstringTostring

  DESCRIPTION
  use the function to covert the jstring obj to char *

  PARAMETERS
  JNIEnv *env     java environment pointer
  jstring jstr    the jstring object

  RETURN VALUE
  if return 0, call this function success
  if return NULL, call this function fails

  DEPENDENCIES
  the env is OK,and not in the thread.

  SIDE EFFECTS
  None
===========================================================================*/
char *jstringTostring(JNIEnv *env, jstring jstr) {
    char *rtn = NULL;
    if (env == NULL || jstr == NULL) {
        LogE("the argument is NULL,please check jni env:%p,jstring jstr:%p,file:%s,Line:%d", env,
             jstr, __FILE__, __LINE__);
        return rtn;
    }
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("utf-8");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray) env->CallObjectMethod(jstr, mid, strencode);
    jsize alen = env->GetArrayLength(barr);
    jbyte *ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0) {
        rtn = (char *) malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);
    return rtn;
}
/***
 * 在服务器发送PCR请求后，
 * @param state
 * @param mpgwIp
 * @param port
 */
/*===========================================================================

  FUNCTION
  setAuthStateToJava

  DESCRIPTION
  set the auth state to java to update the UI,and make the tun iface UP

  PARAMETERS
  int state,        the auth state, the auth is OK or fails
  UINT32 mpgwIp,    the ip address of the mpgw
  int port          the port of the mpgw

  RETURN VALUE
  None

  DEPENDENCIES
  None

  SIDE EFFECTS
  this function just use in the thread.not in the jni thread.
===========================================================================*/
void setAuthStateToJava(int state, UINT32 mpgwIp, int port) {
    int i = 0;
    int ret = -1;
    JNIEnv *env;
    jclass javaClass;
    jmethodID mid;
    int rd_len = -1;
    LogI("enter proactive command thread");

    /*getting environment parameter from global JavaVM*/
    int status = gJavaVM->AttachCurrentThread(&env, NULL);
    if (env == NULL || status != JNI_OK) {
        LogI("ProactiveCmdHandle: get environment fail.");
        return;
    }

    /*Get the java class */
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        return;
    }
    /*get the method */
    mid = env->GetMethodID(javaClass, "backAuthenResult", "(III)V");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        return;
    }
    /*call result*/
    env->CallVoidMethod(gJavaObj, mid, state, mpgwIp, port);//回调java函数建立相关的type.
    END:
    gJavaVM->DetachCurrentThread();
}
/***
 * 没有在其他线程中调用相关的java Thread，仅用于测试
 * @param state
 * 认证状态
 * @param mpgwIp
 * 服务器的IP地址
 * @param port
 * 服务器的port
 */
/*===========================================================================

  FUNCTION
  setAuthStateToJavaInMainThread

  DESCRIPTION
  this function just ues in no thread create to call the java method
  now just used in test

  PARAMETERS
  int state,        the auth state, the auth is OK or fails
  UINT32 mpgwIp,    the ip address of the mpgw
  int port          the port of the mpgw

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  None

  SIDE EFFECTS
  if you use this in the thread, the program will be crash.just be careful.
===========================================================================*/
void setAuthStateToJavaInMainThread(int state, UINT32 mpgwIp, int port) {
    int i = 0;
    int ret = -1;
    JNIEnv *env;
    jclass javaClass;
    jmethodID mid;
    int rd_len = -1;
    LogI("enter proactive command thread");

    /*getting environment parameter from global JavaVM*/
    if (gJavaVM->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        LogI("ERROR: GetEnv failed");
        return;
    }

    /*Get the java class */
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        return;
    }
    /*get the method */
    mid = env->GetMethodID(javaClass, "backAuthenResult", "(III)V");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        return;
    }
    /*call result*/
    env->CallVoidMethod(gJavaObj, mid, mpgwIp, port, state);//回调java函数建立相关的type.
}




/*===========================================================================

  FUNCTION
  protectFdFromJava

  DESCRIPTION
  call the vpn service in java code to protect the fd

  PARAMETERS
  int fd  the file description

  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  VPN service is OK

  SIDE EFFECTS
  if protect fd fails, we can't use this function to send and recv data.
===========================================================================*/
static JNIEnv *g_env = NULL;
int AttachCurrentThreadFunc(JNIEnv *env)
{
  int ret = 0;
  /*getting environment parameter from global JavaVM*/
  int status = gJavaVM->AttachCurrentThread(&env, NULL);
  if (env == NULL || status != JNI_OK) {
    LogI("ProactiveCmdHandle: get environment fail.");
    ret = -1;
    return ret;
  }

  return 0;
}

void DetachCurrentThreadFunc()
{
    gJavaVM->DetachCurrentThread();
    g_env = NULL;
}
int protectFdFromJava(JNIEnv *env,int fd) {
    int i = 0;
    int ret = -1;

    jclass javaClass;
    jmethodID mid;

    /*getting environment parameter from global JavaVM*/
    int status = gJavaVM->AttachCurrentThread(&env, NULL);
    if (env == NULL || status != JNI_OK) {
        LogI("ProactiveCmdHandle: get environment fail.");
        ret = -1;
        return ret;
    }

    /*Get the java class */
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        ret = -1;
        goto END;
    }
    /*get the method */
    mid = env->GetMethodID(javaClass, "protectCFd", "(I)I");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        ret = -1;
        goto END;
    }
    /*call result*/
    ret = env->CallIntMethod(gJavaObj, mid, fd);//回调java函数建立相关的type.
    if (ret == -1) {
        LogE("Protect fd fails");
    } else {
        LogI("Protect fd success!");
    }

    END:
    gJavaVM->DetachCurrentThread();
	
	return ret;
}

/*===========================================================================

  FUNCTION
  DESCRIPTION
  PARAMETERS
  RETURN VALUE
  if return 0, call this function success
  if return -1, call this function fails

  DEPENDENCIES
  SIDE EFFECTS
===========================================================================*/
int protectFd(JNIEnv *env,int fd) {
    int i = 0;
    int ret = -1;

    jclass javaClass;
    jmethodID mid;
    if(env == NULL)
    {
        return protectFdFromJava(env,fd);
    }
    /*Get the java class */
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        ret = -1;
        goto END;
    }
    /*get the method */
    mid = env->GetMethodID(javaClass, "protectCFd", "(I)I");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        ret = -1;
        goto END;
    }
    /*call result*/
    ret = env->CallIntMethod(gJavaObj, mid, fd);//回调java函数建立相关的type.
    if (ret == -1) {
        LogE("Protect fd fails");
    } else {
        LogI("Protect fd success!");
    }

    END:
    return ret;
}

/*===========================================================================

  FUNCTION
  bind Network To Handle Packet Thought Java

  DESCRIPTION
  accordint to lte and wifi, bind network to handle the packet

  PARAMETERS
  int lte  1 handle the lte,other don't handle
  int wifi 1 handle the wifi,other don't handle

  RETURN VALUE
  if return 0, call this function fails
  if return -1, call this function fails
  if return 1, call this function success

  DEPENDENCIES
  None

  SIDE EFFECTS
  None
===========================================================================*/
int bindNetworkToHandlePacketThoughtJava(int lte,int wifi)
{
    int i = 0;
    int ret = -1;
    jclass javaClass;
    jmethodID mid;
    JNIEnv *env;
    /*getting environment parameter from global JavaVM*/
    int status = gJavaVM->AttachCurrentThread(&env, NULL);
    if (env == NULL || status != JNI_OK) {
        LogI("ProactiveCmdHandle: get environment fail.");
        ret = -1;
        return ret;
    }

    /*Get the java class */
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        ret = -1;
        goto END;
    }
    /*get the method */
    mid = env->GetMethodID(javaClass, "bindNetworkToHandlePacket", "(II)I");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        ret = -1;
        goto END;
    }
    /*call result*/
    ret = env->CallIntMethod(gJavaObj, mid, lte, wifi);
    if (ret == -1) {
        LogE("please check wifi and lte is OK");
    } else {
        LogI("bind Process success!");
    }

    END:
    gJavaVM->DetachCurrentThread();
    return ret;
}

int bindNetworkToHandlePacketThoughtJavaInMain(JNIEnv *env,int lte,int wifi)
{

    if(env == NULL)
    {
        //JNIEnv  *env = NULL;
        if (gJavaVM->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
            LogI("ERROR: GetEnv failed");
            return -1;
        }
    }
    jclass  javaClass;
    int ret = 0;
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        ret = -1;
        return ret;
    }
    /*get the method */
    jmethodID  mid;
    mid = env->GetMethodID(javaClass, "bindNetworkToHandlePacket", "(II)I");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        ret = -1;
        return ret;
    }
    /*call result*/
    ret = env->CallIntMethod(gJavaObj, mid, lte, wifi);
    if (ret == -1) {
        LogE("please check wifi and lte is OK");
    } else {
        LogI("bind Process success!");
    }
    return 0;
}

void HeartBeatErrorStateToJava(int lteState, int wifiState){
    int i = 0;
    int ret = -1;
    JNIEnv *env;
    jclass javaClass;
    jmethodID mid;
    LogI("enter proactive command thread");

    /*getting environment parameter from global JavaVM*/
    int status = gJavaVM->AttachCurrentThread(&env, NULL);
    if (env == NULL || status != JNI_OK) {
        LogI("ProactiveCmdHandle: get environment fail.");
        return;
    }

    /*Get the java class */
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        goto End;
    }

    /*get the method */
    mid = env->GetMethodID(javaClass, "heartbeatCallback", "(II)V");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        return;
    }

    env->CallVoidMethod(gJavaObj, mid, lteState, wifiState);

End:
    gJavaVM->DetachCurrentThread();
    return ;
}

void  HeartBeatIsBroken_ThoughtJava(int iStatus)
 {
    int i = 0;
    int ret = -1;
    JNIEnv *env;
    jclass javaClass;
    jmethodID mid;
    int rd_len = -1;
    LogI("enter proactive command thread");

    /*getting environment parameter from global JavaVM*/
    int status = gJavaVM->AttachCurrentThread(&env, NULL);
    if (env == NULL || status != JNI_OK) {
        LogI("ProactiveCmdHandle: get environment fail.");
        return;
    }

    /*Get the java class */
    javaClass = env->GetObjectClass(gJavaObj);
    if (javaClass == NULL) {
        LogI("ProactiveCmdHandle: get java class object fail.");
        return;
    }
    /*get the method */
    mid = env->GetMethodID(javaClass, "backVpnDisconnectResult", "(I)V");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        return;
    }
    /*call result*/
    env->CallVoidMethod(gJavaObj, mid, iStatus);//回调java 弹出提示框，关闭或打开hag
    END:
    gJavaVM->DetachCurrentThread();
}

extern int is_iperf_eixt;
void setIperfTestResultToJava(int id, int startTime, int endTime,  double dBytes, double dBps, int status)
{

    JNIEnv *env = NULL;
    jclass javaClass;
    jmethodID mid;

    if(is_iperf_eixt) return;
    
	LogD("iperf debug: Enter setIperfTestResultToJava.");
    /*getting environment parameter from global JavaVM*/
    int ret = gJavaVM->AttachCurrentThread(&env, NULL);
    if (env == NULL || ret != JNI_OK) {
        LogI("get environment fail.");
        return;
    }

    /*Get the java class */
    javaClass = env->GetObjectClass(iperfJavaObj);
    if (javaClass == NULL) {
        LogE("ProactiveCmdHandle: get java class objet fail.");
        return;
    }

    /*get the method */
    mid = env->GetMethodID(javaClass, "onIperfTestResult", "(IIIDDI)V");
    if (mid == NULL) {
        LogI("ProactiveCmdHandle: get callback method fail.");
        return;
    }

    /*call result*/
    env->CallVoidMethod(iperfJavaObj,mid,id,startTime,endTime,dBytes,dBps,status);

    gJavaVM->DetachCurrentThread();
    LogD("iperf debug: End to setIperfTestResultToJava.");
}

char *get_local_storage_dir(void)
{
   char *szPath = NULL;
   char *sdcard_root_dir = getenv("EXTERNAL_STORAGE");
   
   if(sdcard_root_dir == NULL){
   	   sdcard_root_dir = getenv("SECONDARY_STORAGE");
   }

   if(sdcard_root_dir != NULL){
   	szPath = (char *)malloc(512);
   	memset(szPath, 0x0, 512);
	strcpy(szPath, sdcard_root_dir);
	
	strcat(szPath, "/Android/data/pcap.mptcp");
   	DIR* dir = opendir(szPath);
    if (dir != NULL) {
       closedir(dir); 
	   return szPath;
    }
	else
	{
	   if(mkdir(szPath,550) == 0)
	   	  return szPath;
	   else
	   	  free(szPath);
	}
   }
   return NULL;
}


int getCurrentPid(){
    return gettid();
}
void upThreadPro(pthread_t* __pthread){
#if UP_THREAD_PRIO
    struct sched_param param;
    int policy;
    pthread_getschedparam(*__pthread, &policy, &param);
    param.sched_priority -=19;
    pthread_setschedparam(*__pthread, policy, &param);
#endif	
}
int bindThreadToCpu(int cpu){
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu,&cpuset);
    pid_t pt= gettid();
    int ret = sched_setaffinity(pt,sizeof(cpuset),&cpuset);
    if(ret != 0){
        LogE("sched bind cpu fails:%s",strerror(errno));
    }
    return ret;
}

void setThreadName(const char* name){
    pthread_setname_np(pthread_self(),name);
}

void pthreadSetOp(int proivity){
    int tmp;
    struct sched_param param;
    pthread_getschedparam(pthread_self(),&tmp,&param);
    pthread_setschedparam(pthread_self(),SCHED_FIFO,&param);
}
uint64_t getCTime(){
    struct timeval _tv;
    uint64_t time;
    gettimeofday(&_tv,NULL);
    time = _tv.tv_sec * 1000000 + _tv.tv_usec;
    return time;
}
#if MUTP_TEST_DEBUG_OUTPUT_DATA
void printStream(char *data,int len)
{
    char *buf = new char[len*3+1];
    for(int i = 0;i< len;i++)
    {
        sprintf(&buf[i*3],"%2x ",data[i]);
        if(data[i]>0 && data[i]<10)
           buf[i*3] = '0';
    }
    LogI("mutp message:%s",buf);
    delete[] buf;
}
#endif
