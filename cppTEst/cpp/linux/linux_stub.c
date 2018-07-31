#include "lwip/lwipopts.h"
#include "tools/tools.h"
#include "tools/common.h"
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>

#include "exception_handler.h"
#include "minidump_descriptor.h"
#include "linux_stub.h"

int stillRun = 0;
static google_breakpad::ExceptionHandler *breakpad_handler = NULL;
#define LOG_FILE	"a.log"

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


void setAuthStateToJava(int state, unsigned int mpgwIp, int port)
{
}

int bindNetworkToHandlePacketThoughtJava(int lte,int wifi)
{
    return 0;
}

int bindNetworkToHandlePacketThoughtJavaInMain(JNIEnv *env,int lte,int wifi)
{
    return 0;
}

int protectFd(JNIEnv *env,int fd) {
	return 0;
}

char *get_local_storage_dir(void)
{
   char *szPath = NULL;
   char *sdcard_root_dir = getenv("EXTERNAL_STORAGE");
   
   if(sdcard_root_dir == NULL){
   	   sdcard_root_dir = getenv("SECONDARY_STORAGE");
   }

   if(sdcard_root_dir == NULL)
   	   sdcard_root_dir= (char*)"/home/huawei/mptcp_linux_master/pcap\0";

   if(sdcard_root_dir != NULL){
   	szPath = (char *)malloc(512);
   	memset(szPath, 0x0, 512);
	strcpy(szPath, sdcard_root_dir);
	
	/*strcat(szPath, "/Android/data/com.example.user.myapplication");*/
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

void setup_breakpad(void)
{
#if LWIP_GOOGLEPAD_ENABLE 
    char *dir_str = NULL;
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
}

void setThreadName(const char* name){
    pthread_setname_np(pthread_self(),name);
}

int getCurrentPid(){
    return 0;
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
    return 0;
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

