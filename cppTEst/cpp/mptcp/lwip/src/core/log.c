#include "lwip/lwipopts.h"
#if !LINUX_PLATFORM
#include <android/log.h>
#else
#include <stdarg.h>
#include <syslog.h>
#include "tools/common.h"
#endif
#include <stdio.h>
#include "common.h"


int g_log_level_ctrl[E_LOG_LEV_MAX][E_LOG_MODULE_MAX] = {
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = debug,
        [E_LOG_LEV_DEBUG]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = info,
        [E_LOG_LEV_INFO]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = warn,
        [E_LOG_LEV_WARN]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = error,
        [E_LOG_LEV_ERR]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = fatal,
        [E_LOG_LEV_FATAL]={
                LOG_MODULES
        }
#undef LOG_MOD_ITEM
};  //æ§å¶LOGD/E/I/Wæå°


int g_log_level_ctrl_def[E_LOG_LEV_MAX][E_LOG_MODULE_MAX] = {
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = debug,
        [E_LOG_LEV_DEBUG]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = info,
        [E_LOG_LEV_INFO]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = warn,
        [E_LOG_LEV_WARN]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = error,
        [E_LOG_LEV_ERR]={
                LOG_MODULES
        },
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = fatal,
        [E_LOG_LEV_FATAL]={
                LOG_MODULES
        }
#undef LOG_MOD_ITEM
};  //æ§å¶LOGD/E/I/Wæå°

const char *g_log_modules_str[E_LOG_MODULE_MAX]=
        {
#undef LOG_MOD_ITEM
#define LOG_MOD_ITEM(lev, lev_str, lev_n, debug, info, warn, error, fatal)  [lev] = lev_str,
        LOG_MODULES
#undef LOG_MOD_ITEM
        };

void aprintf(const char* format, ...)
{
    char buffer [1024];
    va_list args;
    va_start (args, format);
    vsnprintf(buffer, 1024, format, args);
#if !LINUX_PLATFORM
    __android_log_print(ANDROID_LOG_ERROR, "TS DEBUG", "%s", buffer);
#else
    /*syslog(LOG_DEBUG,"TS DEBUG %s", buffer);*/
    LogE("TS DEBUG %s", buffer);
    printf("TS DEBUG %s", buffer);
#endif
    va_end (args);
}