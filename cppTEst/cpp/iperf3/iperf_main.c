/*
 * iperf, Copyright (c) 2014, 2015, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#include "iperf_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <netinet/tcp.h>

#include "iperf.h"
#include "iperf_api.h"
#include "units.h"
#include "iperf_locale.h"
#include "net.h"
#include "../vpn_tun/vpn_tun_if.h"
#include "iperf_key.h"
#include<pthread.h>

pthread_mutex_t networkLock = PTHREAD_COND_INITIALIZER;
struct iperf_test *ptTest = NULL;
static pthread_t g_ntid;
struct iperf_test *ptTest1 = NULL;
static pthread_t g_ntid1;
extern char mutp_lte_ip[18];
extern char mutp_wifi_ip[18];
extern mptcp_data_init_V01 gMPTCP_config;
extern int isSetWifiAddr;
extern int isSetLteAddr;
static int iperf_run_flag = 0;
static pthread_mutex_t iperfRunLock = PTHREAD_MUTEX_INITIALIZER;
static int run(struct iperf_test *test);

void* iperf_run(void* args)
{
    struct iperf_test *pstArgsIperf = (struct iperf_test *)args;
    setGlobalIperfInThread(pstArgsIperf);
    setIperfTestResultToJava(0, 0, 0, 0, 0, TEST_RUNNING);

    LogD_Iperf("iperf_debug: enter to iperf_run");
    int ret = run(pstArgsIperf);
    LogD_Iperf("iperf_debug: end to iperf_run, ret = %d", ret);

    if(pstArgsIperf->lte){
        setIperfTestResultToJava(0, 0, pstArgsIperf->duration, 0, 0, DISPLAY_RESULTS);
    }
    if(NULL != pstArgsIperf){

        LogD_Iperf("iperf_debug: free ptTest in iperf_run()");
        iperf_free_test(pstArgsIperf);
        ptTest = NULL;
    }
    iperf_run_flag = 0;
    return NULL;
}

int iperf_mptcp_stop(void)
{
    LogD_Iperf("iperf_debug: enter iperf_mptcp_stop()");
    pthread_mutex_lock(&iperfRunLock);
    if(iperf_run_flag == 1) {
        if (ptTest != NULL && 0 != iperf_set_send_state(ptTest, IPERF_DONE)) {
            LogE_Iperf("iperf_debug:fail to iperf_set_send_state()");
        }

        if (ptTest1 != NULL && 0 != iperf_set_send_state(ptTest1, IPERF_DONE)) {
            LogE_Iperf("iperf_debug:fail to iperf_set_send_state()");
        }
    }
    iperf_run_flag = 0;
    pthread_mutex_unlock(&iperfRunLock);
    LogD_Iperf("iperf_debug: end to iperf_mptcp_stop()");

    return 0;
}

int iperf_mptcp_main(int argc, char **argv)
{
    int ret = 0;
    /* update the iperf status*/
    pthread_mutex_lock(&iperfRunLock);
    iperf_run_flag = 1;
    pthread_mutex_unlock(&iperfRunLock);
    clearIperfUploadValue();
    LogD_Iperf("iperf_debug: enter to iperf_mptcp_main()");
    LogD_Iperf("LTE:%d wifi:%d",isSetLteAddr, isSetWifiAddr);
    globalIperfKeyInit();
    if(gMPTCP_config.is_mptcp_init){
        if(isSetLteAddr){
            ptTest = iperf_new_test();
            if (NULL == ptTest){
                iperf_errexit(NULL, "create new test error - %s", iperf_strerror(i_errno));
                LogE_Iperf("iperf_debug: fail to iperf_new_test");
                return RET_MALLOC_FAIL;
            }
            iperf_set_test_bind_address(ptTest,mutp_lte_ip);
            iperf_defaults(ptTest); /* sets defaults */

            if (iperf_parse_arguments(ptTest, argc, argv) < 0) {
                iperf_err(ptTest, "parameter error - %s", iperf_strerror(i_errno));
                LogE_Iperf("iperf_debug: fail to iperf_parse_arguments");
                fprintf(stderr, "\n");
                usage_long();
                return RET_PARAMS_ERROR;
            }
            ptTest->lte = 1;
        }

        if(isSetWifiAddr){
        /**********************************************/
            ptTest1= iperf_new_test();
            if (NULL == ptTest1){
                iperf_errexit(NULL, "create new test error - %s", iperf_strerror(i_errno));
                LogE_Iperf("iperf_debug: fail to iperf_new_test");
                return RET_MALLOC_FAIL;
            }
            iperf_defaults(ptTest1);    /* sets defaults */

            if (iperf_parse_arguments(ptTest1, argc, argv) < 0) {
                iperf_err(ptTest, "parameter error - %s", iperf_strerror(i_errno));
                LogE_Iperf("iperf_debug: fail to iperf_parse_arguments");
                fprintf(stderr, "\n");
                usage_long();
                return RET_PARAMS_ERROR;
            }
            ptTest1->server_port = ptTest->server_port+1;
            ptTest1->lte = 2;
            iperf_set_test_bind_address(ptTest1,mutp_wifi_ip);
        }

        if(isSetLteAddr && isSetWifiAddr &&  gMPTCP_config.is_mptcp_init) {
            LogD_Iperf("enter wifi+lte");
            LogD_Iperf("iperf_debug: start to pthread_create, logPath:%s", ptTest->logfile);
            ret = pthread_create(&g_ntid, NULL, iperf_run, (void *) ptTest);
            if (0 != ret) {
                LogE_Iperf("iperf_debug: fail to pthread_create, ret=%d", ret);
            }

            LogD_Iperf("iperf_debug: start to pthread_create, logPath:%s", ptTest1->logfile);
            ret = pthread_create(&g_ntid1, NULL, iperf_run, (void *) ptTest1);
            if (0 != ret) {
                LogE_Iperf("iperf_debug: fail to pthread_create, ret=%d", ret);
            }
            LogD_Iperf("iperf_debug: end to pthread_create, ntid=%ld", g_ntid1);
        }else if(isSetWifiAddr){
            LogD_Iperf("enter wifi");
            LogD_Iperf("iperf_debug: start to pthread_create, logPath:%s", ptTest1->logfile);
            ret = pthread_create(&g_ntid1, NULL, iperf_run, (void *) ptTest1);
            if (0 != ret) {
                LogE_Iperf("iperf_debug: fail to pthread_create, ret=%d", ret);
            }
            LogD_Iperf("iperf_debug: end to pthread_create, ntid=%ld", g_ntid1);
        }else if(isSetLteAddr){
            LogD_Iperf("enter lte");
            LogD_Iperf("iperf_debug: start to pthread_create, logPath:%s", ptTest->logfile);
            ret = pthread_create(&g_ntid, NULL, iperf_run, (void *) ptTest);
            if (0 != ret) {
                LogE_Iperf("iperf_debug: fail to pthread_create, ret=%d", ret);
            }
            LogD_Iperf("iperf_debug: end to pthread_create, logPath:%s", ptTest->logfile);
        }
    }else{
        ptTest = iperf_new_test();
        if (NULL == ptTest){
            iperf_errexit(NULL, "create new test error - %s", iperf_strerror(i_errno));
            LogE_Iperf("iperf_debug: fail to iperf_new_test");
            return RET_MALLOC_FAIL;
        }
        iperf_defaults(ptTest); /* sets defaults */

        if (iperf_parse_arguments(ptTest, argc, argv) < 0) {
            iperf_err(ptTest, "parameter error - %s", iperf_strerror(i_errno));
            LogE_Iperf("iperf_debug: fail to iperf_parse_arguments");
            fprintf(stderr, "\n");
            usage_long();
            return RET_PARAMS_ERROR;
        }
        ret = pthread_create(&g_ntid, NULL, iperf_run, (void *) ptTest);
        if (0 != ret) {
            LogE_Iperf("iperf_debug: fail to pthread_create, ret=%d", ret);
        }
        LogD_Iperf("iperf_debug: end to pthread_create, logPath:%s", ptTest->logfile);
    }
    return ret;
}

/**************************************************************************/

static jmp_buf sigend_jmp_buf;

static void
sigend_handler(int sig)
{
    longjmp(sigend_jmp_buf, 1);
}

/**************************************************************************/
static int
run(struct iperf_test *test)
{
    /* Termination signals. */
    iperf_catch_sigend(sigend_handler);
    if (setjmp(sigend_jmp_buf))
    iperf_got_sigend(test);

    switch (test->role) {
        case 's':
        if (test->daemon) {
        int rc = daemon(0, 0);
        if (rc < 0) {
            i_errno = IEDAEMON;
            iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
        }
        }
        if (iperf_create_pidfile(test) < 0) {
        i_errno = IEPIDFILE;
        iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
        }
        for (;;) {
            int rc;
            rc = iperf_run_server(test);
            if (rc < 0) {
                iperf_err(test, "error - %s", iperf_strerror(i_errno));
                if (rc < -1) {
                    iperf_errexit(test, "exiting");
                    break;
                }
            }
            iperf_reset_test(test);
            if (iperf_get_test_one_off(test))
                break;
        }
        iperf_delete_pidfile(test);
        break;
    case 'c':
        if (iperf_run_client(test) < 0)
            iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
        break;
    default:
        usage();
        break;
    }

    iperf_catch_sigend(SIG_DFL);

    return 0;
}
