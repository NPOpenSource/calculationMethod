//
// Created by user on 2018/1/16.
//

#ifndef IPERF_MAIN_H
#define IPERF_MAIN_H
#ifdef __cplusplus
extern "C" {
#endif
int iperf_mptcp_main(int argc, char **argv);
int iperf_mptcp_stop(void);

#ifdef __cplusplus
};
#endif
#endif //IPERF_MAIN_H
