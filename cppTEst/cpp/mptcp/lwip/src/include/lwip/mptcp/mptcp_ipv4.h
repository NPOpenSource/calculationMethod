//
// Created by user on 17-4-20.
//

#ifndef MYAPPLICATION_MPTCP_IPV4_H
#define MYAPPLICATION_MPTCP_IPV4_H
#include <lwip/arch.h>
#if LINUX_PLATFORM
#include <linux/types.h>
#endif
u32_t mptcp_v4_get_nonce(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,u32_t *mptcp_seed, u8_t *mptcp_secret);
u64_t mptcp_v4_get_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                       u32_t seed, u8_t *mptcp_secret);
#endif //MYAPPLICATION_MPTCP_IPV4_H
