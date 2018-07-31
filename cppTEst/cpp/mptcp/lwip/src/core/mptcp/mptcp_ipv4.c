/*===========================================================================

                         mptcp_ipv4.c

DESCRIPTION


MPTCP implementation - IPv4-specific functions

Copyright (c) 2017.04 - 2017.05 Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/
#include <lwip/mptcp/mptcp_ipv4.h>
#include <lwip/mptcp/cryptohash.h>
#include <lwip/mptcp/mptcp.h>
#include <netif/ppp/polarssl/md5.h>
#if LINUX_PLATFORM
#define __force
#endif

#if LWIP_MPTCP_SUPPORT

u32_t mptcp_v4_get_nonce(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, 
       u32_t *mptcp_seed, u8_t *mptcp_secret)
{
    u32_t hash[MD5_DIGEST_WORDS];

    hash[0] = (__force u32_t)saddr;
    hash[1] = (__force u32_t)daddr;
    hash[2] = ((__force u32_t)sport << 16) + (__force u16_t)dport;
    hash[3] = *mptcp_seed++;

    md5_transform(hash, (u8_t const *)mptcp_secret);

    return hash[0];
}

u64_t mptcp_v4_get_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                     u32_t seed, u8_t *mptcp_secret)
{
    u32_t hash[MD5_DIGEST_WORDS];

    hash[0] = (__force u32_t)saddr;
    hash[1] = (__force u32_t)daddr;
    hash[2] = ((__force u16_t)sport << 16) + (__force u16_t)dport;
    hash[3] = seed;

    md5_transform(hash, (u8_t const *)mptcp_secret);

    return *((u64_t *)hash);
}

#endif