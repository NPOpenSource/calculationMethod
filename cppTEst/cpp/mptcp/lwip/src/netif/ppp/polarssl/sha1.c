/*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of PolarSSL or XySSL nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *  The SHA-1 standard was published by NIST in 1993.
 *
 *  http://www.itl.nist.gov/fipspubs/fip180-1.htm
 */
#include "lwip/lwipopts.h"
#include "netif/ppp/ppp_opts.h"
//#if PPP_SUPPORT && LWIP_INCLUDED_POLARSSL_SHA1

#include "netif/ppp/polarssl/sha1.h"

#include <string.h>

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

void sha_init(u32_t *buf)
{
    buf[0] = 0x67452301;
    buf[1] = 0xefcdab89;
    buf[2] = 0x98badcfe;
    buf[3] = 0x10325476;
    buf[4] = 0xc3d2e1f0;
}

/*
 * SHA-1 context setup
 */
void sha1_starts( sha1_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

//static void sha1_process( sha1_context *ctx, const unsigned char data[64] )
//{
//    unsigned long temp, W[16], A, B, C, D, E;
//
//    GET_ULONG_BE( W[ 0], data,  0 );
//    GET_ULONG_BE( W[ 1], data,  4 );
//    GET_ULONG_BE( W[ 2], data,  8 );
//    GET_ULONG_BE( W[ 3], data, 12 );
//    GET_ULONG_BE( W[ 4], data, 16 );
//    GET_ULONG_BE( W[ 5], data, 20 );
//    GET_ULONG_BE( W[ 6], data, 24 );
//    GET_ULONG_BE( W[ 7], data, 28 );
//    GET_ULONG_BE( W[ 8], data, 32 );
//    GET_ULONG_BE( W[ 9], data, 36 );
//    GET_ULONG_BE( W[10], data, 40 );
//    GET_ULONG_BE( W[11], data, 44 );
//    GET_ULONG_BE( W[12], data, 48 );
//    GET_ULONG_BE( W[13], data, 52 );
//    GET_ULONG_BE( W[14], data, 56 );
//    GET_ULONG_BE( W[15], data, 60 );
//
//#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))
//
//#define R(t)                                            \
//(                                                       \
//    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
//           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
//    ( W[t & 0x0F] = S(temp,1) )                         \
//)
//
//#define P(a,b,c,d,e,x)                                  \
//{                                                       \
//    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
//}
//
//    A = ctx->state[0];
//    B = ctx->state[1];
//    C = ctx->state[2];
//    D = ctx->state[3];
//    E = ctx->state[4];
//
//#define F(x,y,z) (z ^ (x & (y ^ z)))
//#define K 0x5A827999
//
//    P( A, B, C, D, E, W[0]  );
//    P( E, A, B, C, D, W[1]  );
//    P( D, E, A, B, C, W[2]  );
//    P( C, D, E, A, B, W[3]  );
//    P( B, C, D, E, A, W[4]  );
//    P( A, B, C, D, E, W[5]  );
//    P( E, A, B, C, D, W[6]  );
//    P( D, E, A, B, C, W[7]  );
//    P( C, D, E, A, B, W[8]  );
//    P( B, C, D, E, A, W[9]  );
//    P( A, B, C, D, E, W[10] );
//    P( E, A, B, C, D, W[11] );
//    P( D, E, A, B, C, W[12] );
//    P( C, D, E, A, B, W[13] );
//    P( B, C, D, E, A, W[14] );
//    P( A, B, C, D, E, W[15] );
//    P( E, A, B, C, D, R(16) );
//    P( D, E, A, B, C, R(17) );
//    P( C, D, E, A, B, R(18) );
//    P( B, C, D, E, A, R(19) );
//
//#undef K
//#undef F
//
//#define F(x,y,z) (x ^ y ^ z)
//#define K 0x6ED9EBA1
//
//    P( A, B, C, D, E, R(20) );
//    P( E, A, B, C, D, R(21) );
//    P( D, E, A, B, C, R(22) );
//    P( C, D, E, A, B, R(23) );
//    P( B, C, D, E, A, R(24) );
//    P( A, B, C, D, E, R(25) );
//    P( E, A, B, C, D, R(26) );
//    P( D, E, A, B, C, R(27) );
//    P( C, D, E, A, B, R(28) );
//    P( B, C, D, E, A, R(29) );
//    P( A, B, C, D, E, R(30) );
//    P( E, A, B, C, D, R(31) );
//    P( D, E, A, B, C, R(32) );
//    P( C, D, E, A, B, R(33) );
//    P( B, C, D, E, A, R(34) );
//    P( A, B, C, D, E, R(35) );
//    P( E, A, B, C, D, R(36) );
//    P( D, E, A, B, C, R(37) );
//    P( C, D, E, A, B, R(38) );
//    P( B, C, D, E, A, R(39) );
//
//#undef K
//#undef F
//
//#define F(x,y,z) ((x & y) | (z & (x | y)))
//#define K 0x8F1BBCDC
//
//    P( A, B, C, D, E, R(40) );
//    P( E, A, B, C, D, R(41) );
//    P( D, E, A, B, C, R(42) );
//    P( C, D, E, A, B, R(43) );
//    P( B, C, D, E, A, R(44) );
//    P( A, B, C, D, E, R(45) );
//    P( E, A, B, C, D, R(46) );
//    P( D, E, A, B, C, R(47) );
//    P( C, D, E, A, B, R(48) );
//    P( B, C, D, E, A, R(49) );
//    P( A, B, C, D, E, R(50) );
//    P( E, A, B, C, D, R(51) );
//    P( D, E, A, B, C, R(52) );
//    P( C, D, E, A, B, R(53) );
//    P( B, C, D, E, A, R(54) );
//    P( A, B, C, D, E, R(55) );
//    P( E, A, B, C, D, R(56) );
//    P( D, E, A, B, C, R(57) );
//    P( C, D, E, A, B, R(58) );
//    P( B, C, D, E, A, R(59) );
//
//#undef K
//#undef F
//
//#define F(x,y,z) (x ^ y ^ z)
//#define K 0xCA62C1D6
//
//    P( A, B, C, D, E, R(60) );
//    P( E, A, B, C, D, R(61) );
//    P( D, E, A, B, C, R(62) );
//    P( C, D, E, A, B, R(63) );
//    P( B, C, D, E, A, R(64) );
//    P( A, B, C, D, E, R(65) );
//    P( E, A, B, C, D, R(66) );
//    P( D, E, A, B, C, R(67) );
//    P( C, D, E, A, B, R(68) );
//    P( B, C, D, E, A, R(69) );
//    P( A, B, C, D, E, R(70) );
//    P( E, A, B, C, D, R(71) );
//    P( D, E, A, B, C, R(72) );
//    P( C, D, E, A, B, R(73) );
//    P( B, C, D, E, A, R(74) );
//    P( A, B, C, D, E, R(75) );
//    P( E, A, B, C, D, R(76) );
//    P( D, E, A, B, C, R(77) );
//    P( C, D, E, A, B, R(78) );
//    P( B, C, D, E, A, R(79) );
//
//#undef K
//#undef F
//
//    ctx->state[0] += A;
//    ctx->state[1] += B;
//    ctx->state[2] += C;
//    ctx->state[3] += D;
//    ctx->state[4] += E;
//}

#if 0
void sha_transform( u32_t *digest, const char *data, u32_t *array)
{
    unsigned long temp, W[16], A, B, C, D, E;

    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

    A = digest[0];
    B = digest[1];
    C = digest[2];
    D = digest[3];
    E = digest[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P( A, B, C, D, E, W[0]  );
    P( E, A, B, C, D, W[1]  );
    P( D, E, A, B, C, W[2]  );
    P( C, D, E, A, B, W[3]  );
    P( B, C, D, E, A, W[4]  );
    P( A, B, C, D, E, W[5]  );
    P( E, A, B, C, D, W[6]  );
    P( D, E, A, B, C, W[7]  );
    P( C, D, E, A, B, W[8]  );
    P( B, C, D, E, A, W[9]  );
    P( A, B, C, D, E, W[10] );
    P( E, A, B, C, D, W[11] );
    P( D, E, A, B, C, W[12] );
    P( C, D, E, A, B, W[13] );
    P( B, C, D, E, A, W[14] );
    P( A, B, C, D, E, W[15] );
    P( E, A, B, C, D, R(16) );
    P( D, E, A, B, C, R(17) );
    P( C, D, E, A, B, R(18) );
    P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P( A, B, C, D, E, R(20) );
    P( E, A, B, C, D, R(21) );
    P( D, E, A, B, C, R(22) );
    P( C, D, E, A, B, R(23) );
    P( B, C, D, E, A, R(24) );
    P( A, B, C, D, E, R(25) );
    P( E, A, B, C, D, R(26) );
    P( D, E, A, B, C, R(27) );
    P( C, D, E, A, B, R(28) );
    P( B, C, D, E, A, R(29) );
    P( A, B, C, D, E, R(30) );
    P( E, A, B, C, D, R(31) );
    P( D, E, A, B, C, R(32) );
    P( C, D, E, A, B, R(33) );
    P( B, C, D, E, A, R(34) );
    P( A, B, C, D, E, R(35) );
    P( E, A, B, C, D, R(36) );
    P( D, E, A, B, C, R(37) );
    P( C, D, E, A, B, R(38) );
    P( B, C, D, E, A, R(39) );

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P( A, B, C, D, E, R(40) );
    P( E, A, B, C, D, R(41) );
    P( D, E, A, B, C, R(42) );
    P( C, D, E, A, B, R(43) );
    P( B, C, D, E, A, R(44) );
    P( A, B, C, D, E, R(45) );
    P( E, A, B, C, D, R(46) );
    P( D, E, A, B, C, R(47) );
    P( C, D, E, A, B, R(48) );
    P( B, C, D, E, A, R(49) );
    P( A, B, C, D, E, R(50) );
    P( E, A, B, C, D, R(51) );
    P( D, E, A, B, C, R(52) );
    P( C, D, E, A, B, R(53) );
    P( B, C, D, E, A, R(54) );
    P( A, B, C, D, E, R(55) );
    P( E, A, B, C, D, R(56) );
    P( D, E, A, B, C, R(57) );
    P( C, D, E, A, B, R(58) );
    P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P( A, B, C, D, E, R(60) );
    P( E, A, B, C, D, R(61) );
    P( D, E, A, B, C, R(62) );
    P( C, D, E, A, B, R(63) );
    P( B, C, D, E, A, R(64) );
    P( A, B, C, D, E, R(65) );
    P( E, A, B, C, D, R(66) );
    P( D, E, A, B, C, R(67) );
    P( C, D, E, A, B, R(68) );
    P( B, C, D, E, A, R(69) );
    P( A, B, C, D, E, R(70) );
    P( E, A, B, C, D, R(71) );
    P( D, E, A, B, C, R(72) );
    P( C, D, E, A, B, R(73) );
    P( B, C, D, E, A, R(74) );
    P( A, B, C, D, E, R(75) );
    P( E, A, B, C, D, R(76) );
    P( D, E, A, B, C, R(77) );
    P( C, D, E, A, B, R(78) );
    P( B, C, D, E, A, R(79) );

#undef K
#undef F

    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
    digest[4] += E;
}
#else
#define CONFIG_X86 LINUX_PLATFORM
typedef unsigned int __u32;
#ifdef CONFIG_X86
#define setW(x, val) (*(volatile __u32 *)&W(x) = (val))
#elif defined(CONFIG_ARM)
#define setW(x, val) do { W(x) = (val); __asm__("":::"memory"); } while (0)
#else
#define setW(x, val) (W(x) = (val))
#endif

/* This "rolls" over the 512-bit array */
#define W(x) (array[(x)&15])

static inline __u32 get_unaligned_be32(const unsigned char *p)
{
    return ((__u32)p[0] << 24) |  ((__u32)p[1] << 16) |  ((__u32)p[2] << 8) |  ((__u32)p[3]);
}

static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << shift) | (word >> ((-shift) & 31));
}

static inline __u32 ror32(__u32 word, unsigned int shift)
{
    return (word >> shift) | (word << (32 - shift));
}
/*
 * Where do we get the source from? The first 16 iterations get it from
 * the input data, the next mix it from the 512-bit array.
 */
#define SHA_SRC(t) get_unaligned_be32((unsigned char *)((__u32 *)data + t))
#define SHA_MIX(t) rol32(W(t+13) ^ W(t+8) ^ W(t+2) ^ W(t), 1)

#define SHA_ROUND(t, input, fn, constant, A, B, C, D, E) do { \
	__u32 TEMP = input(t); setW(t, TEMP); \
	E += TEMP + rol32(A,5) + (fn) + (constant); \
	B = ror32(B, 2); } while (0)

#define T_0_15(t, A, B, C, D, E)  SHA_ROUND(t, SHA_SRC, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
#define T_16_19(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
#define T_20_39(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) , 0x6ed9eba1, A, B, C, D, E )
#define T_40_59(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, ((B&C)+(D&(B^C))) , 0x8f1bbcdc, A, B, C, D, E )
#define T_60_79(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) ,  0xca62c1d6, A, B, C, D, E )


/**
 * sha_transform - single block SHA1 transform
 *
 * @digest: 160 bit digest to update
 * @data:   512 bits of data to hash
 * @array:  16 words of workspace (see note)
 *
 * This function generates a SHA1 digest for a single 512-bit block.
 * Be warned, it does not handle padding and message digest, do not
 * confuse it with the full FIPS 180-1 digest algorithm for variable
 * length messages.
 *
 * Note: If the hash is security sensitive, the caller should be sure
 * to clear the workspace. This is left to the caller to avoid
 * unnecessary clears between chained hashing operations.
 */
void sha_transform(__u32 *digest, const char *data, __u32 *array)
{
    __u32 A, B, C, D, E;

    A = digest[0];
    B = digest[1];
    C = digest[2];
    D = digest[3];
    E = digest[4];

    /* Round 1 - iterations 0-16 take their input from 'data' */
    T_0_15( 0, A, B, C, D, E);
    T_0_15( 1, E, A, B, C, D);
    T_0_15( 2, D, E, A, B, C);
    T_0_15( 3, C, D, E, A, B);
    T_0_15( 4, B, C, D, E, A);
    T_0_15( 5, A, B, C, D, E);
    T_0_15( 6, E, A, B, C, D);
    T_0_15( 7, D, E, A, B, C);
    T_0_15( 8, C, D, E, A, B);
    T_0_15( 9, B, C, D, E, A);
    T_0_15(10, A, B, C, D, E);
    T_0_15(11, E, A, B, C, D);
    T_0_15(12, D, E, A, B, C);
    T_0_15(13, C, D, E, A, B);
    T_0_15(14, B, C, D, E, A);
    T_0_15(15, A, B, C, D, E);

    /* Round 1 - tail. Input from 512-bit mixing array */
    T_16_19(16, E, A, B, C, D);
    T_16_19(17, D, E, A, B, C);
    T_16_19(18, C, D, E, A, B);
    T_16_19(19, B, C, D, E, A);

    /* Round 2 */
    T_20_39(20, A, B, C, D, E);
    T_20_39(21, E, A, B, C, D);
    T_20_39(22, D, E, A, B, C);
    T_20_39(23, C, D, E, A, B);
    T_20_39(24, B, C, D, E, A);
    T_20_39(25, A, B, C, D, E);
    T_20_39(26, E, A, B, C, D);
    T_20_39(27, D, E, A, B, C);
    T_20_39(28, C, D, E, A, B);
    T_20_39(29, B, C, D, E, A);
    T_20_39(30, A, B, C, D, E);
    T_20_39(31, E, A, B, C, D);
    T_20_39(32, D, E, A, B, C);
    T_20_39(33, C, D, E, A, B);
    T_20_39(34, B, C, D, E, A);
    T_20_39(35, A, B, C, D, E);
    T_20_39(36, E, A, B, C, D);
    T_20_39(37, D, E, A, B, C);
    T_20_39(38, C, D, E, A, B);
    T_20_39(39, B, C, D, E, A);

    /* Round 3 */
    T_40_59(40, A, B, C, D, E);
    T_40_59(41, E, A, B, C, D);
    T_40_59(42, D, E, A, B, C);
    T_40_59(43, C, D, E, A, B);
    T_40_59(44, B, C, D, E, A);
    T_40_59(45, A, B, C, D, E);
    T_40_59(46, E, A, B, C, D);
    T_40_59(47, D, E, A, B, C);
    T_40_59(48, C, D, E, A, B);
    T_40_59(49, B, C, D, E, A);
    T_40_59(50, A, B, C, D, E);
    T_40_59(51, E, A, B, C, D);
    T_40_59(52, D, E, A, B, C);
    T_40_59(53, C, D, E, A, B);
    T_40_59(54, B, C, D, E, A);
    T_40_59(55, A, B, C, D, E);
    T_40_59(56, E, A, B, C, D);
    T_40_59(57, D, E, A, B, C);
    T_40_59(58, C, D, E, A, B);
    T_40_59(59, B, C, D, E, A);

    /* Round 4 */
    T_60_79(60, A, B, C, D, E);
    T_60_79(61, E, A, B, C, D);
    T_60_79(62, D, E, A, B, C);
    T_60_79(63, C, D, E, A, B);
    T_60_79(64, B, C, D, E, A);
    T_60_79(65, A, B, C, D, E);
    T_60_79(66, E, A, B, C, D);
    T_60_79(67, D, E, A, B, C);
    T_60_79(68, C, D, E, A, B);
    T_60_79(69, B, C, D, E, A);
    T_60_79(70, A, B, C, D, E);
    T_60_79(71, E, A, B, C, D);
    T_60_79(72, D, E, A, B, C);
    T_60_79(73, C, D, E, A, B);
    T_60_79(74, B, C, D, E, A);
    T_60_79(75, A, B, C, D, E);
    T_60_79(76, E, A, B, C, D);
    T_60_79(77, D, E, A, B, C);
    T_60_79(78, C, D, E, A, B);
    T_60_79(79, B, C, D, E, A);

    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
    digest[4] += E;
}
#endif

/*
 * SHA-1 process buffer
 */
//void sha1_update( sha1_context *ctx, const unsigned char *input, int ilen )
//{
//    int fill;
//    unsigned long left;
//
//    if( ilen <= 0 )
//        return;
//
//    left = ctx->total[0] & 0x3F;
//    fill = 64 - left;
//
//    ctx->total[0] += ilen;
//    ctx->total[0] &= 0xFFFFFFFF;
//
//    if( ctx->total[0] < (unsigned long) ilen )
//        ctx->total[1]++;
//
//    if( left && ilen >= fill )
//    {
//        MEMCPY( (void *) (ctx->buffer + left),
//                input, fill );
//        sha1_process( ctx, ctx->buffer );
//        input += fill;
//        ilen  -= fill;
//        left = 0;
//    }
//
//    while( ilen >= 64 )
//    {
//        sha1_process( ctx, input );
//        input += 64;
//        ilen  -= 64;
//    }
//
//    if( ilen > 0 )
//    {
//        MEMCPY( (void *) (ctx->buffer + left),
//                input, ilen );
//    }
//}

static const unsigned char sha1_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-1 final digest
 */
//void sha1_finish( sha1_context *ctx, unsigned char output[20] )
//{
//    unsigned long last, padn;
//    unsigned long high, low;
//    unsigned char msglen[8];
//
//    high = ( ctx->total[0] >> 29 )
//         | ( ctx->total[1] <<  3 );
//    low  = ( ctx->total[0] <<  3 );
//
//    PUT_ULONG_BE( high, msglen, 0 );
//    PUT_ULONG_BE( low,  msglen, 4 );
//
//    last = ctx->total[0] & 0x3F;
//    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );
//
//    sha1_update( ctx, sha1_padding, padn );
//    sha1_update( ctx, msglen, 8 );
//
//    PUT_ULONG_BE( ctx->state[0], output,  0 );
//    PUT_ULONG_BE( ctx->state[1], output,  4 );
//    PUT_ULONG_BE( ctx->state[2], output,  8 );
//    PUT_ULONG_BE( ctx->state[3], output, 12 );
//    PUT_ULONG_BE( ctx->state[4], output, 16 );
//}

/*
 * output = SHA-1( input buffer )
 */
//void sha1( unsigned char *input, int ilen, unsigned char output[20] )
//{
//    sha1_context ctx;
//
//    sha1_starts( &ctx );
//    sha1_update( &ctx, input, ilen );
//    sha1_finish( &ctx, output );
//}

//#endif /* PPP_SUPPORT && LWIP_INCLUDED_POLARSSL_SHA1 */
