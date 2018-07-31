/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file contains function prototypes for a TLS layer.
 */

/*
 * Copyright (c) 2017 Simon Goldschmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 *
 */
#ifndef LWIP_HDR_ALTCP_TLS_H
#define LWIP_HDR_ALTCP_TLS_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "altcp_tls_opts.h"

#if LWIP_ALTCP_TLS

#include "lwip/altcp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct altcp_tls_config;

struct altcp_tls_config *altcp_tls_create_config_server_privkey_cert(const u8_t *privkey, size_t privkey_len,
                            const u8_t *privkey_pass, size_t privkey_pass_len,
                            const u8_t *cert, size_t cert_len);
struct altcp_tls_config *altcp_tls_create_config_client(const u8_t *cert, size_t cert_len);

struct altcp_pcb *altcp_tls_new(struct altcp_tls_config* config, struct altcp_pcb *inner_pcb);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP_TLS */
#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_TLS_H */
