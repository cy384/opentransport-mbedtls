/*
 *  TCP/IP or UDP/IP networking functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/* Enable definition of getaddrinfo() even when compiling with -std=c99. Must
 * be set before config.h, which pulls in glibc's features.h indirectly.
 * Harmless on other platforms. */
#define _POSIX_C_SOURCE 200112L

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_NET_C)

// TODO figure out the retro68 defines and error on them here
#if 0
#error "This module only works on the Retro68/RetroPPC toolchains"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

#include <string.h>

static int OT_init_done = 0;

// event handler to yield whenever we're blocked
static pascal void yield_notifier(void* contextPtr, OTEventCode code,
                                  OTResult result, void* cookie)
{
    switch (code)
    {
        case kOTSyncIdleEvent:
            YieldToAnyThread();
        default:
            break;
    }
}

static int net_prepare( void )
{
    int ret = 0;

    if (!OT_init_done)
    {
        OSStatus err = InitOpenTransport();
        if (err != noErr)
        {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
        }
        else
        {
            OT_init_done = 1;
        }
    }

    return ret;
}

void mbedtls_net_init(mbedtls_net_context *ctx)
{
    ctx->endpoint = kOTInvalidEndpointRef;
}

// FIXME: add UDP handling
int mbedtls_net_connect(mbedtls_net_context *ctx, const char *host,
                        const char *port, int proto )
{
    if (proto != MBEDTLS_NET_PROTO_TCP) return MBEDTLS_ERR_NET_SOCKET_FAILED;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = net_prepare()) != 0) return ret;

    OSStatus err = noErr;
    TCall remote;
    DNSAddress remote_dns;

    // OT takes a string like "www.example.com:1234"
    // so we need to construct one
    char* host_with_port = malloc(strlen(host) + strlen(port) + 2*sizeof(char));
    strcpy(host_with_port, host);
    host_with_port[strlen(host)] = ':';
    strcpy(host_with_port + strlen(host) + 1, port);

    EndpointRef endpoint = ctx->endpoint;

    // TODO: DRY the error handling
    endpoint = OTOpenEndpoint(OTCreateConfiguration(kTCPName), 0, nil, &err);
    if (err != noErr) return MBEDTLS_ERR_NET_SOCKET_FAILED;

    err = OTSetSynchronous(endpoint);
    if (err != noErr) return MBEDTLS_ERR_NET_SOCKET_FAILED;

    err = OTSetBlocking(endpoint);
    if (err != noErr) return MBEDTLS_ERR_NET_SOCKET_FAILED;

    // FIXME do we really need the event handler thread?
    err = OTInstallNotifier(endpoint, yield_notifier, nil);
    if (err != noErr) return MBEDTLS_ERR_NET_SOCKET_FAILED;

    err = OTUseSyncIdleEvents(endpoint, true);
    if (err != noErr) return MBEDTLS_ERR_NET_SOCKET_FAILED;

    err = OTBind(endpoint, nil, nil);
    if (err != noErr) return MBEDTLS_ERR_NET_SOCKET_FAILED;

    OTMemzero(&remote, sizeof(TCall));

    remote.addr.buf = (UInt8 *) &remote_dns;
    remote.addr.len = OTInitDNSAddress(&remote_dns, host_with_port);

    err = OTConnect(endpoint, &remote, nil);
    if (err != noErr) return MBEDTLS_ERR_NET_UNKNOWN_HOST;

    free(host_with_port);
    return 0;
}

// FIXME: probably not going to implement this
int mbedtls_net_bind( mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto )
{
    return -1;
}

// we're only going to support blocking operations
static int net_would_block( const mbedtls_net_context *ctx )
{
    return 0;
}

// FIXME: probably not going to implement this
int mbedtls_net_accept( mbedtls_net_context *bind_ctx,
                        mbedtls_net_context *client_ctx,
                        void *client_ip, size_t buf_size, size_t *ip_len )
{
    return -1;
}

// always blocking
int mbedtls_net_set_block( mbedtls_net_context *ctx )
{
    return 0;
}

// TODO: not sure what the best thing to return is, since we only block
int mbedtls_net_set_nonblock( mbedtls_net_context *ctx )
{
    return -1;
}

// very not sure this is correct, so probably don't use it
int mbedtls_net_poll( mbedtls_net_context *ctx, uint32_t rw, uint32_t timeout )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ctx->endpoint == kOTInvalidEndpointRef)
    {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    OTResult look = OTLook(ctx->endpoint);
    switch (look)
    {
        case T_DATA:
        case T_EXDATA:
            return MBEDTLS_NET_POLL_READ;
            break;
        default:
            ret = 0;
            break;
    }

    return ret;
}

// Ugly but probably as good as we can get. Quote the documentation:
// "You should never call the OTIdle function in production code on a Macintosh
//  computer."
void mbedtls_net_usleep( unsigned long usec )
{
    OTTimeStamp start, end, delta;
    OTGetTimeStamp(&start);

    int done = 0;

    while (!done)
    {
        OTGetTimeStamp(&end);
        OTSubtractTimeStamps(&delta, &start, &end);

        if (OTTimeStampInMicroseconds(&delta) > usec)
        {
            done = 1;
        }
        else
        {
            OTIdle();
        }
    }
}

int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    OTFlags unused_flags;
    OTResult look;
    EndpointRef endpoint = ((mbedtls_net_context*)ctx)->endpoint;
    OSStatus err = noErr;

    if (endpoint == kOTInvalidEndpointRef)
    {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    ret = OTRcv(endpoint, (void *) buf, len, &unused_flags);

    // TODO: handle more error cases
    // TODO: make this less ugly
    if (ret < 0)
    {
        switch (ret)
        {
            case kOTLookErr:
            {
                look = OTLook(endpoint);
                switch (look)
                {
                    case T_DISCONNECT:
                        OTRcvDisconnect(endpoint, nil);
                        ret = MBEDTLS_ERR_NET_CONN_RESET;
                        break;
                    case T_ORDREL:
                        err = OTRcvOrderlyDisconnect(endpoint);
                        if (err == noErr) OTSndOrderlyDisconnect(endpoint);
                        ret = MBEDTLS_ERR_NET_RECV_FAILED;
                        break;
                    default:
                        ret = MBEDTLS_ERR_NET_RECV_FAILED;
                        break;
                }
                break;
            default:
                ret = MBEDTLS_ERR_NET_RECV_FAILED;
                break;
            }
        }
    }

    return ret;
}

// OT doesn't seem to nicely support timeouts on operations
int mbedtls_net_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                             uint32_t timeout)
{
    return mbedtls_net_recv(ctx, buf, len);
}

// TODO: make this work for both UDP and TCP
// FIXME: only does TCP now
int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
    // don't try to send on an unopened endpoint

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    EndpointRef endpoint = ((mbedtls_net_context*)ctx)->endpoint;

    if (endpoint == kOTInvalidEndpointRef)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int sent = OTSnd(endpoint, (void *) buf, len, 0);

    if (sent < 0)
    {
        // TODO: handle cases more nicely and return correct errors
        ret = MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}

void mbedtls_net_close(mbedtls_net_context *ctx)
{
    // don't try to close an unopened endpoint
    if (ctx->endpoint == kOTInvalidEndpointRef) return;

    // ignore returned errors: we can't do handle them usefully here
    OTUnbind(ctx->endpoint);
    OTCloseProvider(ctx->endpoint);
    ctx->endpoint = kOTInvalidEndpointRef;
}

void mbedtls_net_free(mbedtls_net_context *ctx)
{
    // not really sure what the best way to translate this to Open Transport is
    // TODO: do an OTSndOrderlyDisconnect or something?
    mbedtls_net_close(ctx);
}

#endif /* MBEDTLS_NET_C */
