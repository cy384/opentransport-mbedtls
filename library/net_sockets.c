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

// ??? TODO
#define read(fd,buf,len)        recv( fd, (char*)( buf ), (int)( len ), 0 )
#define write(fd,buf,len)       send( fd, (char*)( buf ), (int)( len ), 0 )
#define close(fd)               closesocket(fd)

static int OT_init_done = 0;


/*
 * Prepare for using the OT interface
 */
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

/*
 * Initialize a context
 */
void mbedtls_net_init( mbedtls_net_context *ctx )
{
    ctx->endpoint = kOTInvalidEndpointRef;
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int mbedtls_net_connect( mbedtls_net_context *ctx, const char *host,
                         const char *port, int proto )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if((ret = net_prepare()) != 0) return ret;

/*
    struct addrinfo hints, *addr_list, *cur;




    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if( getaddrinfo( host, port, &hints, &addr_list ) != 0 )
        return( MBEDTLS_ERR_NET_UNKNOWN_HOST );


    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
        ctx->fd = (int) socket( cur->ai_family, cur->ai_socktype,
                            cur->ai_protocol );
        if( ctx->fd < 0 )
        {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if( connect( ctx->fd, cur->ai_addr, MSVC_INT_CAST cur->ai_addrlen ) == 0 )
        {
            ret = 0;
            break;
        }

        close( ctx->fd );
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo( addr_list );
*/
    return( ret );
}

/*
 * Create a listening socket on bind_ip:port
 */
int mbedtls_net_bind( mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto )
{
    int n;
    int ret = 0;

    if ((ret = net_prepare()) != 0) return ret;

/*
    struct addrinfo hints, *addr_list, *cur;



    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;
    if( bind_ip == NULL )
        hints.ai_flags = AI_PASSIVE;

    if( getaddrinfo( bind_ip, port, &hints, &addr_list ) != 0 )
        return( MBEDTLS_ERR_NET_UNKNOWN_HOST );

    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
        ctx->fd = (int) socket( cur->ai_family, cur->ai_socktype,
                            cur->ai_protocol );
        if( ctx->fd < 0 )
        {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        n = 1;
        if( setsockopt( ctx->fd, SOL_SOCKET, SO_REUSEADDR,
                        (const char *) &n, sizeof( n ) ) != 0 )
        {
            close( ctx->fd );
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if( bind( ctx->fd, cur->ai_addr, MSVC_INT_CAST cur->ai_addrlen ) != 0 )
        {
            close( ctx->fd );
            ret = MBEDTLS_ERR_NET_BIND_FAILED;
            continue;
        }

        if( proto == MBEDTLS_NET_PROTO_TCP )
        {
            if( listen( ctx->fd, MBEDTLS_NET_LISTEN_BACKLOG ) != 0 )
            {
                close( ctx->fd );
                ret = MBEDTLS_ERR_NET_LISTEN_FAILED;
                continue;
            }
        }


        ret = 0;
        break;
    }

    freeaddrinfo( addr_list );
*/
    return( ret );

}


/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 *
 * Note: on a blocking socket this function always returns 0!
 */
// we're only going to support blocking operations
static int net_would_block( const mbedtls_net_context *ctx )
{
    return 0;
}

/*
 * Accept a connection from a remote client
 */
int mbedtls_net_accept( mbedtls_net_context *bind_ctx,
                        mbedtls_net_context *client_ctx,
                        void *client_ip, size_t buf_size, size_t *ip_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
/*
    int type;

    struct sockaddr_storage client_addr;

#if defined(__socklen_t_defined) || defined(_SOCKLEN_T) ||  \
    defined(_SOCKLEN_T_DECLARED) || defined(__DEFINED_socklen_t)
    socklen_t n = (socklen_t) sizeof( client_addr );
    socklen_t type_len = (socklen_t) sizeof( type );
#else
    int n = (int) sizeof( client_addr );
    int type_len = (int) sizeof( type );
#endif

    if( getsockopt( bind_ctx->fd, SOL_SOCKET, SO_TYPE,
                    (void *) &type, &type_len ) != 0 ||
        ( type != SOCK_STREAM && type != SOCK_DGRAM ) )
    {
        return( MBEDTLS_ERR_NET_ACCEPT_FAILED );
    }

    if( type == SOCK_STREAM )
    {
        ret = client_ctx->fd = (int) accept( bind_ctx->fd,
                                             (struct sockaddr *) &client_addr, &n );
    }
    else
    {
        char buf[1] = { 0 };

        ret = (int) recvfrom( bind_ctx->fd, buf, sizeof( buf ), MSG_PEEK,
                        (struct sockaddr *) &client_addr, &n );

#if defined(_WIN32)
        if( ret == SOCKET_ERROR &&
            WSAGetLastError() == WSAEMSGSIZE )
        {
            ret = 0;
        }
#endif
    }

    if( ret < 0 )
    {
        if( net_would_block( bind_ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_READ );

        return( MBEDTLS_ERR_NET_ACCEPT_FAILED );
    }


    if( type != SOCK_STREAM )
    {
        struct sockaddr_storage local_addr;
        int one = 1;

        if( connect( bind_ctx->fd, (struct sockaddr *) &client_addr, n ) != 0 )
            return( MBEDTLS_ERR_NET_ACCEPT_FAILED );

        client_ctx->fd = bind_ctx->fd;
        bind_ctx->fd   = -1; 

        n = sizeof( struct sockaddr_storage );
        if( getsockname( client_ctx->fd,
                         (struct sockaddr *) &local_addr, &n ) != 0 ||
            ( bind_ctx->fd = (int) socket( local_addr.ss_family,
                                           SOCK_DGRAM, IPPROTO_UDP ) ) < 0 ||
            setsockopt( bind_ctx->fd, SOL_SOCKET, SO_REUSEADDR,
                        (const char *) &one, sizeof( one ) ) != 0 )
        {
            return( MBEDTLS_ERR_NET_SOCKET_FAILED );
        }

        if( bind( bind_ctx->fd, (struct sockaddr *) &local_addr, n ) != 0 )
        {
            return( MBEDTLS_ERR_NET_BIND_FAILED );
        }
    }

    if( client_ip != NULL )
    {
        if( client_addr.ss_family == AF_INET )
        {
            struct sockaddr_in *addr4 = (struct sockaddr_in *) &client_addr;
            *ip_len = sizeof( addr4->sin_addr.s_addr );

            if( buf_size < *ip_len )
                return( MBEDTLS_ERR_NET_BUFFER_TOO_SMALL );

            memcpy( client_ip, &addr4->sin_addr.s_addr, *ip_len );
        }
        else
        {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &client_addr;
            *ip_len = sizeof( addr6->sin6_addr.s6_addr );

            if( buf_size < *ip_len )
                return( MBEDTLS_ERR_NET_BUFFER_TOO_SMALL );

            memcpy( client_ip, &addr6->sin6_addr.s6_addr, *ip_len);
        }
    }
*/
    return( 0 );
}

/*
 * Set the socket blocking or non-blocking
 */
int mbedtls_net_set_block( mbedtls_net_context *ctx )
{
    return 0;
}

// TODO: not sure what the best thing to return is, since we only block
int mbedtls_net_set_nonblock( mbedtls_net_context *ctx )
{
    return -1;
}

/*
 * Check if data is available on the socket
 */

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
            // TODO: is this correct?
            return MBEDTLS_NET_POLL_READ;
            break;
        default:
            ret = 0;
            break;
    }
/*
    struct timeval tv;

    fd_set read_fds;
    fd_set write_fds;

    int fd = ctx->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    memset( &read_fds, 0, sizeof( read_fds ) );
    memset( &write_fds, 0, sizeof( write_fds ) );
#endif
#endif

    FD_ZERO( &read_fds );
    if( rw & MBEDTLS_NET_POLL_READ )
    {
        rw &= ~MBEDTLS_NET_POLL_READ;
        FD_SET( fd, &read_fds );
    }

    FD_ZERO( &write_fds );
    if( rw & MBEDTLS_NET_POLL_WRITE )
    {
        rw &= ~MBEDTLS_NET_POLL_WRITE;
        FD_SET( fd, &write_fds );
    }

    if( rw != 0 )
        return( MBEDTLS_ERR_NET_BAD_INPUT_DATA );

    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = ( timeout % 1000 ) * 1000;

    do
    {
        ret = select( fd + 1, &read_fds, &write_fds, NULL,
                      timeout == (uint32_t) -1 ? NULL : &tv );
    }
    while( IS_EINTR( ret ) );

    if( ret < 0 )
        return( MBEDTLS_ERR_NET_POLL_FAILED );

    ret = 0;
    if( FD_ISSET( fd, &read_fds ) )
        ret |= MBEDTLS_NET_POLL_READ;
    if( FD_ISSET( fd, &write_fds ) )
        ret |= MBEDTLS_NET_POLL_WRITE;
*/
    return( ret );
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

/*
 * Read at most 'len' characters
 */
int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
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
/*
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );

    ret = (int) read( fd, buf, len );

    if( ret < 0 )
    {
        if( net_would_block( ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_READ );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_READ );
#endif

        return( MBEDTLS_ERR_NET_RECV_FAILED );
    }
*/
}

// OT doesn't seem to nicely support timeouts on operations
int mbedtls_net_recv_timeout( void *ctx, unsigned char *buf,
                              size_t len, uint32_t timeout )
{
    return mbedtls_net_recv(ctx, buf, len);
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
/*
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );

    ret = (int) write( fd, buf, len );

    if( ret < 0 )
    {
        if( net_would_block( ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_WRITE );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_WRITE );
#endif

        return( MBEDTLS_ERR_NET_SEND_FAILED );
    }
*/
    return ret;
}

/*
 * Close the connection
 */
void mbedtls_net_close( mbedtls_net_context *ctx )
{
    // don't try to close an unopened endpoint
    if (ctx->endpoint == kOTInvalidEndpointRef) return;

    // ignore returned errors: we can't do handle them usefully here
    OTUnbind(ctx->endpoint);
    OTCloseProvider(ctx->endpoint);
    ctx->endpoint = kOTInvalidEndpointRef;
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free( mbedtls_net_context *ctx )
{
    // not really sure what the best way to translate this to Open Transport is
    // TODO: do an OTSndOrderlyDisconnect or something?
    mbedtls_net_close(ctx);
}

#endif /* MBEDTLS_NET_C */
