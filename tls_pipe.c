
#include <tinylib/net/loop.h>
#include <tinylib/util/log.h>

#include <openssl/ssl.h>

#if defined(WIN32)
  #include "tinylib/windows/net/socket.h"

  #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32")
  #endif

#elif defined(__linux__)
  #define _GNU_SOURCE
  #define __USE_GNU
  #include <fcntl.h>
  #include <unistd.h>
  #include <errno.h>
  #include <sys/types.h>
  #include <sys/socket.h>

  #include <sys/epoll.h>
  #define POLLIN EPOLLIN
  #define POLLOUT EPOLLOUT
  #define POLLHUP EPOLLHUP
  #define POLLERR EPOLLERR
  
  #define SOCKET int
  #define closesocket close
#endif

#include <stdio.h>

enum tls_state
{
    TLS_STATE_HANDSHAKE,
    TLS_STATE_SNDRCV,
};

/************************************************************/

typedef struct tls_client{
    SOCKET fd;
    loop_t *loop;
    channel_t *channel;
    
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    enum tls_state tls_state;
} tls_client_t;

static
void on_tls_client_event(SOCKET fd, int event, void* userdata)
{
    tls_client_t *tls_client = (tls_client_t*)userdata;
    int ssl_ret;
    int ssl_error;

    if (tls_client->tls_state == TLS_STATE_HANDSHAKE)
    {
        if (event & (POLLHUP | POLLERR))
        {
            log_error("tls client handshake failed: IO failure, sys error: %d", errno);
        }
        else
        {
            ssl_ret = SSL_connect(tls_client->ssl);
            ssl_error = SSL_get_error(tls_client->ssl, ssl_ret);
            if (ssl_ret == 1)
            {
                tls_client->tls_state = TLS_STATE_SNDRCV;
                log_info("=== tls client handshake OK ===");
            }
            else if (ssl_ret < 0 && (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE))
            {
                /* keep going and nothing todo */
            }
            else
            {
                log_error("tls client handshake failed: fatal ssl error: %d, sys error: %d", ssl_error, errno);
            }
        }
    }
    else if (tls_client->tls_state == TLS_STATE_SNDRCV)
    {
        /* TODO */
    }
    
    return;
}

static
int tls_client_start(tls_client_t* tls_client, SOCKET fd, loop_t *loop)
{
    int ssl_ret;
    int ssl_error;
    
    tls_client->fd = fd;
    tls_client->loop = loop;
    tls_client->channel = channel_new(fd, loop, on_tls_client_event, tls_client);
    channel_setevent(tls_client->channel, POLLIN);

    tls_client->tls_state = TLS_STATE_HANDSHAKE;
    
    tls_client->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());;
    SSL_CTX_set_mode(tls_client->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY);
    tls_client->ssl = SSL_new(tls_client->ssl_ctx);
    SSL_set_fd(tls_client->ssl, fd);

    ssl_ret = SSL_connect(tls_client->ssl);
    ssl_error = SSL_get_error(tls_client->ssl, ssl_ret);
    if (ssl_ret == 1)
    {
        tls_client->tls_state = TLS_STATE_SNDRCV;
        log_info("=== tls client handshake OK ===");
    }
    else if (ssl_ret < 0 && (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE))
    {
        /* keep going and nothing todo */
    }
    else
    {
        log_error("failed to start tls client handshake: fatal ssl error: %d, sys error: %d", ssl_error, errno);
        return -1;
    }

    return 0;
}

static
void tls_client_stop(tls_client_t* tls_client)
{
    if (tls_client->tls_state == TLS_STATE_SNDRCV)
    {
        SSL_shutdown(tls_client->ssl);
    }

    SSL_free(tls_client->ssl);
    SSL_CTX_free(tls_client->ssl_ctx);
    channel_detach(tls_client->channel);
    channel_destroy(tls_client->channel);

    return;
}

/************************************************************/

typedef struct tls_server{
    SOCKET fd;
    loop_t *loop;
    channel_t *channel;
    
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    enum tls_state tls_state;
} tls_server_t;

static
void on_tls_server_event(SOCKET fd, int event, void* userdata)
{
    tls_server_t *tls_server = (tls_server_t*)userdata;
    int ssl_ret;
    int ssl_error;

    if (tls_server->tls_state == TLS_STATE_HANDSHAKE)
    {
        if (event & (POLLHUP | POLLERR))
        {
            log_error("tls server handshake failed: IO failure, sys error: %d", errno);
        }
        else
        {
            ssl_ret = SSL_accept(tls_server->ssl);
            ssl_error = SSL_get_error(tls_server->ssl, ssl_ret);
            if (ssl_ret == 1)
            {
                tls_server->tls_state = TLS_STATE_SNDRCV;
                log_info("=== tls server handshake OK ===");
            }
            else if (ssl_ret < 0 && (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE))
            {
                /* keep going and nothing todo */
            }
            else
            {
                log_error("tls server handshake failed: fatal ssl error: %d, sys error: %d", ssl_error, errno);
            }
        }
    }
    else if (tls_server->tls_state == TLS_STATE_SNDRCV)
    {
        /* TODO */
    }

    return;
}

static
int tls_server_start
(
    tls_server_t* tls_server, SOCKET fd, loop_t *loop,
    const char* ca_file, const char *private_key_file, const char *ca_pwd
)
{
    int ssl_ret;
    int ssl_error;
    
    tls_server->fd = fd;
    tls_server->loop = loop;
    tls_server->channel = channel_new(fd, loop, on_tls_server_event, tls_server);
    channel_setevent(tls_server->channel, POLLIN);

    tls_server->tls_state = TLS_STATE_HANDSHAKE;

    tls_server->ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());;
    SSL_CTX_set_mode(tls_server->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY);
    tls_server->ssl = SSL_new(tls_server->ssl_ctx);
    SSL_set_fd(tls_server->ssl, fd);

    ssl_ret = SSL_use_certificate_file(tls_server->ssl, ca_file, SSL_FILETYPE_PEM);
    if (ssl_ret != 1)
    {
        ssl_error = SSL_get_error(tls_server->ssl, ssl_ret);
        log_error("tls server: failed to load CA, ssl errno: %d", ssl_error);
        return -1;
    }

    if (private_key_file && (ssl_ret = SSL_use_PrivateKey_file(tls_server->ssl, private_key_file, SSL_FILETYPE_PEM)) != 1)
    {
        ssl_error = SSL_get_error(tls_server->ssl, ssl_ret);
        log_error("tls server: failed to load CA private key, ssl errno: %d", ssl_error);
        return -1;
    }

    ssl_ret = SSL_check_private_key(tls_server->ssl);
    if (ssl_ret != 1)
    {
        ssl_error = SSL_get_error(tls_server->ssl, ssl_ret);
        log_error("tls server: check ssl private key failed, ssl errno: %d", ssl_error);
        return -1;
    }

    return 0;
}

static
void tls_server_stop(tls_server_t* tls_server)
{
    if (tls_server->tls_state == TLS_STATE_SNDRCV)
    {
        SSL_shutdown(tls_server->ssl);
    }

    SSL_free(tls_server->ssl);
    SSL_CTX_free(tls_server->ssl_ctx);
    channel_detach(tls_server->channel);
    channel_destroy(tls_server->channel);

    return;
}

/************************************************************/

int main(int argc, char *argv[])
{
    SOCKET fds[2];
    loop_t *loop;

    tls_client_t tls_client;
    tls_server_t tls_server;
    
    if (argc < 4)
    {
        printf("usage: %s <ca file> <key file> <ca pwd>\n", argv[0]);
        return -1;
    }
    
    SSL_library_init();
    SSL_load_error_strings();

  #if defined(WIN32)
    {
        WSADATA wsadata;
        WSAStartup(MAKEWORD(2, 2), &wsadata);
    }
    socketpair(fds);
  #elif defined(__linux__)
    /* 给 openssl 底层数据交换的 fd 必须是双向读写的，因而只能用 socketpair() 而不是 pipe() */
    socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds);
  #endif
    loop = loop_new(64);

    tls_client_start(&tls_client, fds[0], loop);
    tls_server_start(&tls_server, fds[1], loop, argv[1], argv[2], argv[3]);

    loop_loop(loop);

    tls_client_stop(&tls_client);
    tls_server_stop(&tls_server);

    loop_destroy(loop);

    closesocket(fds[0]);
    closesocket(fds[1]);

  #if defined(WIN32)
    WSACleanup();
  #endif

    return 0;
}