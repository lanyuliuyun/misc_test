
#include <tinylib/net/loop.h>
#include <tinylib/net/buffer.h>
#include <tinylib/util/log.h>

#include <openssl/ssl.h>

#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <sys/epoll.h>
#define POLLIN EPOLLIN
#define POLLOUT EPOLLOUT
#define POLLHUP EPOLLHUP
#define POLLERR EPOLLERR

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/************************************************************/

#if defined(USE_STREAM_BIO)

struct stream_bio_private{
    int fd;
    buffer_t *in_buffer;
    buffer_t *out_buffer;
};

static
int stream_bio_bwrite(BIO *b, const char *in, int inl)
{
    struct stream_bio_private *priv = (struct stream_bio_private*)b->ptr;
    
    int result;
    void *pending_data;
    int pending_data_len;

    buffer_append(priv->out_buffer, &inl, sizeof(inl));
    buffer_append(priv->out_buffer, in, inl);

    /* TODO: optimize write routine */

    pending_data = buffer_peek(priv->out_buffer);
    pending_data_len = (int)buffer_readablebytes(priv->out_buffer);
    result = write(priv->fd, pending_data, pending_data_len);
    BIO_clear_retry_flags(b);
    if (result >= 0)
    {
        buffer_retrieve(priv->out_buffer, result);
        if (result < pending_data_len)
        {
            BIO_set_retry_write(b);
        }
    }
    else
    {
        BIO_set_retry_write(b);
    }

    return inl;
}

static
int stream_bio_bread(BIO *b, char *out, int outl)
{
    struct stream_bio_private *priv = (struct stream_bio_private*)b->ptr;

    int result;
    char *pending_data;
    int pending_data_len;

    buffer_readFd(priv->in_buffer, priv->fd);
    BIO_clear_retry_flags(b);

    pending_data = (char*)buffer_peek(priv->in_buffer);
    pending_data_len = (int)buffer_readablebytes(priv->in_buffer);
    if (pending_data_len > 0)
    {
        int copy_bytes;
        int packet_len = *(int*)pending_data;
        if ((packet_len + sizeof(packet_len)) > pending_data_len)
        {
            BIO_set_retry_read(b);
            return -1;
        }

        copy_bytes = (packet_len >= outl) ? outl : packet_len;
        memcpy(out, pending_data+sizeof(packet_len), copy_bytes);
        buffer_retrieve(priv->in_buffer, (packet_len + sizeof(packet_len)));
        return copy_bytes;
    }
    else
    {
        BIO_set_retry_read(b);
        return -1;
    }
}

static
int stream_bio_bputs(BIO *b, const char *str)
{
    return stream_bio_bwrite(b, str, (int)strlen(str));
}

static
long stream_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    struct stream_bio_private *priv = (struct stream_bio_private*)b->ptr;

    int ret = 1;
    switch(cmd)
    {
        case BIO_C_SET_FD:
        {
            priv->fd = *(int*)ptr;
            break;
        }
        case BIO_C_GET_FD:
        {
            *(int*)ptr = priv->fd;
            ret = priv->fd;
            break;
        }
        case BIO_CTRL_GET_CLOSE:
        {
            ret = BIO_NOCLOSE;
            break;
        }
      #if 0
        case BIO_CTRL_SET_CLOSE:
        {
            break;
        }
        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
        {
            break;
        }
        case BIO_CTRL_DGRAM_QUERY_MTU:
        {
            ret = 1500;
            break;
        }
        case BIO_CTRL_DGRAM_SET_MTU:
        {
            ret = num;
            break;
        }
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        {
            ret = 28;
            break;
        }
        case BIO_CTRL_WPENDING:
        {
            ret = 0;
            break;
        }
        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        {
            break;
        }
        case BIO_CTRL_PUSH:
        {
            BIO *lb = (BIO*)ptr;
            BIO_set_next(b, lb);
            break;
        }
      #endif
        default:
        {
            return 0;
        }
    }
    
    return ret;
}
    
static
int stream_bio_create(BIO *b)
{
    struct stream_bio_private *priv = (struct stream_bio_private*)malloc(sizeof(*priv));

    priv->in_buffer = buffer_new(4096);
    priv->out_buffer = buffer_new(4096);
    b->ptr = priv;
    b->init = 1;
    b->shutdown = 0;
    b->num = 0;

    return 1;
}

static
int stream_bio_destroy(BIO *b)
{
    struct stream_bio_private *priv = (struct stream_bio_private*)b->ptr;

    b->ptr = NULL;
    if (priv != NULL)
    {
        buffer_destory(priv->in_buffer);
        buffer_destory(priv->out_buffer);
        free(priv);
    }

    return 1;
}

#if 0
BIO_METHOD *stream_bio_method_new(void)
{
    BIO_METHOD *bio_method = BIO_meth_new(BIO_TYPE_SOCKET, "stream_packet");
    BIO_meth_set_write(bio_method, stream_bio_bwrite);
    BIO_meth_set_read(bio_method, stream_bio_bread);
    BIO_meth_set_puts(bio_method, stream_bio_bputs);
    BIO_meth_set_ctrl(bio_method, stream_bio_ctrl);
    BIO_meth_set_create(bio_method, stream_bio_create);
    BIO_meth_set_destroy(bio_method, stream_bio_destroy);

    return bio_method;
}
#else

BIO_METHOD stream_bio_method = {
    BIO_TYPE_SOCKET,
    "stream_packet",
    stream_bio_bwrite,
    stream_bio_bread,
    stream_bio_bputs,
    NULL,
    stream_bio_ctrl,
    stream_bio_create,
    stream_bio_destroy,
    NULL
};
#endif

#endif

/************************************************************/

enum dtls_state
{
    DTLS_STATE_HANDSHAKE,
    DTLS_STATE_SNDRCV,
};

/************************************************************/

typedef struct dtls_client{
    int fd;
    loop_t *loop;
    channel_t *channel;
    
    SSL_CTX *ssl_ctx;
    SSL *ssl;
  #if defined(USE_STREAM_BIO)
    BIO *bio;
  #endif

    enum dtls_state dtls_state;
} dtls_client_t;

static
void on_dtls_client_event(int fd, int event, void* userdata)
{
    dtls_client_t *dtls_client = (dtls_client_t*)userdata;
    int ssl_ret;
    int ssl_error;

    if (dtls_client->dtls_state == DTLS_STATE_HANDSHAKE)
    {
        if (event & (POLLHUP | POLLERR))
        {
            log_error("dtls client handshake failed: IO failure, sys error: %d", errno);
        }
        else
        {
            ssl_ret = SSL_do_handshake(dtls_client->ssl);
            ssl_error = SSL_get_error(dtls_client->ssl, ssl_ret);
            if (ssl_ret == 1)
            {
                dtls_client->dtls_state = DTLS_STATE_SNDRCV;
                log_info("=== dtls client handshake OK ===");
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
    else if (dtls_client->dtls_state == DTLS_STATE_SNDRCV)
    {
        /* TODO */
    }
    
    return;
}

static
int dtls_client_start(dtls_client_t* dtls_client, int fd, loop_t *loop)
{
    int ssl_ret;
    int ssl_error;
    
    dtls_client->fd = fd;
    dtls_client->loop = loop;
    dtls_client->channel = channel_new(fd, loop, on_dtls_client_event, dtls_client);
    channel_setevent(dtls_client->channel, POLLIN);

    dtls_client->dtls_state = DTLS_STATE_HANDSHAKE;
    
    dtls_client->ssl_ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_mode(dtls_client->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY);
    dtls_client->ssl = SSL_new(dtls_client->ssl_ctx);
  #if defined(USE_STREAM_BIO)
    dtls_client->bio = BIO_new(&stream_bio_method);
    BIO_set_fd(dtls_client->bio, fd, BIO_NOCLOSE);
    SSL_set_bio(dtls_client->ssl, dtls_client->bio, dtls_client->bio);
  #else
    SSL_set_fd(dtls_client->ssl, fd);
  #endif

    SSL_set_connect_state(dtls_client->ssl);
    ssl_ret = SSL_do_handshake(dtls_client->ssl);
    ssl_error = SSL_get_error(dtls_client->ssl, ssl_ret);
    if (ssl_ret == 1)
    {
        dtls_client->dtls_state = DTLS_STATE_SNDRCV;
        log_info("=== dtls client handshake OK ===");
    }
    else if (ssl_ret < 0 && (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE))
    {
        /* keep going and nothing todo */
    }
    else
    {
        log_error("failed to start dtls client handshake: fatal ssl error: %d, sys error: %d", ssl_error, errno);
        return -1;
    }

    return 0;
}

static
void dtls_client_stop(dtls_client_t* dtls_client)
{
    if (dtls_client->dtls_state == DTLS_STATE_SNDRCV)
    {
        SSL_shutdown(dtls_client->ssl);
    }

    SSL_free(dtls_client->ssl);
    SSL_CTX_free(dtls_client->ssl_ctx);
  #if defined(USE_STREAM_BIO)
    BIO_free(dtls_client->bio);
  #endif
    channel_detach(dtls_client->channel);
    channel_destroy(dtls_client->channel);

    return;
}

/************************************************************/

typedef struct dtls_server{
    int fd;
    loop_t *loop;
    channel_t *channel;
    
    SSL_CTX *ssl_ctx;
    SSL *ssl;
  #if defined(USE_STREAM_BIO)
    BIO *bio;
  #endif

    enum dtls_state dtls_state;
} dtls_server_t;

static
void on_dtls_server_event(int fd, int event, void* userdata)
{
    dtls_server_t *dtls_server = (dtls_server_t*)userdata;
    int ssl_ret;
    int ssl_error;

    if (dtls_server->dtls_state == DTLS_STATE_HANDSHAKE)
    {
        if (event & (POLLHUP | POLLERR))
        {
            log_error("tls server handshake failed: IO failure, sys error: %d", errno);
        }
        else
        {
            ssl_ret = SSL_do_handshake(dtls_server->ssl);
            ssl_error = SSL_get_error(dtls_server->ssl, ssl_ret);
            if (ssl_ret == 1)
            {
                dtls_server->dtls_state = DTLS_STATE_SNDRCV;
                log_info("=== dtls server handshake OK ===");
            }
            else if (ssl_ret < 0 && (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE))
            {
                /* keep going and nothing todo */
            }
            else
            {
                log_error("dtls server handshake failed: fatal ssl error: %d, sys error: %d", ssl_error, errno);
            }
        }
    }
    else if (dtls_server->dtls_state == DTLS_STATE_SNDRCV)
    {
        /* TODO */
    }

    return;
}

static
int dtls_server_start
(
    dtls_server_t* dtls_server, int fd, loop_t *loop,
    const char* ca_file, const char *private_key_file, const char *ca_pwd
)
{
    int ssl_ret;
    int ssl_error;
    
    dtls_server->fd = fd;
    dtls_server->loop = loop;
    dtls_server->channel = channel_new(fd, loop, on_dtls_server_event, dtls_server);
    channel_setevent(dtls_server->channel, POLLIN);

    dtls_server->dtls_state = DTLS_STATE_HANDSHAKE;

    dtls_server->ssl_ctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_set_mode(dtls_server->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY);
    dtls_server->ssl = SSL_new(dtls_server->ssl_ctx);

  #if defined(USE_STREAM_BIO)
    dtls_server->bio = BIO_new(&stream_bio_method);
    BIO_set_fd(dtls_server->bio, fd, BIO_NOCLOSE);

    SSL_set_bio(dtls_server->ssl, dtls_server->bio, dtls_server->bio);
  #else
    SSL_set_fd(dtls_server->ssl, fd);
  #endif

    SSL_set_accept_state(dtls_server->ssl);

    ssl_ret = SSL_use_certificate_file(dtls_server->ssl, ca_file, SSL_FILETYPE_PEM);
    if (ssl_ret != 1)
    {
        ssl_error = SSL_get_error(dtls_server->ssl, ssl_ret);
        log_error("tls server: failed to load CA, ssl errno: %d", ssl_error);
        return -1;
    }

    if (private_key_file && (ssl_ret = SSL_use_PrivateKey_file(dtls_server->ssl, private_key_file, SSL_FILETYPE_PEM)) != 1)
    {
        ssl_error = SSL_get_error(dtls_server->ssl, ssl_ret);
        log_error("tls server: failed to load CA private key, ssl errno: %d", ssl_error);
        return -1;
    }

    ssl_ret = SSL_check_private_key(dtls_server->ssl);
    if (ssl_ret != 1)
    {
        ssl_error = SSL_get_error(dtls_server->ssl, ssl_ret);
        log_error("tls server: check ssl private key failed, ssl errno: %d", ssl_error);
        return -1;
    }

    return 0;
}

static
void dtls_server_stop(dtls_server_t* dtls_server)
{
    if (dtls_server->dtls_state == DTLS_STATE_SNDRCV)
    {
        SSL_shutdown(dtls_server->ssl);
    }

    SSL_free(dtls_server->ssl);
    SSL_CTX_free(dtls_server->ssl_ctx);
  #if defined(USE_STREAM_BIO)
    BIO_free(dtls_server->bio);
  #endif
    channel_detach(dtls_server->channel);
    channel_destroy(dtls_server->channel);

    return;
}

/************************************************************/

int main(int argc, char *argv[])
{
    int fds[2];
    loop_t *loop;

    dtls_client_t dtls_client;
    dtls_server_t dtls_server;

    const char *ca_file;
    const char *key_file;
    const char *ca_pwd;

  #if !defined(NDEBUG)
    ca_file = "/mnt/d/ca/cert.pem";
    key_file = "/mnt/d/ca/key.pem";
    ca_pwd = "SSLSelfTest";
  #else
    if (argc < 4)
    {
        printf("usage: %s <ca file> <key file> <ca pwd>\n", argv[0]);
        return -1;
    }
    ca_file = argv[1]；
    key_file = argv[2];
    ca_pwd = argv[3];
  #endif

    SSL_library_init();
    SSL_load_error_strings();

    /* 给 openssl 底层数据交换的 fd 必须是双向读写的，因而只能用 socketpair() 而不是 pipe() */
  #if defined(USE_STREAM_BIO)
    socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds);
  #else
    socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds);
  #endif

    loop = loop_new(64);

    dtls_client_start(&dtls_client, fds[0], loop);
    dtls_server_start(&dtls_server, fds[1], loop, ca_file, key_file, ca_pwd);

    loop_loop(loop);

    dtls_client_stop(&dtls_client);
    dtls_server_stop(&dtls_server);

    loop_destroy(loop);

    close(fds[0]);
    close(fds[1]);

    return 0;
}