
#include <tinylib/linux/net/loop.h>
#include <tinylib/linux/net/tcp_client.h>
#include <tinylib/linux/net/udp_peer.h>

#include <pjlib.h>
#include <pjnath.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

typedef struct turn_client
{
    loop_t* loop;

    udp_peer_t *signal_transport;
    unsigned short local_signal_port;
    unsigned short remote_signal_port;

    pj_caching_pool pj_cache_pool;
    pj_pool_t* pj_pool;
    pj_timer_heap_t	*pj_timer_heap;
    int pj_timer_run;
    pthread_t pj_timer_th;
    
    pj_stun_config pj_stun_config;

    udp_peer_t *turn_transport;
    pj_turn_session* turn_session;
} turn_client_t;

struct signal_msg
{
    uint32_t peer_ip; // network byte order
    uint32_t peer_port; // network byte order

    uint32_t peer_relay_ip; // network byte order
    uint32_t peer_relay_port; // network byte order
};

pj_status_t on_turn_send_pkt(pj_turn_session *sess, const pj_uint8_t *pkt, unsigned pkt_len, const pj_sockaddr_t *dst_addr, unsigned addr_len)
{
    turn_client_t* turn_client = (turn_client_t*)pj_turn_session_get_user_data(sess);

    inetaddr_t addr;
    inetaddr_initbyipport(&addr, pj_inet_ntoa(((pj_sockaddr*)dst_addr)->ipv4.sin_addr), pj_sockaddr_get_port(dst_addr));
    udp_peer_send(turn_client->turn_transport, pkt, pkt_len, &addr);

    return PJ_SUCCESS;
}

void on_turn_channel_bound(pj_turn_session *sess, const pj_sockaddr_t *peer_addr, unsigned addr_len, unsigned ch_num)
{
    turn_client_t* turn_client = (turn_client_t*)pj_turn_session_get_user_data(sess);

    return;
}

void on_turn_rx_data(pj_turn_session *sess, void *pkt, unsigned pkt_len, const pj_sockaddr_t *peer_addr, unsigned addr_len)
{
    turn_client_t* turn_client = (turn_client_t*)pj_turn_session_get_user_data(sess);

    printf("turn msg received: ");
    fwrite(pkt, 1, pkt_len, stdout);
    printf("\n");

    return;
}

void on_turn_state(pj_turn_session *sess, pj_turn_state_t old_state, pj_turn_state_t new_state)
{
    turn_client_t* turn_client = (turn_client_t*)pj_turn_session_get_user_data(sess);

    // turn allocation OK
    if (new_state == PJ_TURN_STATE_READY)
    {
        pj_turn_session_info turn_session_info;
        pj_turn_session_get_info(sess, &turn_session_info);

        /* pj_turn_session_info.server          // turnsever的TCP/UDP服务端口
         * pj_turn_session_info.mapped_addr     // turnclient的对外映射地址
         * pj_turn_session_info.relay_addr      // turnserver分配给turnclient的对外中继收包地址
         */

        printf("turn allocation result: \n"
                "  conn_type: %d\n"
                "  server: %s:%u\n"
                "  mapped_addr: %s:%u\n"
                "  relay_addr: %s:%u\n",
            turn_session_info.conn_type,
            inet_ntoa(*(struct in_addr*)&turn_session_info.server.ipv4.sin_addr), ntohs(turn_session_info.server.ipv4.sin_port),
            inet_ntoa(*(struct in_addr*)&turn_session_info.mapped_addr.ipv4.sin_addr), ntohs(turn_session_info.mapped_addr.ipv4.sin_port),
            inet_ntoa(*(struct in_addr*)&turn_session_info.relay_addr.ipv4.sin_addr), ntohs(turn_session_info.relay_addr.ipv4.sin_port));

        struct signal_msg signal_msg = {
            turn_session_info.mapped_addr.ipv4.sin_addr.s_addr, 
            turn_session_info.mapped_addr.ipv4.sin_port,
            turn_session_info.relay_addr.ipv4.sin_addr.s_addr,
            turn_session_info.relay_addr.ipv4.sin_port
        };

        sleep(3);

        inetaddr_t peer_addr = {"127.0.0.1", turn_client->remote_signal_port};
        udp_peer_send(turn_client->signal_transport, &signal_msg, sizeof(signal_msg), &peer_addr);
    }
    else if (new_state == PJ_TURN_STATE_DEALLOCATED)
    {
    }

    return;
}

void on_turn_transport_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    turn_client_t* turn_client = (turn_client_t*)userdata;
    pj_turn_session_on_rx_pkt(turn_client->turn_session, message, size, NULL);

    return;
}

/********************************************************************************/

void on_signal_transport_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    turn_client_t* turn_client = (turn_client_t*)userdata;

    struct signal_msg* signal_msg = (struct signal_msg*)message;

    printf("=== received signal_msg msg from %s:%u ===\n", peer_addr->ip, peer_addr->port);

    /* 利用turn中继发送数据时，申请permission和发送数据，
     * 目标地址为目标 peer 的relay 地址
     */

    pj_sockaddr pj_peer_replay_addr;
    pj_peer_replay_addr.ipv4.sin_family = pj_AF_INET();
    pj_peer_replay_addr.ipv4.sin_addr.s_addr = signal_msg->peer_relay_ip;
    pj_peer_replay_addr.ipv4.sin_port = signal_msg->peer_relay_port;
    pj_turn_session_set_perm(turn_client->turn_session, 1, &pj_peer_replay_addr, 1);

    char msg[1024];
    memset(msg, 0, sizeof(msg));
    int len = snprintf(msg, sizeof(msg)-1, "turn msg from peer@%p, client signal_msg port: %u", turn_client, turn_client->local_signal_port);
    pj_status_t status = pj_turn_session_sendto(turn_client->turn_session, msg, len, &pj_peer_replay_addr, sizeof(pj_peer_replay_addr));
    if (PJ_SUCCESS != status)
    {
        printf("=== pj_turn_session_sendto() failed, ret: %d ===\n", status);
    }
    else
    {
        printf("=== pj_turn_session_sendto() OK ===\n");
    }

    return;
}

/********************************************************************************/

loop_t* g_loop = NULL;
void on_interrupt(int signo)
{
    loop_quit(g_loop);

    return;
}

int main(int argc, char *argv[])
{
    turn_client_t turn_client;

    const char *turn_server_ip;
    unsigned short turn_server_port;
    unsigned short local_signal_port;
    unsigned short remote_signal_port;
    unsigned short local_turn_port;

    if (argc < 6)
    {
        printf("usage: %s <turn server ip> <turn server port> <local signal port> <remote signal port>\n", argv[0]);
        return 0;
    }
    turn_server_ip = argv[1];
    turn_server_port = (unsigned short)atoi(argv[2]);
    local_signal_port = (unsigned short)atoi(argv[3]);
    remote_signal_port = (unsigned short)atoi(argv[4]);
    local_turn_port = (unsigned short)atoi(argv[5]);

    memset(&turn_client, 0, sizeof(turn_client));
    turn_client.local_signal_port = local_signal_port;
    turn_client.remote_signal_port = remote_signal_port;

    turn_client.loop = loop_new(64);

    pj_init();
    pjlib_util_init();
    pjnath_init();

    pj_caching_pool_init(&turn_client.pj_cache_pool, &pj_pool_factory_default_policy, 0);
    turn_client.pj_pool = pj_pool_create(&turn_client.pj_cache_pool.factory, "main", 1000, 1000, NULL);
    pj_timer_heap_create(turn_client.pj_pool, 100, &turn_client.pj_timer_heap);
  #if 0
    turn_client.pj_timer_run = 1;
    pthread_create(&turn_client.pj_timer_th, NULL, timer_thread, &turn_client);
  #endif
    pj_stun_config_init(&turn_client.pj_stun_config, &turn_client.pj_cache_pool.factory, 0, NULL, turn_client.pj_timer_heap);

    turn_client.turn_transport = udp_peer_new(turn_client.loop, "0.0.0.0", local_turn_port, on_turn_transport_message, NULL, &turn_client);
    pj_turn_session_cb turn_sess_callback = {
        on_turn_send_pkt,
        on_turn_channel_bound,
        on_turn_rx_data,
        on_turn_state
    };
    pj_turn_session_create(&turn_client.pj_stun_config, "turn", pj_AF_INET(), PJ_TURN_TP_UDP, NULL, &turn_sess_callback, 0, &turn_client, &turn_client.turn_session);
    pj_turn_session_set_user_data(turn_client.turn_session, &turn_client);

    pj_stun_auth_cred sess_credential;
    memset(&sess_credential, 0, sizeof(sess_credential));
    sess_credential.type = PJ_STUN_AUTH_CRED_STATIC;
    char turn_realm[] = "domain.org";
    sess_credential.data.static_cred.realm.ptr = turn_realm;
    sess_credential.data.static_cred.realm.slen = strlen(turn_realm);
    char turn_user[] = "toto";
    sess_credential.data.static_cred.username.ptr = turn_user;
    sess_credential.data.static_cred.username.slen = strlen(turn_user);
    sess_credential.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
    char turn_cred_data[] = "password";
    sess_credential.data.static_cred.data.ptr = turn_cred_data;
    sess_credential.data.static_cred.data.slen = strlen(turn_cred_data);
    pj_turn_session_set_credential(turn_client.turn_session, &sess_credential);

    pj_str_t str_server_addr = {(char*)turn_server_ip, strlen(turn_server_ip)};
    pj_turn_session_set_server(turn_client.turn_session, &str_server_addr, turn_server_port, NULL);
    pj_turn_session_alloc(turn_client.turn_session, NULL);

    turn_client.signal_transport = udp_peer_new(turn_client.loop, "127.0.0.1", local_signal_port, on_signal_transport_message, NULL, &turn_client);

    g_loop = turn_client.loop;
    signal(SIGINT, on_interrupt);
    loop_loop(turn_client.loop);

    pj_turn_session_shutdown(turn_client.turn_session);
    pj_turn_session_destroy(turn_client.turn_session, PJ_SUCCESS);

    udp_peer_destroy(turn_client.turn_transport);
    udp_peer_destroy(turn_client.signal_transport);

    loop_destroy(turn_client.loop);

    pj_timer_heap_destroy(turn_client.pj_timer_heap);
    pj_pool_release(turn_client.pj_pool);
    pj_shutdown();

    return 0;
}
