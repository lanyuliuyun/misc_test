
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>

#include <tinylib/net/loop.h>
#include <tinylib/net/udp_peer.h>
#include <tinylib/net/tcp_client.h>
#include <tinylib/util/log.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct ice_global
{
    inetaddr_t turn_server_addr;
    loop_t *loop;

    pj_caching_pool cache_pool;
    pj_pool_t *pj_pool;
    pj_ioqueue_t *io_queue;
    pj_timer_heap_t *timer_heap;
    pj_stun_config stun_config;

    inetaddr_t turn_local_addr;
    udp_peer_t *turn_transport;
    pj_turn_session *turn;

    pj_ice_sess *ice;
    int ice_passive;
    char ice_ufrag[8];
    char ice_passwd[32];
    char ice_foundation[32];

    inetaddr_t candidate_host;
    inetaddr_t candidate_srvflx;
    inetaddr_t candidate_relay;

    udp_peer_t *signal_transport;
    inetaddr_t remote_signal_addr;
    
    int pj_run;
    pthread_t pj_worker;
} g_ice_global;

static
void *pj_worker_routine(void *arg)
{
    pj_thread_desc thread_desc;
    pj_thread_t *pj_thead_handle;
    pj_thread_register("pj_worker_routine", thread_desc, &pj_thead_handle);
    
    while (g_ice_global.pj_run)
    {
        const pj_time_val delay = {0, 10};

        pj_ioqueue_poll(g_ice_global.io_queue, &delay);
        pj_timer_heap_poll(g_ice_global.timer_heap, NULL);
    }

    return NULL;
}

static
int libpj_init(void)
{
    pj_init();
    pjlib_util_init();
    pjnath_init();

    pj_caching_pool_init(&g_ice_global.cache_pool, &pj_pool_factory_default_policy, 0);
    g_ice_global.pj_pool = pj_pool_create(&g_ice_global.cache_pool.factory, "main", 1000, 1000, NULL);
    pj_ioqueue_create(g_ice_global.pj_pool, 64, &g_ice_global.io_queue);
    pj_timer_heap_create(g_ice_global.pj_pool, 1000, &g_ice_global.timer_heap);

    pj_stun_config_init(&g_ice_global.stun_config, &g_ice_global.cache_pool.factory, 0, g_ice_global.io_queue, g_ice_global.timer_heap);
    
    g_ice_global.pj_run = 1;
    pthread_create(&g_ice_global.pj_worker, NULL, pj_worker_routine, NULL);

    return 0;
}

static
void libpj_uninit(void)
{
    g_ice_global.pj_run = 0;
    pthread_join(g_ice_global.pj_worker, NULL);

    pj_ioqueue_destroy(g_ice_global.io_queue);
    pj_timer_heap_destroy(g_ice_global.timer_heap);
    pj_pool_release(g_ice_global.pj_pool);

    pj_shutdown();

    return;
}

/**********************************************************************/

static
void on_turn_udp_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    /* TODO: 根据源地址，区分包来源
     * 1, 若是来自 turnserver， 则标明是turn会话消息或应用数据中继消息
     * 2, 若是来自其他端点，则表明是 P2P 直连消息，
     */

    char first_byte = ((char*)message)[0];

    if (first_byte == 0 || first_byte == 1)
    {
        pj_status_t pj_status = pj_turn_session_on_rx_pkt(g_ice_global.turn, message, size, NULL);
        if (pj_status != PJ_SUCCESS)
        {
            log_error("pj_turn_session_on_rx_pkt() failed, ret: %d", pj_status);
        }
    }
    else
    {
        pj_sockaddr addr;
        addr.ipv4.sin_family = pj_AF_INET();
        addr.ipv4.sin_addr = pj_inet_addr2(peer_addr->ip);
        addr.ipv4.sin_port = pj_htons(peer_addr->port);
        pj_ice_sess_on_rx_pkt(g_ice_global.ice, 1, 3, message, size, &addr, sizeof(addr));
    }

    return;
}

static
pj_status_t on_turn_send_packet(pj_turn_session *sess, const pj_uint8_t *pkt, unsigned pkt_len, const pj_sockaddr_t *dst_addr, unsigned addr_len)
{
    inetaddr_t addr;
    inetaddr_initbyipport(&addr, pj_inet_ntoa(((pj_sockaddr*)dst_addr)->ipv4.sin_addr), pj_sockaddr_get_port(dst_addr));
    udp_peer_send(g_ice_global.turn_transport, pkt, pkt_len, &addr);

    return PJ_SUCCESS;
}

static
void on_turn_channel_bound(pj_turn_session *sess, const pj_sockaddr_t *peer_addr, unsigned addr_len, unsigned ch_num)
{
    return;
}

static
void on_turn_rx_data(pj_turn_session *sess, void *pkt, unsigned pkt_len, const pj_sockaddr_t *peer_addr, unsigned addr_len)
{
    /* 接收来自 turnserver 的 SendIndication/ChannelData 的数据，自然是经 turnserver 中继过来的消息 */
    pj_ice_sess_on_rx_pkt(g_ice_global.ice, 1, 3, pkt, pkt_len, peer_addr, addr_len);

    return;
}

static
void offer_local_candidate(void);

static
void on_turn_state_change(pj_turn_session *sess, pj_turn_state_t old_state, pj_turn_state_t new_state)
{
    if (new_state == PJ_TURN_STATE_READY)
    {
        pj_str_t ice_foundation = {g_ice_global.ice_foundation, strlen(g_ice_global.ice_foundation)};

        pj_sockaddr host_addr;
        host_addr.ipv4.sin_family = pj_AF_INET();
        host_addr.ipv4.sin_addr = pj_inet_addr2(g_ice_global.turn_local_addr.ip);
        host_addr.ipv4.sin_port = pj_htons(g_ice_global.turn_local_addr.port);

      #if 0
        /* For host candidates, the base is the same as the host candidate itself */
        pj_ice_sess_add_cand(g_ice_global.ice, 1, 1, PJ_ICE_CAND_TYPE_HOST, 65535, &ice_foundation, 
            &host_addr,
            &host_addr,
            NULL,
            sizeof(host_addr),
            NULL);
        g_ice_global.candidate_host = g_ice_global.turn_local_addr;
      #endif

        pj_turn_session_info turn_session_info;
        pj_turn_session_get_info(sess, &turn_session_info);

      #if 0
        /* For reflexive candidates, the base is the local IP address of the socket */
        pj_ice_sess_add_cand(g_ice_global.ice, 1, 2, PJ_ICE_CAND_TYPE_SRFLX, 65535, &ice_foundation, 
            &turn_session_info.mapped_addr,
            &host_addr,
            NULL,
            sizeof(turn_session_info.mapped_addr),
            NULL);
        inetaddr_initbyipport(&g_ice_global.candidate_srvflx, 
            pj_inet_ntoa(turn_session_info.mapped_addr.ipv4.sin_addr), 
            pj_sockaddr_get_port(&turn_session_info.mapped_addr));
      #endif

        /* For relayed candidates, the base address is the transport address allocated in the TURN server for this candidate */
        /* 此处对于 relayed candidate, base address要求是turnserver上通信地址端口, 所以只能提供 pj_turn_session_info.server */
        pj_ice_sess_add_cand(g_ice_global.ice, 1, 3, PJ_ICE_CAND_TYPE_RELAYED, 65535, &ice_foundation, 
            &turn_session_info.relay_addr,
            &turn_session_info.server,
            NULL,
            sizeof(turn_session_info.relay_addr),
            NULL);
        inetaddr_initbyipport(&g_ice_global.candidate_relay, 
            pj_inet_ntoa(turn_session_info.relay_addr.ipv4.sin_addr), 
            pj_sockaddr_get_port(&turn_session_info.relay_addr));

        sleep(3);
        offer_local_candidate();
    }

    return;
}

static
int setup_turn(const char *turn_server_ip, unsigned short turn_server_port, const char *local_ip, unsigned short local_turn_port)
{
    inetaddr_initbyipport(&g_ice_global.turn_local_addr, local_ip, local_turn_port);
    g_ice_global.turn_transport = udp_peer_new(g_ice_global.loop, local_ip, local_turn_port, on_turn_udp_message, NULL, NULL);

    pj_turn_session_cb turn_session_callback = {
        on_turn_send_packet,
        on_turn_channel_bound,
        on_turn_rx_data,
        on_turn_state_change
    };

    pj_status_t pj_status = pj_turn_session_create(
        &g_ice_global.stun_config, "turn", pj_AF_INET(), PJ_TURN_TP_UDP,
        NULL, &turn_session_callback, 0, NULL,
        &g_ice_global.turn);
    if (pj_status != PJ_SUCCESS)
    {
        log_error("setup_turn, pj_turn_session_create() failed, ret: %d", pj_status);
        return -1;
    }

    pj_stun_auth_cred auth_cred;
    memset(&auth_cred, 0, sizeof(auth_cred));
    auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
    char turn_realm[] = "domain.org";
    auth_cred.data.static_cred.realm.ptr = turn_realm;
    auth_cred.data.static_cred.realm.slen = strlen(turn_realm);
    char turn_username[] = "toto";
    auth_cred.data.static_cred.username.ptr = turn_username;
    auth_cred.data.static_cred.username.slen = strlen(turn_username);
    auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
    char turn_password[] = "password";
    auth_cred.data.static_cred.data.ptr = turn_password;
    auth_cred.data.static_cred.data.slen = strlen(turn_password);
    pj_turn_session_set_credential(g_ice_global.turn, &auth_cred);

    pj_str_t str_turn_server = {turn_server_ip, strlen(turn_server_ip)};
    pj_turn_session_set_server(g_ice_global.turn, &str_turn_server, turn_server_port, NULL);

    pj_turn_session_alloc(g_ice_global.turn, NULL);

    return 0;
}

static
void cleanup_turn(void)
{
    pj_turn_session_shutdown(g_ice_global.turn);
    udp_peer_destroy(g_ice_global.turn_transport);

    return;
}

/**********************************************************************/

static
void on_ice_complete(pj_ice_sess *ice, pj_status_t status)
{
    log_info("ice complete, status: %d", status);
    return;
}

static
pj_status_t on_ice_tx_pkt
(
    pj_ice_sess *ice, 
    unsigned comp_id, 
    unsigned transport_id,
    const void *pkt, 
    pj_size_t size,
    const pj_sockaddr_t *dst_addr,
    unsigned dst_addr_len
)
{
    /* comp_id 表示是那路媒体，transport_id 是哪路数据通道 
     * 实际主机可能有多个网口IP，因而有多个数据通路，transport_id 可以用此来进行标识
     */
    log_info("=== on_ice_tx_pkt, comp_id: %u, transport_id: %u ===", comp_id, transport_id);

    pj_status_t pj_status;

    /* STUN HOST直通 或 STUN mapped 地址 */
    if (transport_id == 1 || transport_id == 2)
    {
    }
    /* turn rely */
    else if (transport_id == 3)
    {
        pj_turn_session_sendto(g_ice_global.turn, pkt, size, dst_addr, dst_addr_len);
    }

    return PJ_SUCCESS;
}

static
void on_ice_rx_data
(
    pj_ice_sess *ice, 
    unsigned comp_id,
    unsigned transport_id, 
    void *pkt, 
    pj_size_t size,
    const pj_sockaddr_t *src_addr,
    unsigned src_addr_len
)
{
    /* 同 on_ice_tx_pkt() 中对 comp_id 和 transport_id 的说明 */

    /* TODO: 处理应用层数据 */

    return;
}

static
void setup_ice(int ice_role_passive, const char *ice_ufrag, const char *ice_passwd, const char *ice_foundation)
{
    pj_status_t pj_status;

    pj_ice_sess_cb ice_session_callback = {
        on_ice_complete,
        on_ice_tx_pkt,
        on_ice_rx_data
    };
    
    strncpy(g_ice_global.ice_ufrag, ice_ufrag, sizeof(g_ice_global.ice_ufrag)-1);
    strncpy(g_ice_global.ice_passwd, ice_passwd, sizeof(g_ice_global.ice_passwd)-1);
    strncpy(g_ice_global.ice_foundation, ice_foundation, sizeof(g_ice_global.ice_foundation)-1);

    pj_ice_sess_role ice_role = ice_role_passive != 0 ? PJ_ICE_SESS_ROLE_CONTROLLING : PJ_ICE_SESS_ROLE_CONTROLLED;
    g_ice_global.ice_passive = ice_role_passive;

    pj_str_t ice_str_ufrag = {ice_ufrag, strlen(ice_ufrag)};
    pj_str_t ice_str_passwd = {ice_passwd, strlen(ice_passwd)};
    pj_status = pj_ice_sess_create(&g_ice_global.stun_config, "ice", ice_role, 1, &ice_session_callback, 
        &ice_str_ufrag, &ice_str_passwd, NULL, &g_ice_global.ice);
    if (pj_status != PJ_SUCCESS)
    {
        log_error("setup_ice, pj_ice_sess_create() failed, ret: %d", pj_status);
    }
    else
    {
        snprintf(g_ice_global.ice_foundation, sizeof(g_ice_global.ice_foundation), "ice:%p", g_ice_global.ice);
    }

    return;
}

static
void cleanup_ice(void)
{
    pj_ice_sess_destroy(g_ice_global.ice);

    return;
}

/**********************************************************************/

struct signal_msg
{
    inetaddr_t cand_rely;
    char ice_ufrag[8];
    char ice_passwd[32];
    char ice_foundation[32];
};

static
void offer_local_candidate(void)
{
    struct signal_msg signal_msg;
    memset(&signal_msg, 0, sizeof(signal_msg));
    signal_msg.cand_rely = g_ice_global.candidate_relay;
    strncpy(signal_msg.ice_ufrag, g_ice_global.ice_ufrag, sizeof(signal_msg.ice_ufrag));
    strncpy(signal_msg.ice_passwd, g_ice_global.ice_passwd, sizeof(signal_msg.ice_passwd));
    strncpy(signal_msg.ice_foundation, g_ice_global.ice_foundation, sizeof(signal_msg.ice_foundation));

    udp_peer_send(g_ice_global.signal_transport, &signal_msg, sizeof(signal_msg), &g_ice_global.remote_signal_addr);

    return;
}

static
void on_signal_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    struct signal_msg *candidate_msg = (struct signal_msg*)message;

    pj_ice_sess_cand candidates[3];
    memset(candidates, 0, sizeof(candidates));
  #if 0
    candidates[0].type = PJ_ICE_CAND_TYPE_HOST;
    candidates[0].status = PJ_SUCCESS;
    candidates[0].comp_id = 1;
    candidates[0].transport_id = 0;
    candidates[0].local_pref = 65535;
    candidates[0].foundation = ;
    candidates[0].prio = 255;
    candidates[0].addr = ;
    candidates[0].base_addr = ;
    candidates[0].rel_addr = ;

    candidates[1].type = PJ_ICE_CAND_TYPE_SRFLX;
    candidates[1].status = PJ_SUCCESS;
    candidates[1].comp_id = 1;
    candidates[1].transport_id = 1;
    candidates[1].local_pref = 65535;
    candidates[1].foundation = ;
    candidates[1].prio = 255;
    candidates[1].addr = ;
    candidates[1].base_addr = ;
    candidates[1].rel_addr = ;
  #endif

    candidates[0].type = PJ_ICE_CAND_TYPE_RELAYED;
    candidates[0].status = PJ_SUCCESS;
    candidates[0].comp_id = 1;
    candidates[0].transport_id = 3;
    candidates[0].local_pref = 65535;
    candidates[0].foundation.ptr = candidate_msg->ice_foundation;
    candidates[0].foundation.slen = strlen(candidate_msg->ice_foundation);
    candidates[0].prio = 255;
    candidates[0].addr.ipv4.sin_family = pj_AF_INET();
    candidates[0].addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_rely.ip);
    candidates[0].addr.ipv4.sin_port = pj_htons(candidate_msg->cand_rely.port);
    candidates[0].base_addr.ipv4.sin_family = pj_AF_INET();
    candidates[0].base_addr.ipv4.sin_addr = pj_inet_addr2(g_ice_global.turn_server_addr.ip);
    candidates[0].base_addr.ipv4.sin_port = pj_htons(g_ice_global.turn_server_addr.port);

    pj_turn_session_set_perm(g_ice_global.turn, 1, &candidates[0].addr, 1);

    pj_str_t ice_ufrag = {candidate_msg->ice_ufrag, strlen(candidate_msg->ice_ufrag)};
    pj_str_t ice_passwd = {candidate_msg->ice_passwd, strlen(candidate_msg->ice_passwd)};
    pj_status_t pj_status = pj_ice_sess_create_check_list(g_ice_global.ice, &ice_ufrag, &ice_passwd, 1, candidates);
    if (pj_status == PJ_SUCCESS)
    {
        if (g_ice_global.ice_passive)
        {
            pj_status = pj_ice_sess_start_check(g_ice_global.ice);
            if (pj_status != PJ_SUCCESS)
            {
                log_error("pj_ice_sess_start_check() failed, ret: %d", pj_status);
            }
        }
    }
    else
    {
        log_error("pj_ice_sess_create_check_list() failed, ret: %d", pj_status);
    }

    return;
}

static
void setup_signal(const char *local_ip, unsigned short local_signal_port, const char *remote_signal_ip, unsigned short remote_signal_port)
{
    inetaddr_initbyipport(&g_ice_global.remote_signal_addr, remote_signal_ip, remote_signal_port);

    g_ice_global.signal_transport = udp_peer_new(g_ice_global.loop, local_ip, local_signal_port, on_signal_message, NULL, NULL);
    
    return;
}

static
void cleanup_signal(void)
{
    udp_peer_destroy(g_ice_global.signal_transport);
    return;
}

/**********************************************************************/

#include <signal.h>

static
void on_interrupt(int signo)
{
    loop_quit(g_ice_global.loop);
    return;
}

int main(int argc, char *argv[])
{
    const char *turn_server_ip;
    unsigned short turn_server_port;
    const char *local_turn_ip;
    unsigned short local_turn_port;
    int ice_role_passive;
    const char *ice_ufrag;
    const char *ice_passwd;
    const char *ice_foundation;
    const char *local_signal_ip;
    unsigned short local_signal_port;
    const char *remote_signal_ip;
    unsigned short remote_signal_port;

    if (argc < 13)
    {
        printf("usge: %s "
            "<turn server ip> <turn server port> "
            "<local turn ip> <local turn port> "
            "<ice role: 0/1> <ice ufrag> <ice passwd> <ice foundation> "
            "<local signal ip> <local signal port> "
            "<remote signal ip> <remote signal port>\n", 
            argv[0]);
        return 0;
    }
    turn_server_ip = argv[1];
    turn_server_port = (unsigned short)atoi(argv[2]);
    local_turn_ip = argv[3];
    local_turn_port = (unsigned short)atoi(argv[4]);
    ice_role_passive = atoi(argv[5]) != 0;
    ice_ufrag = argv[6];
    ice_passwd = argv[7];
    ice_foundation = argv[8];
    local_signal_ip = argv[9];
    local_signal_port = (unsigned short)atoi(argv[10]);
    remote_signal_ip = argv[11];
    remote_signal_port = (unsigned short)atoi(argv[12]);

    memset(&g_ice_global, 0, sizeof(g_ice_global));
    libpj_init();

    g_ice_global.loop = loop_new(64);

    inetaddr_initbyipport(&g_ice_global.turn_server_addr, turn_server_ip, turn_server_port);

    setup_signal(local_signal_ip, local_signal_port, remote_signal_ip, remote_signal_port);
    setup_ice(ice_role_passive, ice_ufrag, ice_passwd, ice_foundation);
    setup_turn(turn_server_ip, turn_server_port, local_turn_ip, local_turn_port);

    signal(SIGINT, on_interrupt);
    loop_loop(g_ice_global.loop);

    cleanup_turn();
    cleanup_ice();
    cleanup_signal();

    loop_destroy(g_ice_global.loop);

    libpj_uninit();

    return 0;
}
