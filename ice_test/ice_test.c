
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>

#include <tinylib/net/loop.h>
#include <tinylib/net/udp_peer.h>
#include <tinylib/util/log.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#if !defined(USE_ICE_HOST) && !defined(USE_ICE_SVRFLX) && !defined(USE_ICE_RELAY)
#error at least one type ice candidate type support must be enabled
#error please define one or more macro of USE_ICE_HOST/USE_ICE_SVRFLX/USE_ICE_RELAY
#endif

struct ice_global
{
    loop_t *loop;

    pj_caching_pool cache_pool;
    pj_pool_t *pj_pool;
    pj_timer_heap_t *timer_heap;
    pj_stun_config stun_config;

  #if defined(USE_ICE_HOST)
    inetaddr_t ice_host_local_addr;
    udp_peer_t *ice_host_transport;
  #endif

  #if defined(USE_ICE_SVRFLX)
    inetaddr_t stun_server_addr;
    pj_sockaddr pj_stun_server_addr;
    int stun_candidate_done;
    inetaddr_t stun_local_addr;
    udp_peer_t *stun_transport;
    pj_stun_session *stun;
  #endif

  #if defined(USE_ICE_RELAY)
    inetaddr_t turn_server_addr;
    pj_sockaddr pj_turn_server_addr;
    inetaddr_t turn_local_addr;
    udp_peer_t *turn_transport;
    pj_turn_session *turn;
  #endif

    pj_ice_sess *ice;
    char ice_ufrag[8];
    char ice_passwd[32];
    char ice_foundation[32];
    int expect_cand_done_count;

  #if defined(USE_ICE_HOST)
    inetaddr_t candidate_host;
  #endif
  #if defined(USE_ICE_SVRFLX)
    inetaddr_t candidate_svrflx;
  #endif
  #if defined(USE_ICE_RELAY)
    inetaddr_t candidate_relay;
  #endif

    udp_peer_t *signal_transport;
    inetaddr_t remote_signal_addr;

    loop_timer_t* pj_drive_timer;
} g_ice_global;

static
void pj_drive_timer(void *userdata)
{
    pj_timer_heap_poll(g_ice_global.timer_heap, NULL);
    return;
}

static
int libpj_init(void)
{
    pj_init();
    pjlib_util_init();
    pjnath_init();

    pj_caching_pool_init(&g_ice_global.cache_pool, &pj_pool_factory_default_policy, 0);
    g_ice_global.pj_pool = pj_pool_create(&g_ice_global.cache_pool.factory, "main", 1000, 1000, NULL);
    pj_timer_heap_create(g_ice_global.pj_pool, 1000, &g_ice_global.timer_heap);
    pj_stun_config_init(&g_ice_global.stun_config, &g_ice_global.cache_pool.factory, 0, NULL, g_ice_global.timer_heap);

    g_ice_global.pj_drive_timer = loop_runevery(g_ice_global.loop, 50, pj_drive_timer, NULL);

    return 0;
}

static
void libpj_uninit(void)
{
    loop_cancel(g_ice_global.loop, g_ice_global.pj_drive_timer);
    pj_timer_heap_destroy(g_ice_global.timer_heap);
    pj_pool_release(g_ice_global.pj_pool);

    pj_shutdown();

    return;
}

/**********************************************************************/

#if defined(USE_ICE_HOST)
static
void on_ice_local_host_udp_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    pj_sockaddr addr;
    addr.ipv4.sin_family = pj_AF_INET();
    addr.ipv4.sin_addr = pj_inet_addr2(peer_addr->ip);
    addr.ipv4.sin_port = pj_htons(peer_addr->port);
    pj_ice_sess_on_rx_pkt(g_ice_global.ice, 1, 1, message, size, &addr, sizeof(addr));

    return;
}

static
void ice_on_cand_host_done(void);

static
void setup_ice_local_host(const char *local_ice_host_ip, unsigned short local_ice_host_port)
{
    inetaddr_initbyipport(&g_ice_global.ice_host_local_addr, local_ice_host_ip, local_ice_host_port);
    g_ice_global.ice_host_transport = udp_peer_new(g_ice_global.loop, local_ice_host_ip, local_ice_host_port,
        on_ice_local_host_udp_message, NULL, NULL);

    pj_str_t str_ice_foundation = {g_ice_global.ice_foundation, strlen(g_ice_global.ice_foundation)};
    pj_sockaddr pj_host_addr;
    pj_host_addr.ipv4.sin_family = pj_AF_INET();
    pj_host_addr.ipv4.sin_addr = pj_inet_addr2(local_ice_host_ip);
    pj_host_addr.ipv4.sin_port = pj_htons(local_ice_host_port);

    /* For host candidates, the base is the same as the host candidate itself */
    pj_ice_sess_add_cand(g_ice_global.ice, 1, 1, PJ_ICE_CAND_TYPE_HOST, 65535, &str_ice_foundation, 
        &pj_host_addr,
        &pj_host_addr,
        NULL,
        sizeof(pj_host_addr),
        NULL);
    g_ice_global.candidate_host = g_ice_global.ice_host_local_addr;
    
    ice_on_cand_host_done();

    return;
}

static
void cleanup_ice_local_host(void)
{
    udp_peer_destroy(g_ice_global.ice_host_transport);

    return;
}

#endif

/**********************************************************************/

#if defined(USE_ICE_SVRFLX)

static
void on_stun_udp_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    /* FIXME: 需要保证应用层第一个字节不是以 0 或 1，用以与 STUN 报文区分
     * 实际用在流媒体领域，除了 STUN 报文，一般多是 DTLS/RTP 报文
     *
     * 而此处 STUN 的作用仅仅用于探测 NAT 外侧的地址，而后就是直接的 P2P 通信了
     */

    pj_sockaddr pj_addr;
    pj_addr.ipv4.sin_family = pj_AF_INET();
    pj_addr.ipv4.sin_addr = pj_inet_addr2(peer_addr->ip);
    pj_addr.ipv4.sin_port = pj_htons(peer_addr->port);

    if (g_ice_global.stun_candidate_done == 0)
    {
        pj_status_t pj_status = pj_stun_session_on_rx_pkt(g_ice_global.stun, message, size, 
            PJ_STUN_IS_DATAGRAM, NULL, NULL, &pj_addr, sizeof(pj_addr));
        if (pj_status != PJ_SUCCESS)
        {
            log_error("pj_stun_session_on_rx_pkt() failed, ret: %d", pj_status);
        }
    }
    else
    {
        pj_ice_sess_on_rx_pkt(g_ice_global.ice, 1, 3, message, size, &pj_addr, sizeof(pj_addr));
    }

    return;
}

static
pj_status_t on_stun_send_msg
(
    pj_stun_session *sess,
    void *token,
    const void *pkt,
    pj_size_t pkt_size,
    const pj_sockaddr_t *dst_addr,
    unsigned addr_len
)
{
    inetaddr_t addr;
    inetaddr_initbyipport(&addr, pj_inet_ntoa(((pj_sockaddr*)dst_addr)->ipv4.sin_addr), pj_sockaddr_get_port(dst_addr));
    udp_peer_send(g_ice_global.stun_transport, pkt, pkt_size, &addr);

    return PJ_SUCCESS;
}

static
pj_status_t on_stun_rx_request
(
    pj_stun_session *sess,
    const pj_uint8_t *pkt,
    unsigned pkt_len,
    const pj_stun_rx_data *rdata,
    void *token,
    const pj_sockaddr_t *src_addr,
    unsigned src_addr_len
)
{
    return PJ_SUCCESS;
}

static
void ice_on_cand_svrflx_done(void);

static
void on_stun_request_complete
(
    pj_stun_session *sess,
    pj_status_t status,
    void *token,
    pj_stun_tx_data *tdata,
    const pj_stun_msg *response,
    const pj_sockaddr_t *src_addr,
    unsigned src_addr_len
)
{
    unsigned i;
    if (status == PJ_SUCCESS)
    {
        if (response->hdr.type == PJ_STUN_BINDING_RESPONSE)
        {
            pj_sockaddr *mapped_addr = NULL;
            for (i = 0; i < response->attr_count; ++i)
            {
                pj_stun_attr_hdr *attr_hdr = response->attr[i];
                if (attr_hdr->type == PJ_STUN_ATTR_XOR_MAPPED_ADDR || attr_hdr->type == PJ_STUN_ATTR_MAPPED_ADDR)
                {
                    pj_stun_sockaddr_attr *addr_attr = (pj_stun_sockaddr_attr*)attr_hdr;
                    mapped_addr = &addr_attr->sockaddr;
                    break;
                }
            }

            if (mapped_addr != NULL)
            {
                pj_str_t str_ice_foundation = {g_ice_global.ice_foundation, strlen(g_ice_global.ice_foundation)};

                pj_sockaddr pj_host_addr;
                pj_host_addr.ipv4.sin_family = pj_AF_INET();
                pj_host_addr.ipv4.sin_addr = pj_inet_addr2(g_ice_global.stun_local_addr.ip);
                pj_host_addr.ipv4.sin_port = pj_htons(g_ice_global.stun_local_addr.port);

                /* For host candidates, the base is the same as the host candidate itself */
                /* For reflexive candidates, the base is the local IP address of the socket */

                inetaddr_initbyipport(&g_ice_global.candidate_svrflx, 
                    pj_inet_ntoa(mapped_addr->ipv4.sin_addr), pj_sockaddr_get_port(mapped_addr));

                /* PJ内部也是直接将 checklist中本地候选地址中SVRFLX类型的addr替换成对应的base addr */

                pj_ice_sess_add_cand(g_ice_global.ice, 1, 3, PJ_ICE_CAND_TYPE_HOST, 65535, &str_ice_foundation, 
                    &pj_host_addr,
                    &pj_host_addr,
                    NULL,
                    sizeof(pj_host_addr),
                    NULL);

                pj_ice_sess_add_cand(g_ice_global.ice, 1, 4, PJ_ICE_CAND_TYPE_SRFLX, 65535, &str_ice_foundation, 
                    mapped_addr,
                    &pj_host_addr,
                    NULL,
                    sizeof(*mapped_addr),
                    NULL);

                inetaddr_initbyipport(&g_ice_global.candidate_svrflx, 
                    pj_inet_ntoa(mapped_addr->ipv4.sin_addr), pj_sockaddr_get_port(mapped_addr));

                g_ice_global.stun_candidate_done = 1;
                ice_on_cand_svrflx_done();
            }
        }
    }
    else
    {
        /* TODO: handle timeout or other errors */
    }

    return;
}

static
pj_status_t on_stun_rx_indication
(
    pj_stun_session *sess,
    const pj_uint8_t *pkt,
    unsigned pkt_len,
    const pj_stun_msg *msg,
    void *token,
    const pj_sockaddr_t *src_addr,
    unsigned src_addr_len
)
{
    return PJ_SUCCESS;
}

static
int setup_stun(const char *stun_server_ip, unsigned short stun_server_port, const char *local_stun_ip, unsigned short local_stun_port)
{
    pj_status_t pj_status;

    g_ice_global.pj_stun_server_addr.ipv4.sin_family = pj_AF_INET();
    g_ice_global.pj_stun_server_addr.ipv4.sin_addr = pj_inet_addr2(stun_server_ip);
    g_ice_global.pj_stun_server_addr.ipv4.sin_port = pj_htons(stun_server_port);
    inetaddr_initbyipport(&g_ice_global.stun_server_addr, stun_server_ip, stun_server_port);
    inetaddr_initbyipport(&g_ice_global.stun_local_addr, local_stun_ip, local_stun_port);
    g_ice_global.stun_transport = udp_peer_new(g_ice_global.loop, local_stun_ip, local_stun_port, on_stun_udp_message, NULL, NULL);

    pj_stun_session_cb stun_message_callback = {
        on_stun_send_msg,
        on_stun_rx_request,
        on_stun_request_complete,
        on_stun_rx_indication
    };
    pj_status = pj_stun_session_create(&g_ice_global.stun_config, "stun", &stun_message_callback, PJ_TRUE, NULL, &g_ice_global.stun);
    if (pj_status != PJ_SUCCESS)
    {
        log_error("pj_stun_session_create() failed, ret: %d", pj_status);
        return -1;
    }

  #if 0
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
    pj_stun_session_set_credential(g_ice_global.stun, PJ_STUN_AUTH_LONG_TERM, &auth_cred);
  #endif

    pj_stun_tx_data *stun_tx_msg = NULL;
    pj_uint8_t tsx_id[12] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    pj_stun_session_create_req(g_ice_global.stun, PJ_STUN_BINDING_METHOD, PJ_STUN_MAGIC, tsx_id, &stun_tx_msg);
    pj_stun_session_send_msg(g_ice_global.stun, NULL, PJ_FALSE, PJ_TRUE, 
        &g_ice_global.pj_stun_server_addr, sizeof(g_ice_global.pj_stun_server_addr), stun_tx_msg);

    g_ice_global.expect_cand_done_count++;

    return 0;
}

static
void cleanup_stun(void)
{
    g_ice_global.stun_candidate_done = 0;
    pj_stun_session_destroy(g_ice_global.stun);
    udp_peer_destroy(g_ice_global.stun_transport);

    return;
}

#endif

/**********************************************************************/

#if defined(USE_ICE_RELAY)
static
void on_turn_udp_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    pj_status_t pj_status = pj_turn_session_on_rx_pkt(g_ice_global.turn, message, size, NULL);
    if (pj_status != PJ_SUCCESS)
    {
        log_error("pj_turn_session_on_rx_pkt() failed, ret: %d", pj_status);
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
    pj_ice_sess_on_rx_pkt(g_ice_global.ice, 1, 2, pkt, pkt_len, peer_addr, addr_len);

    return;
}

static
void ice_on_cand_relay_done(void);

static
void on_turn_state_change(pj_turn_session *sess, pj_turn_state_t old_state, pj_turn_state_t new_state)
{
    if (new_state == PJ_TURN_STATE_READY)
    {
        pj_str_t str_ice_foundation = {g_ice_global.ice_foundation, strlen(g_ice_global.ice_foundation)};

        pj_turn_session_info turn_session_info;
        pj_turn_session_get_info(sess, &turn_session_info);

        /* For relayed candidates, the base address is the transport address allocated in the TURN server for this candidate */
        pj_ice_sess_add_cand(g_ice_global.ice, 1, 2, PJ_ICE_CAND_TYPE_RELAYED, 65535, &str_ice_foundation, 
            &turn_session_info.relay_addr,
            &turn_session_info.relay_addr,
            NULL,
            sizeof(turn_session_info.relay_addr),
            NULL);
        inetaddr_initbyipport(&g_ice_global.candidate_relay, 
            pj_inet_ntoa(turn_session_info.relay_addr.ipv4.sin_addr), 
            pj_sockaddr_get_port(&turn_session_info.relay_addr));
        ice_on_cand_relay_done();
    }

    return;
}

static
int setup_turn(const char *turn_server_ip, unsigned short turn_server_port, const char *local_turn_ip, unsigned short local_turn_port)
{
    g_ice_global.pj_turn_server_addr.ipv4.sin_family = pj_AF_INET();
    g_ice_global.pj_turn_server_addr.ipv4.sin_addr = pj_inet_addr2(turn_server_ip);
    g_ice_global.pj_turn_server_addr.ipv4.sin_port = pj_htons(turn_server_port);
    inetaddr_initbyipport(&g_ice_global.turn_server_addr, turn_server_ip, turn_server_port);
    inetaddr_initbyipport(&g_ice_global.turn_local_addr, local_turn_ip, local_turn_port);
    g_ice_global.turn_transport = udp_peer_new(g_ice_global.loop, local_turn_ip, local_turn_port, on_turn_udp_message, NULL, NULL);

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

    g_ice_global.expect_cand_done_count++;

    return 0;
}

static
void cleanup_turn(void)
{
    pj_turn_session_shutdown(g_ice_global.turn);
    udp_peer_destroy(g_ice_global.turn_transport);

    return;
}

#endif

/**********************************************************************/

static
void on_ice_complete(pj_ice_sess *ice, pj_status_t status)
{
    log_info("=== ice complete, status: %d ===", status);
    if (status == PJ_SUCCESS)
    {
        char msg[1024];
        memset(msg, 0, sizeof(msg));
        int result = snprintf(msg, sizeof(msg), "remote app msg from %s", g_ice_global.ice_foundation);
        pj_ice_sess_send_data(g_ice_global.ice, 1, msg, result+1);
    }

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
    log_info("=== on_ice_tx_pkt, comp_id: %u, transport_id: %u, dst: %s:%u ===", comp_id, transport_id, pj_inet_ntoa(((pj_sockaddr*)dst_addr)->ipv4.sin_addr), pj_sockaddr_get_port(dst_addr));

    if (0) {}
  #if defined(USE_ICE_HOST)
    /* STUN HOST直通 */
    else if (transport_id == 1)
    {
        inetaddr_t addr;
        inetaddr_initbyipport(&addr, pj_inet_ntoa(((pj_sockaddr*)dst_addr)->ipv4.sin_addr), pj_sockaddr_get_port(dst_addr));
        udp_peer_send(g_ice_global.ice_host_transport, pkt, size, &addr);
    }
  #endif
  #if defined(USE_ICE_RELAY)
    /* turn rely */
    else if (transport_id == 2)
    {
        pj_turn_session_sendto(g_ice_global.turn, pkt, size, dst_addr, dst_addr_len);
    }
  #endif
  #if defined(USE_ICE_SVRFLX)
    /* STUN mapped 地址 */
    else if (transport_id == 3 || transport_id == 4)
    {
        inetaddr_t addr;
        inetaddr_initbyipport(&addr, pj_inet_ntoa(((pj_sockaddr*)dst_addr)->ipv4.sin_addr), pj_sockaddr_get_port(dst_addr));
        udp_peer_send(g_ice_global.stun_transport, pkt, size, &addr);
    }
  #endif

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
    log_log("=== on_ice_rx_data, local %s, msg: %s ===", g_ice_global.ice_foundation, (char*)pkt);

    return;
}

static
void setup_ice(int ice_role_passive, const char *ice_ufrag, const char *ice_passwd, const char *ice_foundation)
{
    pj_status_t pj_status;

    strncpy(g_ice_global.ice_ufrag, ice_ufrag, sizeof(g_ice_global.ice_ufrag)-1);
    strncpy(g_ice_global.ice_passwd, ice_passwd, sizeof(g_ice_global.ice_passwd)-1);
    strncpy(g_ice_global.ice_foundation, ice_foundation, sizeof(g_ice_global.ice_foundation)-1);

    pj_ice_sess_cb ice_session_callback = {
        on_ice_complete,
        on_ice_tx_pkt,
        on_ice_rx_data
    };

    pj_ice_sess_role ice_role = ice_role_passive != 0 ? PJ_ICE_SESS_ROLE_CONTROLLING : PJ_ICE_SESS_ROLE_CONTROLLED;

    pj_str_t str_ice_ufrag = {ice_ufrag, strlen(ice_ufrag)};
    pj_str_t str_ice_passwd = {ice_passwd, strlen(ice_passwd)};
    pj_status = pj_ice_sess_create(&g_ice_global.stun_config, "ice", ice_role, 1, &ice_session_callback, 
        &str_ice_ufrag, &str_ice_passwd, NULL, &g_ice_global.ice);
    if (pj_status != PJ_SUCCESS)
    {
        log_error("setup_ice, pj_ice_sess_create() failed, ret: %d", pj_status);
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
  #if defined(USE_ICE_HOST)
    inetaddr_t cand_host;
  #endif
  #if defined(USE_ICE_SVRFLX)
    inetaddr_t cand_svrflx;
  #endif
  #if defined(USE_ICE_RELAY)
    inetaddr_t cand_relay;
  #endif
    char ice_ufrag[8];
    char ice_passwd[32];
    char ice_foundation[32];
};

static
void offer_local_candidate(void)
{
    log_info("=== offer_local_candidate() ===");

    sleep(3);

    struct signal_msg candidate_msg;
    memset(&candidate_msg, 0, sizeof(candidate_msg));
  #if defined(USE_ICE_HOST)
    candidate_msg.cand_host = g_ice_global.candidate_host;
  #endif
  #if defined(USE_ICE_SVRFLX)
    candidate_msg.cand_svrflx = g_ice_global.candidate_svrflx;
  #endif
  #if defined(USE_ICE_RELAY)
    candidate_msg.cand_relay = g_ice_global.candidate_relay;
  #endif
    strncpy(candidate_msg.ice_ufrag, g_ice_global.ice_ufrag, sizeof(candidate_msg.ice_ufrag));
    strncpy(candidate_msg.ice_passwd, g_ice_global.ice_passwd, sizeof(candidate_msg.ice_passwd));
    strncpy(candidate_msg.ice_foundation, g_ice_global.ice_foundation, sizeof(candidate_msg.ice_foundation));

    udp_peer_send(g_ice_global.signal_transport, &candidate_msg, sizeof(candidate_msg), &g_ice_global.remote_signal_addr);

    return;
}

#if defined(USE_ICE_HOST)
static
void ice_on_cand_host_done(void)
{
    if (g_ice_global.expect_cand_done_count == 0)
    {
        offer_local_candidate();
    }

    return;
}
#endif

#if defined(USE_ICE_SVRFLX)
static
void ice_on_cand_svrflx_done(void)
{
    g_ice_global.expect_cand_done_count--;
    if (g_ice_global.expect_cand_done_count == 0)
    {
        offer_local_candidate();
    }
    
    return;
}
#endif

#if defined(USE_ICE_RELAY)
static
void ice_on_cand_relay_done(void)
{
    g_ice_global.expect_cand_done_count--;
    if (g_ice_global.expect_cand_done_count == 0)
    {
        offer_local_candidate();
    }

    return;
}
#endif

static
void on_signal_message(udp_peer_t *peer, void *message, unsigned size, void* userdata, const inetaddr_t *peer_addr)
{
    char cand_msg[1024];
    int cand_msg_len = 0;

    struct signal_msg *candidate_msg = (struct signal_msg*)message;

    pj_ice_sess_cand candidates[4];
    pj_ice_sess_cand *candidate = candidates;
    int candidate_count = 0;
    memset(candidates, 0, sizeof(candidates));

    memset(cand_msg, 0, sizeof(cand_msg));
    cand_msg_len = snprintf(cand_msg, sizeof(cand_msg)-1, "=== received remote candidate offer");

  #if defined(USE_ICE_HOST)
    cand_msg_len += snprintf((cand_msg+cand_msg_len), (sizeof(cand_msg)-1-cand_msg_len), ", host: %s:%u", candidate_msg->cand_host.ip, candidate_msg->cand_host.port);

    candidate->type = PJ_ICE_CAND_TYPE_HOST;
    candidate->status = PJ_SUCCESS;
    candidate->comp_id = 1;
    candidate->transport_id = 1;
    candidate->local_pref = 65535;
    candidate->foundation.ptr = candidate_msg->ice_foundation;
    candidate->foundation.slen = strlen(candidate_msg->ice_foundation);
    candidate->addr.ipv4.sin_family = pj_AF_INET();
    candidate->addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_host.ip);
    candidate->addr.ipv4.sin_port = pj_htons(candidate_msg->cand_host.port);
    candidate->base_addr.ipv4.sin_family = pj_AF_INET();
    candidate->base_addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_host.ip);
    candidate->base_addr.ipv4.sin_port = pj_htons(candidate_msg->cand_host.port);
    candidate_count++;
    candidate++;
  #endif

  #if defined(USE_ICE_RELAY)
    cand_msg_len += snprintf((cand_msg+cand_msg_len), (sizeof(cand_msg)-1-cand_msg_len), ", relay: %s:%u", candidate_msg->cand_relay.ip, candidate_msg->cand_relay.port);
  
    candidate->type = PJ_ICE_CAND_TYPE_RELAYED;
    candidate->status = PJ_SUCCESS;
    candidate->comp_id = 1;
    candidate->transport_id = 2;
    candidate->local_pref = 65535;
    candidate->foundation.ptr = candidate_msg->ice_foundation;
    candidate->foundation.slen = strlen(candidate_msg->ice_foundation);
    candidate->addr.ipv4.sin_family = pj_AF_INET();
    candidate->addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_relay.ip);
    candidate->addr.ipv4.sin_port = pj_htons(candidate_msg->cand_relay.port);
    candidate->base_addr.ipv4.sin_family = pj_AF_INET();
    candidate->base_addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_relay.ip);
    candidate->base_addr.ipv4.sin_port = pj_htons(candidate_msg->cand_relay.port);
    pj_turn_session_set_perm(g_ice_global.turn, 1, &candidate->addr, 1);
    candidate++;
    candidate_count++;
  #endif

  #if defined(USE_ICE_SVRFLX)
    cand_msg_len += snprintf((cand_msg+cand_msg_len), (sizeof(cand_msg)-1-cand_msg_len), ", svrflx: %s:%u", candidate_msg->cand_svrflx.ip, candidate_msg->cand_svrflx.port);

    /* PJ内部也是直接将 checklist中 SVRFLX类型的addr替换成对应的base addr */
    candidate->type = PJ_ICE_CAND_TYPE_HOST;
    candidate->status = PJ_SUCCESS;
    candidate->comp_id = 1;
    candidate->transport_id = 3;
    candidate->local_pref = 65535;
    candidate->foundation.ptr = candidate_msg->ice_foundation;
    candidate->foundation.slen = strlen(candidate_msg->ice_foundation);
    candidate->addr.ipv4.sin_family = pj_AF_INET();
    candidate->addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_svrflx.ip);
    candidate->addr.ipv4.sin_port = pj_htons(candidate_msg->cand_svrflx.port);
    candidate->base_addr.ipv4.sin_family = pj_AF_INET();
    candidate->base_addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_svrflx.ip);
    candidate->base_addr.ipv4.sin_port = pj_htons(candidate_msg->cand_svrflx.port);
    candidate_count++;
    candidate++;

    candidate->type = PJ_ICE_CAND_TYPE_SRFLX;
    candidate->status = PJ_SUCCESS;
    candidate->comp_id = 1;
    candidate->transport_id = 4;
    candidate->local_pref = 65535;
    candidate->foundation.ptr = candidate_msg->ice_foundation;
    candidate->foundation.slen = strlen(candidate_msg->ice_foundation);
    candidate->addr.ipv4.sin_family = pj_AF_INET();
    candidate->addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_svrflx.ip);
    candidate->addr.ipv4.sin_port = pj_htons(candidate_msg->cand_svrflx.port);
    candidate->base_addr.ipv4.sin_family = pj_AF_INET();
    candidate->base_addr.ipv4.sin_addr = pj_inet_addr2(candidate_msg->cand_svrflx.ip);
    candidate->base_addr.ipv4.sin_port = pj_htons(candidate_msg->cand_svrflx.port);
    candidate_count++;
    candidate++;
  #endif
    cand_msg_len += snprintf((cand_msg+cand_msg_len), (sizeof(cand_msg)-1-cand_msg_len), " ===\n");
    log_info(cand_msg);

    pj_str_t ice_ufrag = {candidate_msg->ice_ufrag, strlen(candidate_msg->ice_ufrag)};
    pj_str_t ice_passwd = {candidate_msg->ice_passwd, strlen(candidate_msg->ice_passwd)};
    pj_status_t pj_status = pj_ice_sess_create_check_list(g_ice_global.ice, &ice_ufrag, &ice_passwd, candidate_count, candidates);
    if (pj_status == PJ_SUCCESS)
    {
        pj_status = pj_ice_sess_start_check(g_ice_global.ice);
        if (pj_status != PJ_SUCCESS)
        {
            log_error("pj_ice_sess_start_check() failed, ret: %d", pj_status);
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
    int ice_role_passive;
    const char *ice_ufrag;
    const char *ice_passwd;
    const char *ice_foundation;

    const char *local_ice_host_ip;
    unsigned short local_ice_host_port;

    const char *stun_server_ip;
    unsigned short stun_server_port;
    const char *local_stun_ip;
    unsigned short local_stun_port;

    const char *turn_server_ip;
    unsigned short turn_server_port;
    const char *local_turn_ip;
    unsigned short local_turn_port;

    const char *local_signal_ip;
    unsigned short local_signal_port;
    const char *remote_signal_ip;
    unsigned short remote_signal_port;

    if (argc < 19)
    {
        printf("usge: %s \n"
            "  <ice role: 0/1> <ice ufrag> <ice passwd> <ice foundation>\n"
            "  <local ice host ip> <local ice host port>\n"
            "  <stun server ip> <stun server port>\n"
            "  <local stun ip> <local stun port>\n"
            "  <turn server ip> <turn server port>\n"
            "  <local turn ip> <local turn port>\n"
            "  <local signal ip> <local signal port>\n"
            "  <remote signal ip> <remote signal port>\n", 
            argv[0]);
        return 0;
    }
    ice_role_passive = atoi(argv[1]) != 0;
    ice_ufrag = argv[2];
    ice_passwd = argv[3];
    ice_foundation = argv[4];

    local_ice_host_ip = argv[5];
    local_ice_host_port = (unsigned short)atoi(argv[6]);

    stun_server_ip = argv[7];
    stun_server_port = (unsigned short)atoi(argv[8]);
    local_stun_ip = argv[9];
    local_stun_port = (unsigned short)atoi(argv[10]);

    turn_server_ip = argv[11];
    turn_server_port = (unsigned short)atoi(argv[12]);
    local_turn_ip = argv[13];
    local_turn_port = (unsigned short)atoi(argv[14]);

    local_signal_ip = argv[15];
    local_signal_port = (unsigned short)atoi(argv[16]);
    remote_signal_ip = argv[17];
    remote_signal_port = (unsigned short)atoi(argv[18]);

    memset(&g_ice_global, 0, sizeof(g_ice_global));
    g_ice_global.loop = loop_new(64);

    libpj_init();

    setup_signal(local_signal_ip, local_signal_port, remote_signal_ip, remote_signal_port);
    setup_ice(ice_role_passive, ice_ufrag, ice_passwd, ice_foundation);
  #if defined(USE_ICE_HOST)
    setup_ice_local_host(local_ice_host_ip, local_ice_host_port);
  #endif
  #if defined(USE_ICE_SVRFLX)
    setup_stun(stun_server_ip, stun_server_port, local_stun_ip, local_stun_port);
  #endif
  #if defined(USE_ICE_RELAY)
    setup_turn(turn_server_ip, turn_server_port, local_turn_ip, local_turn_port);
  #endif

    signal(SIGINT, on_interrupt);
    loop_loop(g_ice_global.loop);

  #if defined(USE_ICE_HOST)
    cleanup_ice_local_host();
  #endif
  #if defined(USE_ICE_SVRFLX)
    cleanup_stun();
  #endif
  #if defined(USE_ICE_RELAY)
    cleanup_turn();
  #endif
    cleanup_ice();
    cleanup_signal();

    libpj_uninit();

    loop_destroy(g_ice_global.loop);

    return 0;
}
