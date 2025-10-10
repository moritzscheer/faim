// Copyright (C) 2025, Moritz Scheer

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <system_error>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "../../core/buffer.hpp"
#include "../../core/server.hpp"
#include "../../core/timer.hpp"
#include "../../utils/helper.hpp"
#include "../../utils/types.hpp"
#include "../connection.hpp"
#include "../http/session.hpp"
#include "../quic/encoder.hpp"
#include "../webt/decoder.hpp"
#include "../webt/session.hpp"
#include "session.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

int context_init()
{
    int res = RAND_bytes(secret, SECRET_LEN);
    if (res != 0)
    {
        return res;
    }

    supported_versions = {
        NGTCP2_PROTO_VER_V1, // QUIC v1
        NGTCP2_PROTO_VER_V2  //  QUIC v2 (if available)
    };

    ngtcp2_ccerr_default(&app_error);

    default_settings = (ngtcp2_settings *)calloc(sizeof(ngtcp2_settings), 1);
    if (!default_settings)
    {
        return -errno;
    }

    ngtcp2_settings_default(default_settings);

    default_settings->cc_algo = NGTCP2_CC_ALGO_CUBIC;
    default_settings->initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
    default_settings->log_printf = NULL;
    default_settings->max_tx_udp_payload_size = MAX_TX_UDP_PAYLOAD_SIZE;
    default_settings->max_window = MAX_WINDOW;
    default_settings->max_stream_window = MAX_STREAM_WINDOW;
    default_settings->ack_thresh = ACK_THRESH;
    default_settings->no_tx_udp_payload_size_shaping = NO_TX_UDP_PAYLOAD_SIZE_SHAPING;
    default_settings->handshake_timeout = HANDSHAKE_TIMEOUT;
    default_settings->no_pmtud = NO_PMTUD;
    default_settings->preferred_versions = supported_versions.data();
    default_settings->preferred_versionslen = NUM_SUPPORTED_VERSIONS;

    std::array<uint16_t, 3> payload_size{1300, 1400, NGTCP2_MAX_UDP_PAYLOAD_SIZE};
    default_settings->pmtud_probes = payload_size.data();
    default_settings->pmtud_probeslen = 3;

    default_params = (ngtcp2_transport_params *)calloc(sizeof(ngtcp2_transport_params), 1);
    if (!default_params)
    {
        return -errno;
    }

    ngtcp2_transport_params_default(default_params);

    default_params->initial_max_stream_data_bidi_local = INITIAL_MAX_STREAM_DATA_BIDI_LOCAL;
    default_params->initial_max_stream_data_bidi_remote = INITIAL_MAX_STREAM_DATA_BIDI_REMOTE;
    default_params->initial_max_stream_data_uni = INITIAL_MAX_STREAM_DATA_UNI;
    default_params->initial_max_data = INITIAL_MAX_DATA;
    default_params->initial_max_streams_bidi = INITIAL_MAX_STREAMS_BIDI;
    default_params->initial_max_streams_uni = INITIAL_MAX_STREAMS_UNI;
    default_params->max_idle_timeout = MAX_IDLE_TIMEOUT;
    default_params->active_connection_id_limit = ACTIVE_CONNECTION_ID_LIMIT;
    default_params->stateless_reset_token_present = 1;
    default_params->grease_quic_bit = 1;

    ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx)
    {
        return -errno;
    }

    res = ngtcp2_crypto_boringssl_configure_server_context(ssl_ctx);
    if (res != 0)
    {
        return res;
    }

    res = SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM);
    if (res <= 0)
    {
        return res;
    }

    res = SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM);
    if (res <= 0)
    {
        return res;
    }

    return 0;
}

void context_free()
{
    SSL_CTX_free(ssl_ctx);

    if (default_settings)
    {
        free(default_settings);
    }

    if (default_params)
    {
        free(default_params);
    }
}

int create_session(connection *conn, uint64_t &version, ngtcp2_path *path, ngtcp2_cid *odcid, ngtcp2_cid *dcid,
                   ngtcp2_cid *scid, uvarint_t &token, ngtcp2_token_type &token_type, uint64_t &timestamp)
{
    ngtcp2_conn *quic_conn;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;

    uint8_t rand;
    int res = RAND_bytes(&rand, sizeof(uint32_t));
    if (res != 1)
    {
        return res;
    }

    memcpy(&settings, default_settings, sizeof(ngtcp2_settings));

    settings.initial_ts = timestamp;
    settings.token = &token.v.n8;
    settings.tokenlen = token.len;
    settings.token_type = token_type;
    settings.initial_pkt_num = rand;

    memcpy(&params, default_params, sizeof(ngtcp2_transport_params));

    if (odcid->datalen == 0)
    {
        params.original_dcid = *odcid;
        params.retry_scid = *scid;
        params.retry_scid_present = 1;
    }
    else
    {
        params.original_dcid = *scid;
    }
    params.original_dcid_present = 1;

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl)
    {
        uint32_t err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        return err;
    }

    if (ngtcp2_conn_server_new(&quic_conn, scid, dcid, path, version, &callbacks, &settings, &params, NULL, conn) != 0)
    {
        return -errno;
    }

    ngtcp2_conn_set_tls_native_handle(quic_conn, ssl);
    ngtcp2_ccerr_default(&conn->error);

    conn->quic = quic_conn;

    return 0;
}

void delete_session(ngtcp2_conn *conn)
{
    SSL *ssl = (SSL *)ngtcp2_conn_get_tls_native_handle(conn);
    if (ssl)
    {
        SSL_free(ssl);
    }

    if (conn)
    {
        ngtcp2_conn_del(conn);
    }
}

int update_timer(connection *conn, uint64_t &timestamp, uint8_t &action)
{
    int res = get_timestamp_ns(timestamp);
    if (res < 0)
    {
        return res;
    }

    if (ngtcp2_conn_in_closing_period(conn->quic) || ngtcp2_conn_in_draining_period(conn->quic))
    {
        return 0;
    }

    uint64_t expiry = ngtcp2_conn_get_expiry(conn->quic);

    if (expiry <= timestamp)
    {
        res = ngtcp2_conn_handle_expiry(conn->quic, timestamp);
        if (res == NGTCP2_ERR_IDLE_CLOSE)
        {
            close_connection(conn);
            return 0;
        }
    }

    if (conn->timer)
    {
        conn->timer->cancelled = false;
    }

    conn->timer = timerwheel::add_timer(expiry, conn);

    if (action == READ)
    {
        action = WRITE;
    }

    return 0;
}

int handle_expiry(msghdr *&msg, connection *conn, uint64_t ts)
{
    if (!conn)
    {
        return 0;
    }

    int res = ngtcp2_conn_handle_expiry(conn->quic, ts);
    if (res == NGTCP2_ERR_IDLE_CLOSE)
    {
        close_connection(conn);
        return 0;
    }

    size_t pktlen = ngtcp2_conn_get_send_quantum(conn->quic);
    if (pktlen <= 0)
    {
        return 0;
    }

    uint8_t *pkt = (uint8_t *)calloc(pktlen, sizeof(uint8_t));
    if (!pkt)
    {
        return -errno;
    }

    const ngtcp2_path *path = ngtcp2_conn_get_path(conn->quic);

    size_t gso = 0;

    res = ngtcp2_conn_write_aggregate_pkt(conn->quic, &path, &conn->pi, pkt, pktlen, &gso, quic::write_pkt, ts);

    switch (res)
    {
    case WRITE_SUCCESSFUL:
    {
        msg = buffer(pkt, pktlen, gso);
        res = server::prepare_write(msg);
        return res;
    }
    case NGTCP2_ERR_NOMEM:
    {
        free(pkt);
        return -errno;
    }
    case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
    {
        free(pkt);
    }
    case NGTCP2_ERR_CALLBACK_FAILURE:
    {
        free(pkt);

        return 0;
    }
    case NGTCP2_ERR_INVALID_ARGUMENT:
    {
        return 0;
    }
    case NGTCP2_ERR_WRITE_MORE:
    {
        free(pkt);
        return 0;
    }
    default:
    {
        free(pkt);
        return 0;
    }
    }
}

/* ========================================================================= */
/*                          Callback Functions                               */
/* ========================================================================= */

static int handshake_completed(ngtcp2_conn *quic, void *user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    const ngtcp2_path *path = ngtcp2_conn_get_path(quic);

    uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
    ssize_t tokenlen = ngtcp2_crypto_generate_regular_token(token, SECRET, SECRET_LEN, path->remote.addr,
                                                            path->remote.addrlen, get_timestamp_ns());

    if (tokenlen < 0)
    {
        return 0;
    }

    int res = ngtcp2_conn_submit_new_token(quic, token, (size_t)tokenlen);
    if (res != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int recv_stream_data(ngtcp2_conn *c, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data,
                            size_t datalen, void *user_data, void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    size_t nconsumed = parse_stream_header(conn, stream, flags, data, datalen);
    if (nconsumed == HTTP)
    {
        nconsumed = nghttp3_conn_read_stream2(conn->http, stream_id, data, datalen, flags, get_timestamp_ns());
    }

    if (nconsumed < 0)
    {
        ngtcp2_ccerr_set_application_error(&app_error, infer_quic_error_code(static_cast<int>(nconsumed)), nullptr, 0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (nconsumed > 0)
    {
        ngtcp2_conn_extend_max_stream_offset(c, stream_id, static_cast<uint64_t>(nconsumed));
        ngtcp2_conn_extend_max_offset(c, static_cast<uint64_t>(nconsumed));
    }

    return 0;
}

int acked_stream_data_offset(ngtcp2_conn *c, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data,
                             void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    int res;

    if (stream->type == WEBTRANSPORT)
    {
        res = stream->ack_data(offset);
    }
    else if (conn->http)
    {
        res = nghttp3_conn_add_ack_offset(conn->http, stream_id, offset);
    }

    return res == 0 ? res : NGTCP2_ERR_CALLBACK_FAILURE;
}

int stream_open(ngtcp2_conn *c, int64_t stream_id, void *user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    stream_t *stream = stream_t::create(stream_id);
    if (!stream)
    {
        ngtcp2_ccerr_set_application_error(conn->error, NGHTTP3_H3_INTERNAL_ERROR, NULL, 0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    ngtcp2_conn_set_stream_user_data(c, stream_id, stream);
    return 0;
}

int stream_close(ngtcp2_conn *c, uint32_t flags, int64_t stream_id, uint64_t err, void *user_data,
                 void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
    {
        err = NGHTTP3_H3_NO_ERROR;
    }

    int res;

    if (stream->type == WEBTRANSPORT)
    {
        res = ngwebtr_conn_close_stream(conn, stream);
    }
    else if (conn->http)
    {
        res = nghttp3_conn_close_stream(conn->http, stream_id, err);
    }

    switch (res)
    {
    case 0:
    {

        if (ngtcp2_is_bidi_stream(stream_id))
        {
            ngtcp2_conn_extend_max_streams_bidi(c, 1);
        }
        else
        {
            ngtcp2_conn_extend_max_streams_uni(c, 1);
        }

        stream->close_stream();
        return 0;
    }
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
    {

        if (ngtcp2_is_bidi_stream(stream_id))
        {
            ngtcp2_conn_extend_max_streams_bidi(c, 1);
        }
        else
        {
            ngtcp2_conn_extend_max_streams_uni(c, 1);
        }

        return 0;
    }
    default:
        ngtcp2_ccerr_set_application_error(conn->error, infer_quic_error_code(res), nullptr, 0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

static void rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
    if (RAND_bytes(dest, static_cast<int>(destlen)) != 1)
    {
        std::fill(dest, dest + destlen, 0);
    }
}

static int get_new_connection_id(ngtcp2_conn *c, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1)
    {
        NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if (ngtcp2_crypto_generate_stateless_reset_token(token, SECRET, SECRET_LEN, cid) != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    connections.swap(conn->id, *cid);

    return 0;
}

int remove_connection_id(ngtcp2_conn *c, const ngtcp2_cid *cid, void *user_data)
{
    connections.del(*cid);
    return 0;
}

int path_validation(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path, const ngtcp2_path *old_path,
                    ngtcp2_path_validation_result pv_res, void *user_data)
{
    if (pv_res != NGTCP2_PATH_VALIDATION_RESULT_SUCCESS || !(flags & NGTCP2_PATH_VALIDATION_FLAG_NEW_TOKEN))
    {
        return 0;
    }

    std::array<uint8_t, NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN> token;
    ngtcp2_tstamp ts = get_timestamp_ns();

    ssize_t tokenlen = ngtcp2_crypto_generate_regular_token(token.data(), SECRET, SECRET_LEN, path->remote.addr,
                                                            path->remote.addrlen, ts);
    if (tokenlen < 0)
    {
        return 0;
    }

    int res = ngtcp2_conn_submit_new_token(conn, token.data(), (size_t)tokenlen);
    if (res != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

int stream_reset(ngtcp2_conn *c, int64_t stream_id, uint64_t final_size, uint64_t err, void *user_data,
                 void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    int res;

    if (stream->type == WEBTRANSPORT)
    {
        res = ngwebtr_conn_close_stream(conn, stream);
    }
    else if (conn->http)
    {
        int res = nghttp3_conn_shutdown_stream_read(conn->http, stream_id);
    }

    return res == 0 ? res : NGTCP2_ERR_CALLBACK_FAILURE;
}

int extend_max_remote_streams_bidi(ngtcp2_conn *c, uint64_t max_streams, void *user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    if (conn->http)
    {
        nghttp3_conn_set_max_client_streams_bidi(conn->http, max_streams);
    }

    return 0;
}

int extend_max_stream_data(ngtcp2_conn *c, int64_t stream_id, uint64_t max_data, void *user_data,
                           void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    int res = nghttp3_conn_unblock_stream(conn->http, stream_id);
    if (res != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

int stream_stop_sending(ngtcp2_conn *c, int64_t stream_id, uint64_t err, void *user_data, void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    if (conn->http)
    {
        int res = nghttp3_conn_shutdown_stream_read(conn->http, stream_id);
        if (res != 0)
        {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    return 0;
}

int recv_tx_key(ngtcp2_conn *c, ngtcp2_encryption_level level, void *user_data)
{
    if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT)
    {
        return 0;
    }

    connection *conn = reinterpret_cast<connection *>(user_data);

    int res = http::session_new(conn);
    if (res != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

ngtcp2_callbacks callbacks = {
    /**
     * [client_initial] is a callback function which is invoked
     * when client asks TLS stack to produce first TLS cryptographic
     * handshake message.  This callback function must be specified for
     * a client application.
     */
    NULL, // CLIENT ONLY

    /**
     * [recv_client_initial] is a callback function which is
     * invoked when a server receives the first Initial packet from
     * client.  This callback function must be specified for a server
     * application.
     */
    ngtcp2_crypto_recv_client_initial_cb,

    /**
     * [recv_crypto_data] is a callback function which is
     * invoked when cryptographic data (CRYPTO frame, in other words,
     * TLS message) is received.  This callback function must be
     * specified.
     */
    ngtcp2_crypto_recv_crypto_data_cb,

    /**
     * [handshake_completed] is a callback function which is
     * invoked when QUIC cryptographic handshake has completed.  This
     * callback function is optional.
     */
    handshake_completed,

    /**
     * [recv_version_negotiation] is a callback function which
     * is invoked when Version Negotiation packet is received by a
     * client.  This callback function is optional.
     */
    NULL, // CLIENT ONLY

    /**
     * [encrypt] is a callback function which is invoked to
     * encrypt a QUIC packet.  This callback function must be specified.
     */
    ngtcp2_crypto_encrypt_cb,

    /**
     * [decrypt] is a callback function which is invoked to
     * decrypt a QUIC packet.  This callback function must be specified.
     */
    ngtcp2_crypto_decrypt_cb,

    /**
     * [hp_mask] is a callback function which is invoked to get
     * a mask to encrypt or decrypt QUIC packet header.  This callback
     * function must be specified.
     */
    ngtcp2_crypto_hp_mask_cb,

    /**
     * [recv_stream_data] is a callback function which is
     * invoked when stream data, which includes application data, is
     * received.  This callback function is optional.
     */
    recv_stream_data,

    /**
     * [acked_stream_data_offset] is a callback function which
     * is invoked when stream data, which includes application data, is
     * acknowledged by a remote endpoint.  It tells an application the
     * largest offset of acknowledged stream data without a gap so that
     * application can free memory for the data up to that offset.  This
     * callback function is optional.
     */
    acked_stream_data_offset,

    /**
     * [stream_open] is a callback function which is invoked
     * when new remote stream is opened by a remote endpoint.  This
     * callback function is optional.
     */
    stream_open,

    /**
     * [stream_close] is a callback function which is invoked
     * when a stream is closed.  This callback function is optional.
     */
    stream_close,

    /**
     * [recv_stateless_reset] is a callback function which is
     * invoked when Stateless Reset packet is received.  This callback
     * function is optional.
     */
    NULL,

    /**
     * [recv_retry] is a callback function which is invoked when
     * a client receives Retry packet.  For client, this callback
     * function must be specified.  Server never receive Retry packet.
     */
    NULL, // CLIENT ONLY

    /**
     * [extend_max_local_streams_bidi] is a callback function
     * which is invoked when the number of bidirectional stream which a
     * local endpoint can open is increased.  This callback function is
     * optional.
     */
    NULL,

    /**
     * [extend_max_local_streams_uni] is a callback function
     * which is invoked when the number of unidirectional stream which a
     * local endpoint can open is increased.  This callback function is
     * optional.
     */
    NULL,

    /**
     * [rand] is a callback function which is invoked when the
     * library needs random data.  This callback function must be
     * specified.
     */
    rand,

    /**
     * [get_new_connection_id] is a callback function which is
     * invoked when the library needs new connection ID.  This callback
     * function must be specified.
     */
    get_new_connection_id,

    /**
     * [remove_connection_id] is a callback function which
     * notifies an application that connection ID is no longer used by a
     * remote endpoint.  This callback function is optional.
     */
    remove_connection_id,

    /**
     * [update_key] is a callback function which is invoked when
     * the library tells an application that it must update keying
     * materials, and install new keys.  This callback function must be
     * specified.
     */
    ngtcp2_crypto_update_key_cb,

    /**
     * [path_validation] is a callback function which is invoked
     * when path validation completed.  This callback function is
     * optional.
     */
    path_validation,

    /**
     * [select_preferred_addr] is a callback function which is
     * invoked when the library asks a client to select preferred
     * address presented by a server.  If not set, client ignores
     * preferred addresses.  This callback function is optional.
     */
    NULL, // CLIENT ONLY

    /**
     * [stream_reset] is a callback function which is invoked
     * when a stream is reset by a remote endpoint.  This callback
     * function is optional.
     */
    stream_reset,

    /**
     * [extend_max_remote_streams_bidi] is a callback function
     * which is invoked when the number of bidirectional streams which a
     * remote endpoint can open is increased.  This callback function is
     * optional.
     */
    extend_max_remote_streams_bidi,

    /**
     * [extend_max_remote_streams_uni] is a callback function
     * which is invoked when the number of unidirectional streams which
     * a remote endpoint can open is increased.  This callback function
     * is optional.
     */
    NULL,

    /**
     * [extend_max_stream_data] is callback function which is
     * invoked when the maximum offset of stream data that a local
     * endpoint can send is increased.  This callback function is
     * optional.
     */
    extend_max_stream_data,

    /**
     * [dcid_status] is a callback function which is invoked
     * when the new Destination Connection ID is activated, or the
     * activated Destination Connection ID is now deactivated.  This
     * callback function is optional.
     */
    NULL,

    /**
     * [handshake_confirmed] is a callback function which is
     * invoked when both endpoints agree that handshake has finished.
     * This field is ignored by server because
     * [handshake_completed] also indicates the handshake
     * confirmation for server.  This callback function is optional.
     */
    NULL,

    /**
     * [recv_new_token] is a callback function which is invoked
     * when new token is received from server.  This field is ignored by
     * server.  This callback function is optional.
     */
    NULL, // CLIENT ONLY

    /**
     * [delete_crypto_aead_ctx] is a callback function which
     * deletes a given AEAD cipher context object.  This callback
     * function must be specified.
     */
    ngtcp2_crypto_delete_crypto_aead_ctx_cb,

    /**
     * [delete_crypto_cipher_ctx] is a callback function which
     * deletes a given cipher context object.  This callback function
     * must be specified.
     */
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb,

    /**
     * [recv_datagram] is a callback function which is invoked
     * when DATAGRAM frame is received.  This callback function is
     * optional.
     */
    NULL,

    /**
     * [ack_datagram] is a callback function which is invoked
     * when a QUIC packet containing DATAGRAM frame is acknowledged by a
     * remote endpoint.  This callback function is optional.
     */
    NULL,

    /**
     * [lost_datagram] is a callback function which is invoked
     * when a QUIC packet containing DATAGRAM frame is declared lost.
     * This callback function is optional.
     */
    NULL,

    /**
     * [get_path_challenge_data] is a callback function which is
     * invoked when the library needs new data sent along with
     * PATH_CHALLENGE frame.  This callback must be specified.
     */
    ngtcp2_crypto_get_path_challenge_data_cb,

    /**
     * [stream_stop_sending] is a callback function which is
     * invoked when a local endpoint no longer reads from a stream
     * before it receives all stream data.  This callback function is
     * optional.
     */
    NULL,

    /**
     * [version_negotiation] is a callback function which is
     * invoked when the compatible version negotiation takes place.
     * This callback function must be specified.
     */
    ngtcp2_crypto_version_negotiation_cb,

    /**
     * [recv_rx_key] is a callback function which is invoked
     * when a new key for decrypting packets is installed during QUIC
     * cryptographic handshake.  It is not called for
     * :enum:`ngtcp2_encryption_level.NGTCP2_ENCRYPTION_LEVEL_INITIAL`.
     */
    NULL,

    /**
     * [recv_tx_key] is a callback function which is invoked
     * when a new key for encrypting packets is installed during QUIC
     * cryptographic handshake.  It is not called for
     * :enum:[ngtcp2_encryption_level.NGTCP2_ENCRYPTION_LEVEL_INITIAL`.
     */
    recv_tx_key,

    /**
     * [tls_early_data_rejected] is a callback function which is
     * invoked when server rejected early data during TLS handshake, or
     * client decided not to attempt early data.  This callback function
     * is only used by client.
     */
    NULL, // CLIENT ONLY

    /**
     * [begin_path_validation] is a callback function which is
     * invoked when a path validation has started.  This field is
     * available since v1.14.0.
     */
    NULL,
};

} // namespace quic
} // namespace networking
} // namespace faim
