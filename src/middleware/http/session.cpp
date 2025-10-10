// Copyright (C) 2024 Moritz Scheer

#include "session.hpp"
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <openssl/rand.h>
#include <system_error>

#include "../../utils/types.hpp"
#include "../connection.hpp"
#include "encoder.hpp"

namespace faim
{
namespace networking
{
namespace http
{

int context_init()
{
    int res;

    default_settings = (nghttp3_settings *)calloc(sizeof(nghttp3_settings), 1);
    if (!default_settings)
    {
        return -errno;
    }

    nghttp3_settings_default(default_settings);
}

void context_free()
{
    if (default_settings)
    {
        free(default_settings);
    }
}

int session_new(connection *c)
{
    nghttp3_conn *conn;
    nghttp3_settings settings;

    memcpy(&settings, default_settings, sizeof(nghttp3_settings));
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;

    if (nghttp3_conn_server_new(&conn, &callbacks, &settings, NULL, c) != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    const ngtcp2_transport_params *params = ngtcp2_conn_get_local_transport_params(c->quic);
    nghttp3_conn_set_max_client_streams_bidi(conn, params->initial_max_streams_bidi);

    /* need 3 unidirectional streams for http3 */
    if (ngtcp2_conn_get_streams_uni_left(c->quic) <= 3)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    int64_t control_stream_id;

    int res = ngtcp2_conn_open_uni_stream(c->quic, &control_stream_id, nullptr);
    if (res != 0)
    {
        return res;
    }

    res = nghttp3_conn_bind_control_stream(conn, control_stream_id);
    if (res != 0)
    {
        return res;
    }

    int64_t qpack_enc_stream_id, qpack_dec_stream_id;

    res = ngtcp2_conn_open_uni_stream(c->quic, &qpack_enc_stream_id, nullptr);
    if (res != 0)
    {
        return res;
    }

    res = ngtcp2_conn_open_uni_stream(c->quic, &qpack_dec_stream_id, nullptr);
    if (res != 0)
    {
        return res;
    }

    res = nghttp3_conn_bind_qpack_streams(conn, qpack_enc_stream_id, qpack_dec_stream_id);
    if (res != 0)
    {
        return res;
    }

    c->http = conn;

    return 0;
}

void session_del(nghttp3_conn *conn)
{
    if (conn)
    {
        nghttp3_conn_del(conn);
    }
}

/* ========================================================================= */
/*                          Callback Functions                               */
/* ========================================================================= */

static int acked_stream_data(nghttp3_conn *c, int64_t stream_id, uint64_t datalen, void *conn_user_data,
                             void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(conn_user_data);
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    int res = stream->ack_data(datalen);
    if (res != 0)
    {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

int begin_headers(nghttp3_conn *c, int64_t stream_id, void *conn_user_data, void *stream_user_data)
{
    connection *conn = reinterpret_cast<connection *>(conn_user_data);

    stream_t *stream = conn->streams.find(stream_id);
    if (!stream)
    {
        NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    nghttp3_conn_set_stream_user_data(c, stream_id, stream);
    return 0;
}

static int recv_header(nghttp3_conn *c, int64_t stream_id, int32_t token, nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                       uint8_t flags, void *conn_user_data, void *stream_user_data)
{
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    nghttp3_vec vec = nghttp3_rcbuf_get_buf(value);

    switch (token)
    {
    case NGHTTP3_QPACK_TOKEN__PATH:
        stream->uri = std::string{vec.base, vec.base + vec.len};
        break;
    case NGHTTP3_QPACK_TOKEN__METHOD:
        stream->method = std::string{vec.base, vec.base + vec.len};
        break;
    case NGHTTP3_QPACK_TOKEN__AUTHORITY:
        stream->authority = std::string{vec.base, vec.base + vec.len};
        break;
    case NGHTTP3_QPACK_TOKEN__PROTOCOL:
    {
        stream->type = WEBTRANSPORT;
    }
    }

    return 0;
}

int end_headers(nghttp3_conn *conn, int64_t stream_id, int fin, void *user_data, void *stream_user_data)
{
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    return 0;
}

static int stop_sending(nghttp3_conn *c, int64_t stream_id, uint64_t app_error_code, void *conn_user_data,
                        void *stream_user_data)
{
    return 0;
}

static int reset_stream(nghttp3_conn *c, int64_t stream_id, uint64_t app_error_code, void *conn_user_data,
                        void *stream_user_data)
{
    return 0;
}

static int stream_close(nghttp3_conn *c, int64_t stream_id, uint64_t app_error_code, void *conn_user_data,
                        void *stream_user_data)
{
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    if (!ngtcp2_is_bidi_stream(stream_id))
    {
        return 0;
    }

    connection *conn = reinterpret_cast<connection *>(conn_user_data);
    ngtcp2_conn_extend_max_streams_bidi(conn->quic, 1);
    return 0;
}

int shutdown(nghttp3_conn *c, int64_t id, void *conn_user_data)
{
    connection *conn = reinterpret_cast<connection *>(conn_user_data);

    int count;

    count = conn->streams.del_all([](stream_t *stream) { return !stream->webt && stream->bidi; });
    ngtcp2_conn_extend_max_streams_bidi(conn->quic, count);

    count = conn->streams.del_all([](stream_t *stream) { return !stream->webt && !stream->bidi; });
    ngtcp2_conn_extend_max_streams_uni(conn->quic, count);

    return 0;
}

static void rand(uint8_t *dest, size_t destlen)
{
    if (RAND_bytes(dest, static_cast<int>(destlen)) != 1)
    {
        std::fill(dest, dest + destlen, 0);
    }
}

nghttp3_callbacks callbacks = {
    /**
     * [acked_stream_data] is a callback function which is
     * invoked when data sent on a particular stream have been
     * acknowledged by a remote endpoint.
     */
    acked_stream_data,

    /**
     * [stream_close] is a callback function which is invoked
     * when a particular stream has closed.
     */
    stream_close,

    /**
     * [recv_data] is a callback function which is invoked when
     * stream data is received.
     */
    NULL, // NOT NEEDED

    /**
     * [deferred_consume] is a callback function which is
     * invoked when the library consumed data for a particular stream
     * which had been blocked for synchronization between streams.
     */
    NULL, // NOT NEEDED

    /**
     * [begin_headers] is a callback function which is invoked
     * when an HTTP header field section has started on a particular
     * stream.
     */
    begin_headers,

    /**
     * [recv_header] is a callback function which is invoked
     * when a single HTTP header field is received on a particular
     * stream.
     */
    recv_header,

    /**
     * [end_headers] is a callback function which is invoked
     * when an HTTP header field section has ended on a particular
     * stream.
     */
    end_headers,

    /**
     * [begin_trailers] is a callback function which is invoked
     * when an HTTP trailer field section has started on a particular
     * stream.
     */
    NULL, // NOT NEEDED

    /**
     * [recv_trailer] is a callback function which is invoked
     * when a single HTTP trailer field is received on a particular
     * stream.
     */
    NULL, // NOT NEEDED

    /**
     * [end_trailers] is a callback function which is invoked
     * when an HTTP trailer field section has ended on a particular
     * stream.
     */
    NULL, // NOT NEEDED

    /**
     * [stop_sending] is a callback function which is invoked
     * when the library asks application to send STOP_SENDING to a
     * particular stream.
     */
    stop_sending,

    /**
     * [end_stream] is a callback function which is invoked when
     * a receiving side of stream has been closed.
     */
    NULL, // NOT NEEDED

    /**
     * [reset_stream] is a callback function which is invoked
     * when the library asks application to reset stream (by sending
     * RESET_STREAM).
     */
    reset_stream,

    /**
     * [shutdown] is a callback function which is invoked when
     * the remote endpoint has signalled initiation of connection
     * shutdown.
     */
    shutdown,

    /**
     * [recv_settings] is a callback function which is invoked
     * when SETTINGS frame is received.
     */
    NULL, // NOT NEEDED

    /**
     * [recv_origin] is a callback function which is invoked
     * when a single origin in an ORIGIN frame is received.  This field
     * is available since v1.11.0.
     */
    NULL, // NOT NEEDED

    /**
     * [end_origin] is a callback function which is invoked when
     * an ORIGIN frame has been completely processed.  This field is
     * available since v1.11.0.
     */
    NULL, // NOT NEEDED

    /**
     * [rand] is a callback function which is invoked when
     * unpredictable data are needed.  Although this field is optional
     * due to the backward compatibility, it is recommended to specify
     * this field to harden the runtime behavior against suspicious
     * activities of a remote endpoint.  This field is available since
     * v1.11.0.
     */
    rand,

};

}; // namespace http
}; // namespace networking
}; // namespace faim
