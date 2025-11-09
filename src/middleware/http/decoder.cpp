// Copyright (C) 2024 Moritz Scheer

#include "decoder.hpp"
#include "../connection.hpp"
#include "../stream.hpp"
#include <nghttp3/nghttp3.h>

namespace faim
{
namespace networking
{
namespace http
{

ssize_t read_stream(connection *conn, int64_t stream_id, const uint8_t *src, size_t srclen, int fin, uint64_t ts)
{
    ssize_t nconsumed = nghttp3_conn_read_stream2(conn->http, stream_id, src, srclen, fin, ts);

    if (nconsumed < 0)
    {
        return connection_set_error(&conn->error, static_cast<int>(nconsumed));
    }

    if (nconsumed > 0)
    {
        ngtcp2_conn_extend_max_stream_offset(conn->quic, stream_id, static_cast<uint64_t>(nconsumed));
        ngtcp2_conn_extend_max_offset(conn->quic, static_cast<uint64_t>(nconsumed));
    }

    return 0;
}

void set_max_streams_bidi(connection *conn, uint64_t max_streams)
{
    return nghttp3_conn_set_max_client_streams_bidi(conn->http, max_streams);
}

int add_ack_offset(connection *conn, int64_t stream_id, uint64_t n)
{
    int res = nghttp3_conn_add_ack_offset(conn->http, stream_id, n);

    if (res != 0)
    {
        return connection_set_error(&conn->error, res);
    }

    return 0;
}

int reset_stream(connection *conn, int64_t stream_id)
{
    int res = nghttp3_conn_shutdown_stream_read(conn->http, stream_id);

    if (res != 0)
    {
        return connection_set_error(&conn->error, res);
    }

    return 0;
}

int close_stream(connection *conn, stream_t *stream, uint64_t app_error_code)
{
    int res = nghttp3_conn_close_stream(conn->http, stream->id, app_error_code);

    switch (res)
    {
    case 0:
    {
        if (!ngtcp2_is_bidi_stream(stream->id))
        {
            return 0;
        }

        ngtcp2_conn_extend_max_streams_uni(conn->quic, 1);

        conn->streams.close_stream(stream);

        return 0;
    }
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
    {
        if (ngtcp2_is_bidi_stream(stream->id))
        {
            ngtcp2_conn_extend_max_streams_bidi(conn->quic, 1);
        }

        return 0;
    }
    default:
    {
        return connection_set_error(&conn->error, res);
    }
    }
}

int unblock_stream(connection *conn, int64_t stream_id)
{
    int res = nghttp3_conn_unblock_stream(conn->http, stream_id);

    if (res != 0)
    {
        return connection_set_error(&conn->error, res);
    }

    return 0;
}

int shutdown_stream(connection *conn, int64_t stream_id)
{
    int res = nghttp3_conn_shutdown_stream_read(conn->http, stream_id);

    if (res != 0)
    {
        return connection_set_error(&conn->error, res);
    }

    return 0;
}

}; // namespace http
}; // namespace networking
}; // namespace faim
