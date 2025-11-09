// Copyright (C) 2025, Moritz Scheer

#include "session.hpp"
#include "../connection.hpp"
#include <cstdint>
#include <nghttp3/nghttp3.h>

namespace faim
{
namespace networking
{
namespace webt
{

int ngwebt_conn::session_new()
{
    ngwebt_conn *webt = (ngwebt_conn *)calloc(1, sizeof(ngwebt_conn));
    if (!webt)
    {
        return -errno;
    }

    return 0;
}

void ngwebt_conn::session_del()
{
}

uint64_t infer_quic_error_code(int err)
{
    switch (err)
    {
    case WEBTRANSPORT_PROTOCOL_VIOLATION:
    {
    }
    default:
        return nghttp3_err_infer_quic_app_error_code(err);
    }
}

int ngwebt_conn_close_stream(connection *conn, stream_t *stream)
{
    if (!stream)
    {
        return NGHTTP3_ERR_STREAM_NOT_FOUND;
    }

    ngwebt_conn *webt = reinterpret_cast<ngwebt_conn *>(stream->conn);

    if (stream_is_control_stream(webt, stream))
    {
        session_del(conn, webt);
        return NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM;
    }

    stream->close_stream();
    return 0;
}

}; // namespace webt
}; // namespace networking
}; // namespace faim
