// Copyright (C) 2025, Moritz Scheer

#include "session.hpp"
#include "../connection.hpp"
#include <cstdint>
#include <nghttp3/nghttp3.h>

namespace faim
{
namespace networking
{

int session_new(void *conn, stream_t *stream)
{
    connection *c = reinterpret_cast<connection *>(conn);
    if (!conn)
    {
        return 0;
    }

    ngwebtr_conn *webt = c->webt.create(stream->id);
    if (!webt)
    {
        return -errno;
    }

    stream->conn = webt;

    return 0;
}

void session_del(connection *conn, ngwebtr_conn *webt)
{
    if (webt->control_stream)
    {
        webt->control_stream->close_stream();
        free(webt->control_stream);
    }

    webt->streams.del_all([](stream_t *stream) {
        stream->close_stream();
        free(stream);
        return true;
    });

    conn->webt.del(webt->id);
}

uint64_t infer_quic_error_code(int err)
{
    switch (err)
    {
    case WEBTRANSPORT_PROTOCOL_VIOLATION: {
    }
    default:
        return nghttp3_err_infer_quic_app_error_code(err);
    }
}

int ngwebtr_conn_close_stream(connection *conn, stream_t *stream)
{
    if (!stream)
    {
        return NGHTTP3_ERR_STREAM_NOT_FOUND;
    }

    ngwebtr_conn *webt = reinterpret_cast<ngwebtr_conn *>(stream->conn);

    if (stream_is_control_stream(webt, stream))
    {
        session_del(conn, webt);
        return NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM;
    }

    stream->close_stream();
    return 0;
}

}; // namespace networking
}; // namespace faim
