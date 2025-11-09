// Copyright (C) 2025, Moritz Scheer

#include <cstdint>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include "../../utils/uvarint.hpp"
#include "decoder.hpp"
#include "session.hpp"

namespace faim
{
namespace networking
{
namespace webt
{

ssize_t read_stream(connection *conn, int64_t stream_id, const uint8_t *src, size_t srclen, int fin, uint64_t ts)
{
    ssize_t nconsumed;

    if (nconsumed < 0)
    {
        ngtcp2_ccerr_set_application_error(&conn->error, webt::infer_quic_error_code(static_cast<int>(nconsumed)),
                                           nullptr, 0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (nconsumed > 0)
    {
    }

    return 0;
}

void set_max_streams_bidi(connection *conn, uint64_t max_streams)
{
}

int add_ack_offset(connection *conn, int64_t stream_id, uint64_t n)
{
    return 0;
}

int reset_stream(connection *conn, int64_t stream_id)
{
    return 0;
}

int close_stream(connection *conn, stream_t *stream, uint64_t app_error_code)
{
    return 0;
}

int unblock_stream(connection *conn, int64_t stream_id)
{
    return 0;
}

int shutdown_stream(connection *conn, int64_t stream_id)
{
    return 0;
}

uint8_t get_session_type(uint64_t session_type)
{
    switch (session_type)
    {
    case STREAM_TYPE_UNI_WEBTRANSPORT_STREAM:
    case STREAM_TYPE_BIDI_WEBTRANSPORT_STREAM:
        return WEBTRANSPORT;
    default:
        return HTTP;
    }
}

size_t parse_stream_header(connection *conn, stream_t *stream, int flags, const uint8_t *data, size_t datalen)
{
    size_t offset = 0;

    if (datalen < 2)
    {
        return -1;
    }

    /* Check stream type field (first uvarint of stream data) */

    uvarint_t stream_type = uvarint_t(data);
    if (!stream_type)
    {
        return -1;
    }

    offset += stream_type.len;
    if (datalen < offset + 1)
    {
        return -1;
    }

    if (!stream->type)
    {
        stream->type = get_session_type(stream_type);
    }

    if (stream->type != WEBTRANSPORT)
    {
        return HTTP;
    }

    /* Check session id field (second uvarint of stream data) */

    uvarint_t session_id = uvarint_t(data + offset);
    if (!session_id)
    {
        return -1;
    }

    offset += session_id.len;
    if (datalen < offset + 1)
    {
        return -1;
    }

    ngwebt_conn *webt = find(conn->webt, session_id);
    if (!webt)
    {
        return -1;
    }

    if (stream == webt->control_stream)
    {
        return parse_control_stream(webt, data, datalen, offset);
    }

    auto &streams = webt->streams;

    if (find(streams.begin(), streams.end(), stream) == streams.end())
    {
        streams.push_back(stream);
    }

    /* Check payload length field (third uvarint of stream data) */

    size_t payload_len = datalen - offset;
    if (payload_len == 0)
    {
        return 0;
    }

    stream->push_data(data, datalen, RECV);

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
    {
    }

    return offset;
}

size_t parse_control_stream(ngwebt_conn *conn, const uint8_t *data, size_t datalen, size_t &offset)
{
    uvarint_t frame_type;
    uvarint_t frame_len;

    while (offset < datalen)
    {
        frame_type = uvarint_t(data + offset);
        offset += frame_type.len;
        if (!frame_type || datalen < offset + 1)
        {
            return 0;
        }

        frame_len = uvarint_t(data + offset);
        offset += frame_len.len;
        if (!frame_len || datalen < offset + 1)
        {
            return 0;
        }

        switch (frame_type)
        {
        case FRAME_SETTINGS:
        {
            parse_settings_frame(conn, data, datalen, offset);
            break;
        }
        case FRAME_GOAWAY:
        {
            uvarint_t session_id = uvarint_t(data + offset);
            if (!session_id)
            {
                return -1;
            }

            offset += session_id.len;
            if (datalen < offset + 1)
            {
                return -1;
            }

            offset += session_id.len;
            if (offset > datalen || session_id == 0)
            {
                nconsumed = NGHTTP3_H3_FRAME_ERROR;
                return;
            }
            break;
        }
        default:
            continue;
        }
    }

    return offset;
}

void parse_settings_frame(ngwebt_conn *conn, uint8_t *data, size_t datalen, size_t &offset)
{
    while (offset < datalen)
    {
        uvarint_t id = uvarint_t(data + offset);
        offset += id.len;
        if (offset >= datalen || id == 0)
        {
            return;
        }

        uvarint_t value = uvarint_t(data + offset);
        offset += value.len;
        if (offset >= datalen || value == 0)
        {
            return;
        }

        if (id == SETTING_ENABLE_WEBTRANSPORT && value != 1)
        {
            offset = NGHTTP3_H3_SETTINGS_ERROR;
            return;
        }
    }
}

void parse_goaway_frame(ngwebt_conn *conn, uint8_t *data, size_t datalen, size_t &nconsumed)
{
    uvarint_t session_id = uvarint_t(data + nconsumed);
    nconsumed += session_id.len;
    if (nconsumed > datalen || session_id == 0)
    {
        nconsumed = NGHTTP3_H3_FRAME_ERROR;
        return;
    }
}

size_t handle_stream_data(ngwebt_conn *conn, stream_t *stream, uint32_t flags, const uint8_t *data, size_t datalen,
                          size_t &offset)
{
    size_t payload_len = datalen - offset;
    if (payload_len == 0)
    {
        return 0;
    }

    stream->push_tx_data(data, datalen);

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
    {
    }

    return offset;
}

}; // namespace webt
}; // namespace networking
}; // namespace faim
