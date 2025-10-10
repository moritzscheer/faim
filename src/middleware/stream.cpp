// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cerrno>

#include <ngtcp2/ngtcp2.h>

#include "stream.hpp"

namespace faim
{
namespace networking
{

#define MIN_STREAM_DATALEN

int stream_buf::push_data(const uint8_t *data, size_t datalen)
{
    if (!data || datalen == 0)
    {
        return 0;
    }

    if (!buf)
    {
        buf = (uint8_t *)malloc(NGTCP2_MAX_UDP_PAYLOAD_SIZE * 4);
        if (!buf)
        {
            return -errno;
        }

        buflen = NGTCP2_MAX_UDP_PAYLOAD_SIZE * 4;
    }
    else if (push_offset + datalen > buflen)
    {
        size_t new_len = buflen * 2;

        uint8_t *buf = (uint8_t *)realloc(buf, new_len);
        if (!buf)
        {
            return -errno;
        }

        buf = buf;
        buflen = new_len;
    }

    memcpy(buf + push_offset, data, datalen);
    push_offset += datalen;

    return 0;
}

int stream_buf::ack_data(size_t datalen)
{
    if (!buf || datalen == 0)
    {
        return 0;
    }

    if (ack_offset + datalen <= push_offset)
    {
        ack_offset += datalen;
    }
    else
    {
        return -1;
    }

    return 0;
}

void stream_buf::reset_data()
{
    if (buf)
    {
        free(buf);
    }
    *this = {};
}

int stream_t::push_tx_data(const uint8_t *data, size_t datalen)
{
    switch (id)
    {
    case STREAM_CLIENT_UNI:
    {
        return 0;
    }
    case STREAM_SERVER_UNI:
    {
        return static_cast<uni_tx_stream_t *>(this)->tx.push_data(data, datalen);
    }
    default:
    {
        return static_cast<bidi_stream_t *>(this)->tx.push_data(data, datalen);
    }
    }
}

int stream_t::push_rx_data(const uint8_t *data, size_t datalen)
{
    switch (id)
    {
    case STREAM_CLIENT_UNI:
    {
        return static_cast<uni_rx_stream_t *>(this)->rx.push_data(data, datalen);
    }
    case STREAM_SERVER_UNI:
    {
        return 0;
    }
    default:
    {
        return static_cast<bidi_stream_t *>(this)->rx.push_data(data, datalen);
    }
    }
}

stream_t *stream_t::create(uint64_t stream_id)
{
    stream_t *stream;

    switch (stream_id)
    {
    case STREAM_CLIENT_UNI:
    {
        stream = (stream_t *)calloc(sizeof(uni_rx_stream_t), 1);
    }
    case STREAM_SERVER_UNI:
    {
        stream = (stream_t *)calloc(sizeof(uni_tx_stream_t), 1);
    }
    default:
        stream = (stream_t *)calloc(sizeof(bidi_stream_t), 1);
    }

    return stream;
}

int stream_t::ack_data(size_t datalen)
{
    switch (id)
    {
    case STREAM_CLIENT_UNI:
    {
        return 0;
    }
    case STREAM_SERVER_UNI:
    {
        return static_cast<uni_tx_stream_t *>(this)->tx.ack_data(datalen);
    }
    default:
    {
        return static_cast<bidi_stream_t *>(this)->tx.ack_data(datalen);
    }
    }
}

void stream_t::reset_stream()
{
    switch (id)
    {
    case STREAM_CLIENT_UNI:
    {
        static_cast<uni_rx_stream_t *>(this)->rx.reset_data();
    }
    case STREAM_SERVER_UNI:
    {
        static_cast<uni_tx_stream_t *>(this)->tx.reset_data();
    }
    default:
    {
        bidi_stream_t *stream = static_cast<bidi_stream_t *>(this);
        stream->rx.reset_data();
        stream->tx.reset_data();
    }
    }
}

void stream_t::close_stream()
{
    switch (id)
    {
    case STREAM_CLIENT_UNI:
    {
        uni_rx_stream_t *stream = static_cast<uni_rx_stream_t *>(this);
        if (stream->rx.buf)
        {
            free(stream->rx.buf);
        }
        break;
    }
    case STREAM_SERVER_UNI:
    {
        uni_tx_stream_t *stream = static_cast<uni_tx_stream_t *>(this);
        if (stream->tx.buf)
        {
            free(stream->tx.buf);
        }
        break;
    }
    default:
    {
        bidi_stream_t *stream = static_cast<bidi_stream_t *>(this);
        if (stream->rx.buf)
        {
            free(stream->rx.buf);
        }
        if (stream->tx.buf)
        {
            free(stream->tx.buf);
        }
    }
    }

    free(this);
    return;
}

} // namespace networking
} // namespace faim
