// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cerrno>
#include <cstring>
#include <stdlib.h>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include "stream.hpp"
#include "webt/encoder.hpp"

namespace faim
{
namespace networking
{

#define MIN_STREAM_DATALEN

int stream_buf::push_data(const uint8_t *new_data, size_t new_datalen)
{
    if (!new_data || new_datalen == 0)
    {
        return 0;
    }

    if (!data)
    {
        data = (uint8_t *)malloc(NGTCP2_MAX_UDP_PAYLOAD_SIZE * 4);
        if (!data)
        {
            return -errno;
        }

        datalen = NGTCP2_MAX_UDP_PAYLOAD_SIZE * 4;
    }
    else if (push_offset + new_datalen > datalen)
    {
        size_t new_len = datalen * 2;

        uint8_t *tmp = (uint8_t *)realloc(data, new_len);
        if (!tmp)
        {
            return -errno;
        }

        data = tmp;
        datalen = new_len;
    }

    memcpy((uint8_t *)data + push_offset, new_data, new_datalen);
    push_offset += datalen;

    return 0;
}

int stream_buf::ack_data(size_t datalen)
{
    if (!data || datalen == 0)
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
    if (data)
    {
        free(data);
    }
    *this = {};
}

iovec *stream_t::get_tx_data()
{
    switch (id)
    {
    case CLIENT_UNI:
    {
        return 0;
    }
    case SERVER_UNI:
    {
        uni_tx_stream_t *stream = static_cast<uni_tx_stream_t *>(this);
        return reinterpret_cast<iovec *>(&stream->tx);
    }
    default:
    {
        bidi_stream_t *stream = static_cast<bidi_stream_t *>(this);
        return reinterpret_cast<iovec *>(&stream->tx);
    }
    }
}

int stream_t::push_tx_data(const uint8_t *data, size_t datalen)
{
    switch (id)
    {
    case CLIENT_UNI:
    {
        return 0;
    }
    case SERVER_UNI:
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
    case CLIENT_UNI:
    {
        return static_cast<uni_rx_stream_t *>(this)->rx.push_data(data, datalen);
    }
    case SERVER_UNI:
    {
        return 0;
    }
    default:
    {
        return static_cast<bidi_stream_t *>(this)->rx.push_data(data, datalen);
    }
    }
}

int stream_t::ack_data(size_t datalen)
{
    switch (id)
    {
    case CLIENT_UNI:
    {
        return 0;
    }
    case SERVER_UNI:
    {
        return static_cast<uni_tx_stream_t *>(this)->tx.ack_data(datalen);
    }
    default:
    {
        return static_cast<bidi_stream_t *>(this)->tx.ack_data(datalen);
    }
    }
}

void stream_t::close_stream()
{
    switch (id)
    {
    case CLIENT_UNI:
    {
        uni_rx_stream_t *stream = static_cast<uni_rx_stream_t *>(this);
        if (stream->rx.data)
        {
            free(stream->rx.data);
        }
        break;
    }
    case SERVER_UNI:
    {
        uni_tx_stream_t *stream = static_cast<uni_tx_stream_t *>(this);
        if (stream->tx.data)
        {
            free(stream->tx.data);
        }
        break;
    }
    default:
    {
        bidi_stream_t *stream = static_cast<bidi_stream_t *>(this);
        if (stream->rx.data)
        {
            free(stream->rx.data);
        }
        if (stream->tx.data)
        {
            free(stream->tx.data);
        }
    }
    }

    free(this);
    return;
}

void stream_storage_t::close_stream(stream_t *stream)
{
}

void stream_storage_t::close()
{
    client_uni.destruct();
    server_uni.destruct();
    client_bidi.destruct();
    server_bidi.destruct();
}

} // namespace networking
} // namespace faim
