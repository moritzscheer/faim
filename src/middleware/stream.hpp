// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstdint>
#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>

#include "../utils/array.hpp"

namespace faim
{
namespace networking
{

#define CLIENT_BIDI 0x0
#define SERVER_BIDI 0x1

#define CLIENT_UNI 0x2
#define SERVER_UNI 0x3

#define DATA 0x4
#define CONTROL 0x8

#define HTTP 0x10
#define WEBTRANSPORT 0x20

struct stream_buf
{
    uint8_t *data;

    size_t datalen;

    size_t ack_offset;

    size_t push_offset;

    int ack_data(size_t datalen);

    int push_data(const uint8_t *data, size_t datalen);

    void reset_data();
};

struct stream_t
{
    uint32_t id;

    uint16_t type;

    uint16_t index;

    stream_t *next;

    iovec *get_tx_data();

    int push_tx_data(const uint8_t *data, size_t datalen);

    int push_rx_data(const uint8_t *data, size_t datalen);

    int ack_data(size_t datalen);

    void close_stream();
};

struct stream_storage_t
{
    array_t<stream_t> client_uni;
    array_t<stream_t> server_uni;
    array_t<stream_t> client_bidi;
    array_t<stream_t> server_bidi;

    void close_stream(stream_t *stream);

    void close();
};

struct uni_rx_stream_t : stream_t
{
    stream_buf rx;
};

struct uni_tx_stream_t : stream_t
{
    stream_buf tx;
};

struct bidi_stream_t : stream_t
{
    stream_buf rx;

    stream_buf tx;
};

}; // namespace networking
}; // namespace faim
