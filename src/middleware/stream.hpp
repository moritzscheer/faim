// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstdint>
#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>

namespace faim
{
namespace networking
{

#define STREAM_CLIENT_BIDI 0x00
#define STREAM_SERVER_BIDI 0x01
#define STREAM_CLIENT_UNI 0x02
#define STREAM_SERVER_UNI 0x03

#define WEBTRANSPORT 1
#define HTTP 2

struct stream_buf
{
    uint8_t *buf;

    size_t buflen;

    size_t ack_offset;

    size_t push_offset;

    int ack_data(size_t datalen);

    int push_data(const uint8_t *data, size_t datalen);

    void reset_data();
};

enum flag
{
    RECV,
    SEND
};

struct stream_t
{
    int64_t id;

    uint8_t type;

    bool control;

    void *conn;

    static stream_t *create(uint64_t stream_id);

    ssize_t process(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen,
                    ngtcp2_tstamp ts, void *user_data);

    int push_tx_data(const uint8_t *data, size_t datalen);

    int push_rx_data(const uint8_t *data, size_t datalen);

    int ack_data(size_t datalen);

    void reset_stream();

    void close_stream();
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
