// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <nghttp3/nghttp3.h>

#include "../connection.hpp"
#include "../stream.hpp"

namespace faim
{
namespace networking
{
namespace http
{

ssize_t read_stream(connection *conn, int64_t stream_id, const uint8_t *src, size_t srclen, int fin, uint64_t ts);

void set_max_streams_bidi(connection *conn, uint64_t max_streams);

int add_ack_offset(connection *conn, int64_t stream_id, uint64_t n);

int reset_stream(connection *conn, int64_t stream_id);

int close_stream(connection *conn, stream_t *stream, uint64_t app_error_code);

int unblock_stream(connection *conn, int64_t stream_id);

int shutdown_stream(connection *conn, int64_t stream_id);

}; // namespace http
}; // namespace networking
}; // namespace faim
