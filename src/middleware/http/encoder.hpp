// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <string_view>

#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace http
{

ssize_t read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                  void *conn_user_data, void *stream_user_data);

ssize_t write_stream(connection *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen,
                     ngtcp2_tstamp ts);

int send_status_response(nghttp3_conn *conn, uint32_t status_code);

std::string make_status_body(uint32_t status_code);

std::string_view get_reason_phrase(uint32_t status_code);

}; // namespace http
}; // namespace networking
}; // namespace faim
