// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <nghttp3/nghttp3.h>
#include <string_view>

namespace faim
{
namespace networking
{
namespace http
{

int send_status_response(nghttp3_conn *conn, uint32_t status_code);

std::string make_status_body(uint32_t status_code);

std::string_view get_reason_phrase(uint32_t status_code);

}; // namespace http
}; // namespace networking
}; // namespace faim
