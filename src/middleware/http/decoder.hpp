// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <ngtcp2/ngtcp2.h>

#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace http
{

int parse_headers(rstream *stream, nghttp3_conn *conn);

}; // namespace http
}; // namespace networking
}; // namespace faim
