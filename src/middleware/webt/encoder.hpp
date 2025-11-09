// Copyright (C) 2025, Moritz Scheer

#pragma once

#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace webt
{

ssize_t write_stream(connection *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen,
                     ngtcp2_tstamp ts);

}; // namespace webt
}; // namespace networking
}; // namespace faim
