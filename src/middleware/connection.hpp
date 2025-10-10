// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include "../core/timer.hpp"
#include "../utils/map.hpp"
#include "../utils/ringbuffer.hpp"
#include "webt/session.hpp"

namespace faim
{
namespace networking
{

struct connection
{
    ngtcp2_cid id;

    UT_hash_handle hh;

    ngtcp2_conn *quic;

    nghttp3_conn *http;

    ngwebtr_conn *webt;

    ringbuf_t ready_streams;

    ngtcp2_pkt_info pi;

    ngtcp2_ccerr error;

    timer_t *timer;
};

connection *connections;

connection *create_connection(ngtcp2_cid &dcid);

connection *find_connection(ngtcp2_cid &dcid);

void close_connection(connection *conn);

} // namespace networking
} // namespace faim
