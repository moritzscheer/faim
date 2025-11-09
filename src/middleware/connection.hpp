// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include "../../includes/uthash.h"
#include "../core/timer.hpp"
#include "../utils/queue.hpp"
#include "stream.hpp"
#include "webt/session.hpp"

namespace faim
{
namespace networking
{

/* ------------------------------------------- STRUCT DECLARATIONS -------------------------------------------------- */

struct connection
{
    ngtcp2_conn *quic;

    nghttp3_conn *http;

    ngwebt_conn *webt;

    queue<stream_t> tx;

    stream_storage_t streams;

    ngtcp2_ccerr error;

    timer_t *timer;
};

struct connection_id
{
    UT_hash_handle hh;
    uint8_t id[NGTCP2_MAX_CIDLEN];
    connection *conn;
};

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

static connection_id *connections;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

connection *create_connection(ngtcp2_cid *dcid);

connection *find_connection(ngtcp2_cid *dcid);

int add_connection_id(connection *conn, ngtcp2_cid *dcid);

int remove_connection_id(ngtcp2_conn *quic, const ngtcp2_cid *cid, void *user_data);

void close_connection(connection *conn, ngtcp2_pkt_info *pi = nullptr, ngtcp2_path *path = nullptr, uint64_t ts = 0);

int connection_set_error(ngtcp2_ccerr *ccerr, int err);

/* ------------------------------------------------------------------------------------------------------------------ */

} // namespace networking
} // namespace faim
