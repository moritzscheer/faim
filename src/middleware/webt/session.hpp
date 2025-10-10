// Copyright (C) 2025, Moritz Scheer

#pragma once

#include "../../utils/map.hpp"
#include "../stream.hpp"

namespace faim
{
namespace networking
{

#define WEBTRANSPORT_PROTOCOL_VIOLATION -200

struct ngwebtr_conn
{
    uint64_t id;

    stream_t *control_stream;

    std::vector<stream_t *> streams;

    ngwebtr_conn *next;
};

int session_new(void *conn);

void session_del(connection *conn, ngwebtr_conn *webt);

uint64_t infer_quic_error_code(int err);

int ngwebtr_conn_close_stream(connection *conn, stream_t *stream);

bool stream_is_control_stream(ngwebtr_conn *conn, stream_t *stream);

}; // namespace networking
}; // namespace faim
