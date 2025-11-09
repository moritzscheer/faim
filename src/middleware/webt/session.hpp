// Copyright (C) 2025, Moritz Scheer

#pragma once

#include "../stream.hpp"

namespace faim
{
namespace networking
{

struct ngwebt_conn
{
    uint64_t id;

    int session_new();

    void session_del();
};

namespace webt
{

#define WEBTRANSPORT_PROTOCOL_VIOLATION -200

uint64_t infer_quic_error_code(int err);

int ngwebtr_conn_close_stream();

bool stream_is_control_stream();

}; // namespace webt
}; // namespace networking
}; // namespace faim
