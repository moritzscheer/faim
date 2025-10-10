// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstddef>
#include <cstdint>

#include "../../utils/helper.hpp"
#include "../connection.hpp"

namespace faim
{
namespace networking
{

typedef enum
{
    FRAME_DATA = 0x00,
    FRAME_HEADERS = 0x01,
    FRAME_CANCEL_PUSH = 0x03,
    FRAME_SETTINGS = 0x04,
    FRAME_PUSH_PROMISE = 0x05,
    FRAME_GOAWAY = 0x07,
    FRAME_MAX_PUSH_ID = 0x0D,

} frame_type;

typedef enum
{
    STREAM_TYPE_CONTROL = 0x00,
    STREAM_TYPE_PUSH = 0x01,
    STREAM_TYPE_QPACK_ENCODER = 0x02,
    STREAM_TYPE_QPACK_DECODER = 0x03,
    STREAM_TYPE_UNI_WEBTRANSPORT_STREAM = 0x54,
    STREAM_TYPE_BIDI_WEBTRANSPORT_STREAM = 0x41

} stream_type;

typedef enum
{
    SETTING_QPACK_MAX_TABLE_CAPACITY = 0x01,
    SETTING_MAX_FIELD_SECTION_SIZE = 0x06,
    SETTING_QPACK_BLOCKED_STREAMS = 0x07,
    SETTING_ENABLE_CONNECT_PROTOCOL = 0x08,
    SETTING_H3_DATAGRAM = 0x33,
    SETTING_H3_DRAFT04_DATAGRAM = 0xffd277,
    SETTING_ENABLE_WEBTRANSPORT = 0x2b603742,
    SETTING_WEBTRANSPORT_MAX_SESSIONS = 0x2b603743

} setting;

size_t parse_stream_header(connection *conn, stream_t *stream, int flags, const uint8_t *data, size_t datalen);

size_t parse_control_stream(ngwebtr_conn *conn, const uint8_t *data, const size_t datalen, size_t &offset);

void parse_settings_frame(ngwebtr_conn *conn, uint8_t *data, size_t datalen, size_t &offset);

void parse_goaway_frame(ngwebtr_conn *conn, uint8_t *data, size_t datalen, size_t &offset);

size_t handle_stream_data(ngwebtr_conn *conn, stream_t *stream, uint32_t flags, const uint8_t *data, size_t datalen,
                          size_t &offset);

} // namespace networking
} // namespace faim
