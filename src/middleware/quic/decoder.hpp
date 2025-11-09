// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstddef>
#include <cstdint>

#include <ngtcp2/ngtcp2.h>

#include "../../utils/uvarint.hpp"
#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

/* -------------------------------------------- MACRO DECLARATIONS -------------------------------------------------- */

/* Quic packet header bit maps */

#define FIXED_BIT_MASK 0x40

#define FORM_BIT_MASK 0x80

#define TYPE_BIT_MASK 0x30

/* Quic packet types */

#define PKT_TYPE_INITIAL 0x00

#define PKT_TYPE_0RTT 0x01

#define PKT_TYPE_HANDSHAKE 0x02

/* Minimum lengths for short and long header packets */

// 1 flags + max cid bytes
#define SHORT_HEADER_MIN_LENGTH 1 + NGTCP2_MAX_CIDLEN

// 1 flags + 4 version + 1 dcid length + 1 scid length + 1 pktnum + 1 length
#define LONG_HEADER_MIN_LENGTH 8

#define STREAM_TYPE_UNI_WEBTRANSPORT_STREAM 0x54

#define STREAM_TYPE_BIDI_WEBTRANSPORT_STREAM 0x41

#define STREAM_TYPE_CONTROL_STREAM 0x00

/* ------------------------------------------- FUNCTION DECLARATIONS
   ------------------------------------------------ */

//
//
//
int validate_first_header(connection *&conn, uint8_t *pkt, size_t &pktlen, ngtcp2_path *path, uint64_t &timestamp,
                          ngtcp2_pkt_info &info);

//
//
//
static int verify_token(uvarint_t token, size_t &pktlen, ngtcp2_addr *remote, uint64_t timestamp, uint32_t version,
                        ngtcp2_cid *odcid, ngtcp2_cid *dcid, ngtcp2_cid *scid);

//
//
//
static uint32_t get_version(const uint8_t *pkt);

//
//
//
static bool valid_scid(ngtcp2_conn *conn, ngtcp2_cid *scid);

//
//
//
int parse_stream_data_header(stream_t *dest, connection *conn, int64_t stream_id, const uint8_t *data, size_t datalen,
                             void *stream_user_data);

//
//
//
int create_stream(stream_t *&dest, connection *conn, int64_t &stream_id, uint16_t &type, size_t http, size_t webt);

/* ------------------------------------------------------------------------------------------------------------------ */

} // namespace quic
} // namespace networking
} // namespace faim
