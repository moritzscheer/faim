// Copyright (C) 2025, Moritz Scheer

#pragma once

#define FIXED_BIT_MASK 0x40
#define FORM_BIT_MASK 0x80
#define TYPE_BIT_MASK 0x30

#define PKT_TYPE_INITIAL 0x00
#define PKT_TYPE_0RTT 0x01
#define PKT_TYPE_HANDSHAKE 0x02

#define SHORT_HEADER_MIN_LENGTH 1 + NGTCP2_MAX_CIDLEN // 1 + max cid bytes
#define LONG_HEADER_MIN_LENGTH 8 // 1 flag + 4 version + 1 dcid length + 1 scid length + 1 pktnum + 1 length

#include <cstddef>
#include <cstdint>

#include <ngtcp2/ngtcp2.h>

#include "../../utils/types.hpp"
#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

int validate_first_header(msghdr *&write, connection *&conn, uint8_t *pkt, size_t &pktlen, ngtcp2_path *path,
                          uint64_t &timestamp, ngtcp2_pkt_info &info);

int verify_token(msghdr *dest, uvarint_t token, size_t &pktlen, ngtcp2_addr *remote, uint64_t timestamp,
                 uint32_t version, ngtcp2_cid *odcid, ngtcp2_cid *dcid, ngtcp2_cid *scid);

uint32_t get_version(const uint8_t *pkt);

bool valid_scid(ngtcp2_conn *conn, ngtcp2_cid *scid);

} // namespace quic
} // namespace networking
} // namespace faim
