// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <ngtcp2/ngtcp2.h>
#include <openssl/base.h>
#include <sys/socket.h>

#include "../../utils/types.hpp"
#include "../stream.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

#define FLAG_LEN 1

#define CUR_VERS_LEN 4

#define SUP_VERS_LEN 2 * 4

#define DCID_LEN 1

#define SCID_LEN 1

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

static ssize_t res;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

//
//
//
int encode_packets(connection *conn, msghdr *msg);

//
//
//
int write_connection_close_packet(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *info,
                                  const ngtcp2_ccerr *ccerr, uint64_t ts);

//
//
//
int write_connection_close_packet(ngtcp2_cid *dcid, ngtcp2_cid *scid, uint32_t version, error err);

//
//
//
int write_retry_packet(size_t pktlen, ngtcp2_addr *remote, uint64_t timestamp, uint32_t version, ngtcp2_cid *odcid,
                       ngtcp2_cid *dcid, ngtcp2_cid *scid);

//
//
//
int write_stateless_reset_packet(ngtcp2_cid *dcid);

//
//
//
int write_version_negotiation_packet(ngtcp2_addr *remote, ngtcp2_cid dcid, ngtcp2_cid scid);

//
//
//
ngtcp2_ssize write_pkts(ngtcp2_conn *quic, ngtcp2_path *path, ngtcp2_pkt_info *info, uint8_t *dest, size_t destlen,
                        uint64_t ts, void *user_data);

/* ------------------------------------------------------------------------------------------------------------------ */

} // namespace quic
} // namespace networking
}; // namespace faim
