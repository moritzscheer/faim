// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <ngtcp2/ngtcp2.h>
#include <openssl/base.h>
#include <sys/socket.h>

#include "../../utils/types.hpp"
#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

int encode_packets(connection *conn, msghdr *msg);

msghdr *write_connection_close_packet(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *info,
                                      const ngtcp2_ccerr *ccerr, uint64_t ts);

int write_connection_close_packet(msghdr *dest, ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *info,
                                  const ngtcp2_ccerr *ccerr, uint64_t ts);

int write_connection_close_packet(msghdr *dest, ngtcp2_cid *dcid, ngtcp2_cid *scid, uint32_t version, error err);

int write_retry_packet(msghdr *dest, size_t pktlen, ngtcp2_addr *remote, uint64_t timestamp, uint32_t version,
                       ngtcp2_cid *odcid, ngtcp2_cid *dcid, ngtcp2_cid *scid);

int write_stateless_reset_packet(msghdr *dest, ngtcp2_cid *dcid);

int write_version_negotiation_packet(msghdr *dest, ngtcp2_addr *remote, ngtcp2_cid dcid, ngtcp2_cid scid);

ngtcp2_ssize write_pkt(connection *conn, stream_t *stream, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *data,
                       size_t datalen, size_t max_pkt_size, ngtcp2_tstamp ts);

ngtcp2_ssize write_pkts(ngtcp2_conn *quic, ngtcp2_path *path, ngtcp2_pkt_info *info, uint8_t *data, size_t datalen,
                        uint64_t ts, void *user_data);

} // namespace quic
} // namespace networking
}; // namespace faim
