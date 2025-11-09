// Copyright (C) 2024 Moritz Schee0

#include <cstdint>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../../core/signal.hpp"
#include "../../core/write.hpp"
#include "../../utils/types.hpp"
#include "../connection.hpp"
#include "../http/encoder.hpp"
#include "../stream.hpp"
#include "../webt/encoder.hpp"
#include "encoder.hpp"
#include "session.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

int write_connection_close_packet(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *info,
                                  const ngtcp2_ccerr *ccerr, uint64_t ts)
{
    size_t destlen = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

    msghdr *msg = write::buffer(destlen);
    if (!msg)
    {
        return errno;
    }

    uint8_t *dest = (uint8_t *)msg->msg_iov->iov_base;

    if (ngtcp2_conn_write_connection_close(conn, path, info, dest, destlen, ccerr, ts) != 0)
    {
        return 0;
    }

    return signal::submit(signal::main_thread, msg);
}

int write_connection_close_packet(ngtcp2_cid *dcid, ngtcp2_cid *scid, uint32_t version, error err)
{
    size_t destlen = NGTCP2_MAX_UDP_PAYLOAD_SIZE;

    msghdr *msg = write::buffer(destlen);
    if (!msg)
    {
        return -errno;
    }

    uint8_t *dest = (uint8_t *)msg->msg_iov->iov_base;

    if (ngtcp2_crypto_write_connection_close(dest, destlen, version, dcid, scid, err.code, err.reason,
                                             err.reason_len) == -1)
    {
        return 0;
    }

    return signal::submit(signal::main_thread, msg);
}

int write_retry_packet(size_t pktlen, ngtcp2_addr *remote, uint64_t timestamp, uint32_t version, ngtcp2_cid *odcid,
                       ngtcp2_cid *dcid, ngtcp2_cid *scid)
{
    ngtcp2_cid retry_scid;
    retry_scid.datalen = NGTCP2_MAX_CIDLEN;

    if (RAND_bytes(retry_scid.data, retry_scid.datalen) != 1)
    {
        return ERR_get_error();
    }

    uint8_t token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN];
    ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_retry_token(token, SECRET, SECRET_LEN, version, remote->addr,
                                                               remote->addrlen, &retry_scid, odcid, timestamp);
    if (tokenlen == -1)
    {
        return 0;
    }

    // Retry packet size breakdown (in bytes):
    //
    //  1200+ bytes   Padded length (minimum 1200 per QUIC spec)
    //                If triggering Initial packet is larger than 1200 bytes,
    //                pad Retry to match that size
    //
    size_t destlen = pktlen > 1200 ? pktlen : 1200;

    msghdr *msg = write::buffer(pktlen);
    if (!msg)
    {
        return -errno;
    }

    uint8_t *dest = (uint8_t *)msg->msg_iov->iov_base;

    if (ngtcp2_crypto_write_retry(dest, destlen, version, dcid, scid, odcid, token, tokenlen) == -1)
    {
        return 0;
    }

    return signal::submit(signal::main_thread, msg);
}

int write_stateless_reset_packet(ngtcp2_cid *dcid)
{
    uint8_t random[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
    if (RAND_bytes(random, NGTCP2_MIN_STATELESS_RESET_RANDLEN) != 1)
    {
        return ERR_get_error();
    }

    uint8_t token[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
    if (ngtcp2_crypto_generate_stateless_reset_token(token, SECRET, SECRET_LEN, dcid) != 0)
    {
        return 0;
    }

    // Stateless Reset packet size breakdown (in bytes):
    //
    //  1 byte        Short Header
    //  4 bytes       Random padding (to hide packet type, min 4 bytes)
    //  16 bytes      Stateless Reset Token
    //
    size_t destlen = 1 + 4 + NGTCP2_STATELESS_RESET_TOKENLEN;

    msghdr *msg = write::buffer(destlen);
    if (!msg)
    {
        return -errno;
    }

    uint8_t *dest = (uint8_t *)msg->msg_iov->iov_base;

    ngtcp2_pkt_write_stateless_reset(dest, destlen, token, random, NGTCP2_MIN_STATELESS_RESET_RANDLEN);

    return signal::submit(signal::main_thread, msg);
}

int write_version_negotiation_packet(ngtcp2_addr *remote, ngtcp2_cid dcid, ngtcp2_cid scid)
{
    size_t destlen = FLAG_LEN + CUR_VERS_LEN + DCID_LEN + dcid.datalen + SCID_LEN + scid.datalen + SUP_VERS_LEN;

    uint8_t random;
    if (RAND_bytes(&random, sizeof(uint8_t)) != 1)
    {
        return ERR_get_error();
    }

    msghdr *msg = write::buffer(destlen);
    if (!msg)
    {
        return -errno;
    }

    uint8_t *dest = (uint8_t *)msg->msg_iov->iov_base;

    ngtcp2_pkt_write_version_negotiation((uint8_t *)msg->msg_iov->iov_base, destlen, random, dcid.data, dcid.datalen,
                                         scid.data, scid.datalen, supported_versions.data(), supported_versions.size());

    return signal::submit(signal::main_thread, msg);
}

ngtcp2_ssize write_pkts(ngtcp2_conn *quic, ngtcp2_path *path, ngtcp2_pkt_info *info, uint8_t *dest, size_t destlen,
                        uint64_t ts, void *user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    uint64_t write_left = ngtcp2_conn_get_max_data_left(conn->quic);
    if (write_left <= 0)
    {
        return 0;
    }

    size_t max_pkt = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn->quic);

    static ssize_t len = destlen / max_pkt;

    size_t remaining_pkt = max_pkt;
    ssize_t total_written = 0;

    stream_t *stream = conn->tx.front();
    ssize_t nconsumed;
    ssize_t offset;

    while (stream && write_left > 0)
    {
        switch (stream->type)
        {
        case HTTP:
        {
            nconsumed = http::write_stream(conn, path, info, dest + offset, max_pkt, ts);
        }
        case WEBTRANSPORT:
        {
            nconsumed = webt::write_stream(conn, path, info, dest + offset, max_pkt, ts);
        }
        default:
            continue;
        }

        if (nconsumed < 0)
        {
            return nconsumed;
        }
        else if (nconsumed == 0)
        {
            conn->tx.pop();
            stream = conn->tx.front();
        }
        else
        {
            write_left -= nconsumed;
            total_written += nconsumed;
            stream = stream->next;
        }
    }

    return nconsumed;
}

} // namespace quic
} // namespace networking
}; // namespace faim
