// Copyright (C) 2024 Moritz Schee0

#include <cstdint>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../../core/buffer.hpp"
#include "../../utils/types.hpp"
#include "../webt/encoder.hpp"
#include "encoder.hpp"
#include "session.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

msghdr *write_connection_close_packet(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *info,
                                      const ngtcp2_ccerr *ccerr, uint64_t ts)
{
    msghdr *msg = buffer(NGTCP2_MAX_UDP_PAYLOAD_SIZE);
    if (!msg)
    {
        return NULL;
    }

    uint8_t *payload = (uint8_t *)msg->msg_iov->iov_base;

    ngtcp2_conn_write_connection_close(conn, path, info, payload, NGTCP2_MAX_UDP_PAYLOAD_SIZE, ccerr, ts);
    return (msghdr *)msg;
}

int write_connection_close_packet(msghdr *dest, ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *info,
                                  const ngtcp2_ccerr *ccerr, uint64_t ts)
{
    msghdr *msg = buffer(NGTCP2_MAX_UDP_PAYLOAD_SIZE);
    if (!msg)
    {
        return errno;
    }

    uint8_t *payload = (uint8_t *)msg->msg_iov->iov_base;

    ngtcp2_conn_write_connection_close(conn, path, info, payload, NGTCP2_MAX_UDP_PAYLOAD_SIZE, ccerr, ts);

    dest = msg;
    return 0;
}

int write_connection_close_packet(msghdr *dest, ngtcp2_cid *dcid, ngtcp2_cid *scid, uint32_t version, error err)
{
    // Retry packet size breakdown (in bytes):
    //
    size_t payload_len = 1 + 4 + 1 + dcid->datalen + 1 + scid->datalen + (2 * 4);
    msghdr *msg = buffer(payload_len);
    if (!msg)
    {
        return -errno;
    }

    ngtcp2_crypto_write_connection_close((uint8_t *)msg->msg_iov->iov_base, payload_len, version, dcid, scid, err.code,
                                         err.reason, err.reason_len);

    dest = msg;

    return 0;
}

int write_retry_packet(msghdr *dest, size_t pktlen, ngtcp2_addr *remote, uint64_t timestamp, uint32_t version,
                       ngtcp2_cid *odcid, ngtcp2_cid *dcid, ngtcp2_cid *scid)
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
    //  1200+ bytes : Padded length (minimum 1200 per QUIC spec)
    //                If triggering Initial packet is larger than 1200 bytes,
    //                pad Retry to match that size
    pktlen = pktlen > 1200 ? pktlen : 1200;

    msghdr *msg = buffer(pktlen);
    if (!msg)
    {
        return -errno;
    }

    ngtcp2_crypto_write_retry((uint8_t *)msg->msg_iov->iov_base, pktlen, version, dcid, scid, odcid, token, tokenlen);

    dest = msg;

    return 0;
}

int write_stateless_reset_packet(msghdr *dest, ngtcp2_cid *dcid)
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
    //  1 byte   : Short Header
    //  4 bytes  : Random padding (to hide packet type, min 4 bytes)
    //  16 bytes : Stateless Reset Token
    size_t pktlen = 1 + 4 + 16;

    msghdr *msg = buffer(pktlen);
    if (!msg)
    {
        return -errno;
    }

    ngtcp2_pkt_write_stateless_reset((uint8_t *)msg->msg_iov->iov_base, pktlen, token, random,
                                     NGTCP2_MIN_STATELESS_RESET_RANDLEN);

    dest = msg;

    return 0;
}

int write_version_negotiation_packet(msghdr *dest, ngtcp2_addr *remote, ngtcp2_cid dcid, ngtcp2_cid scid)
{
    uint8_t random;
    if (RAND_bytes(&random, sizeof(uint8_t)) != 1)
    {
        return ERR_get_error();
    }

    // Version Negotiation packet size breakdown (in bytes):
    // 1 byte : Flags and Control (includes Fixed Bit etc.)
    // 4 bytes : Version (set to 0 for Version Negotiation)
    // 1 byte : Destination Connection ID length field
    // dcidlen : Destination Connection ID bytes
    // 1 byte : Source Connection ID length field
    // scidlen : Source Connection ID bytes
    // nsv*4 : Supported Versions, 4 bytes each
    size_t payload_len = 1 + 4 + 1 + dcid.datalen + 1 + scid.datalen + (2 * 4);

    msghdr *msg = buffer(payload_len, remote->addrlen, remote->addr);
    if (!msg)
    {
        return -errno;
    }

    ngtcp2_pkt_write_version_negotiation((uint8_t *)msg->msg_iov->iov_base, payload_len, random, dcid.data,
                                         dcid.datalen, scid.data, scid.datalen, supported_versions.data(),
                                         supported_versions.size());

    dest = msg;

    return 0;
}

ngtcp2_ssize write_pkt(connection *conn, stream_t *stream, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *data,
                       size_t datalen, size_t max_pkt_size, ngtcp2_tstamp ts)
{
    int fin;
    iovec vec;
    ngtcp2_ssize nconsumed;

    switch (stream->type)
    {
    case HTTP:
    {
        nconsumed = nghttp3_conn_writev_stream(conn->http, &stream->id, &fin, (nghttp3_vec *)&vec, 1);
        break;
    }
    case WEBTRANSPORT:
    {
        nconsumed = ngwebtr_conn_writev_stream(stream, &fin, &vec, 1);
        break;
    }
    default:
    {
        return 0;
    }
    }

    if (nconsumed < 0)
    {
        ngtcp2_ccerr_set_application_error(&conn->error, infer_quic_error_code(nconsumed), nullptr, 0);

        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (nconsumed == 0)
    {
        return 0;
    }

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | NGTCP2_WRITE_STREAM_FLAG_PADDING;
    if (fin)
    {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    ssize_t nwrite = ngtcp2_conn_writev_stream(conn->quic, path, pi, data, datalen, &nconsumed, flags, stream->id,
                                               (const ngtcp2_vec *)&vec, 1, ts);
    if (nwrite < 0)
    {
        switch (nwrite)
        {
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        {
            nghttp3_conn_block_stream(conn->http, stream->id);
            return 0;
        }
        case NGTCP2_ERR_STREAM_SHUT_WR:
        {
            nghttp3_conn_shutdown_stream_write(conn->http, stream->id);
            return 0;
        }
        case NGTCP2_ERR_WRITE_MORE:
        {
            auto res = nghttp3_conn_add_write_offset(conn->http, stream->id, as_unsigned(nconsumed));

            if (res != 0)
            {
                ngtcp2_ccerr_set_application_error(&conn->error, infer_quic_error_code(res), nullptr, 0);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }

            return 0;
        }
        default:
        {
            ngtcp2_ccerr_set_liberr(&conn->error, static_cast<int>(nwrite), nullptr, 0);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        }
    }

    if (nconsumed >= 0)
    {
        if (auto rv = nghttp3_conn_add_write_offset(conn->http, stream->id, as_unsigned(nconsumed)); rv != 0)
        {
            ngtcp2_ccerr_set_application_error(conn->error, nghttp3_err_infer_quic_app_error_code(rv), nullptr, 0);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    return nwrite;
}

ngtcp2_ssize write_pkts(ngtcp2_conn *quic, ngtcp2_path *path, ngtcp2_pkt_info *info, uint8_t *data, size_t datalen,
                        uint64_t ts, void *user_data)
{
    connection *conn = reinterpret_cast<connection *>(user_data);

    size_t max_pktlen = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn->quic);

    ssize_t total = 0;
    ssize_t nwrite = 0;

    while (conn->ready_streams)
    {
        if (ngtcp2_conn_get_max_data_left(conn->quic))
        {
            break;
        }

        nwrite = conn->ready_streams.flush_and_process(conn, path, info, data, datalen, max_pktlen, ts);

        if (nwrite <= 0)
        {
            break;
        }

        total += nwrite;
    }

    return total;
}

} // namespace quic
} // namespace networking
}; // namespace faim
