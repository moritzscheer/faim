// Copyright (C) 2024 Moritz Scheer

#include <bits/types/struct_iovec.h>
#include <cstdint>
#include <ctime>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>

#include "../../utils/types.hpp"
#include "../connection.hpp"
#include "decoder.hpp"
#include "encoder.hpp"
#include "session.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

int validate_first_header(msghdr *&write, connection *&conn, uint8_t *pkt, size_t &pktlen, ngtcp2_path *path,
                          uint64_t &timestamp, ngtcp2_pkt_info &info)
{

    ngtcp2_cid dcid;

    if (pkt[0] & FORM_BIT_MASK)

    {

        size_t len = LONG_HEADER_MIN_LENGTH;

        if (pktlen < len || !(pkt[0] & FIXED_BIT_MASK))
        {
            return 0;
        }

        dcid.datalen = pkt[5];
        memcpy(&dcid.data, &pkt[6], dcid.datalen);

        len += pkt[5];
        if (pktlen < len)
        {
            return 0;
        }

        ngtcp2_cid scid;

        scid.datalen = pkt[6 + dcid.datalen];
        memcpy(&dcid.data, &pkt[6 + dcid.datalen], scid.datalen);

        len += scid.datalen;
        if (pktlen < len)
        {
            return 0;
        }

        uint64_t version = get_version(pkt);
        if (version == 0)
        {
            return write_version_negotiation_packet(write, &path->remote, dcid, scid);
        }

        ngtcp2_cid odcid;
        uvarint_t token;
        ngtcp2_token_type token_type;

        switch (pkt[0] & TYPE_BIT_MASK)
        {
        case PKT_TYPE_INITIAL:
        {

            token = uvarint_t(&pkt[len]);
            if (token.len == 0)
            {
                return write_retry_packet(write, pktlen, &path->remote, timestamp, version, &odcid, &dcid, &scid);
            }

            int res = verify_token(write, token, pktlen, &path->remote, timestamp, version, &odcid, &dcid, &scid);
            if (res != 0)
            {
                return res;
            }

            len += token.len + 1;
            if (pktlen < len)
            {
                return 0;
            }

            break;
        }
        case PKT_TYPE_0RTT:
        case PKT_TYPE_HANDSHAKE:
        {
            break;
        }
        default:
        {
            return 0;
        }
        }

        uvarint_t payload_len = uvarint_t(&pkt[len]);
        if (!payload_len)
        {
            return 0;
        }

        len += payload_len - 1;
        if (pktlen < len)
        {
            return 0;
        }

        conn = find_connection(dcid);
        if (!conn)
        {
            conn = create_connection(dcid);
            if (!conn)
            {
                return -errno;
            }

            int res = create_session(conn, version, path, &odcid, &dcid, &scid, token, token_type, timestamp);
            if (res != 0)
            {
                return res;
            }
        }
        else if (!valid_scid(conn->quic, &scid))
        {
            return 0;
        }
    }
    else
    {
        size_t len = SHORT_HEADER_MIN_LENGTH;

        if (pktlen < len || !(pkt[0] & FIXED_BIT_MASK))
        {
            return 0;
        }

        dcid.datalen = NGTCP2_MAX_CIDLEN;
        memcpy(&dcid.data, &pkt[2], NGTCP2_MAX_CIDLEN);

        len += pkt[NGTCP2_MAX_CIDLEN];
        if (pktlen < len)
        {
            return 0;
        }

        conn = find_connection(dcid);
        if (!conn)
        {
            return write_stateless_reset_packet(write, &dcid);
        }
    }

    conn->info = info;

    return 0;
}

int verify_token(msghdr *dest, uvarint_t &token, size_t &pktlen, ngtcp2_addr *remote, uint64_t &timestamp,
                 uint32_t &version, ngtcp2_cid *odcid, ngtcp2_cid *dcid, ngtcp2_cid *scid)
{

    if (token != NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY && dcid->datalen < NGTCP2_MIN_INITIAL_DCIDLEN)
    {

        return write_connection_close_packet(dest, dcid, scid, version, {NGTCP2_ERR_PROTO, "Invalid DCID length"});
    }

    switch (token)
    {
    case NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY:
    {

        int res = ngtcp2_crypto_verify_retry_token(odcid, &token.v.n8, token.len, SECRET, SECRET_LEN, version,
                                                   remote->addr, remote->addrlen, dcid, RETRY_TIMEOUT, timestamp);
        if (res == 0)
        {
            return 0;
        }

        return write_connection_close_packet(dest, dcid, scid, version, {NGTCP2_ERR_PROTO, "Invalid DCID length"});
    }
    case NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR:
    {

        int res = ngtcp2_crypto_verify_regular_token(&token.v.n8, token.len, SECRET, SECRET_LEN, remote->addr,
                                                     remote->addrlen, TIMEOUT, timestamp);
        uint32_t get_version(const uint8_t *pkt);

        if (res == 0)
        {
            return 0;
        }

        return write_retry_packet(dest, pktlen, remote, timestamp, version, odcid, dcid, scid);
    }
    default:

        return write_retry_packet(dest, pktlen, remote, timestamp, version, odcid, dcid, scid);
    }
}

uint32_t get_version(const uint8_t *pkt)
{
    uint32_t version = ((uint32_t)pkt[1] << 24) | ((uint32_t)pkt[2] << 16) | ((uint32_t)pkt[3] << 8) | (uint32_t)pkt[4];
    return ntohl(version);
}

bool valid_scid(ngtcp2_conn *conn, ngtcp2_cid *scid)
{
    size_t num_scids = ngtcp2_conn_get_scid(conn, NULL);
    if (num_scids == 0)
    {
        return false;
    }

    ngtcp2_cid scids[num_scids];
    ngtcp2_conn_get_scid(conn, scids);

    for (int i = 0; i < num_scids; i++)
    {
        if (ngtcp2_cid_eq(&scids[i], scid))
        {
            return true;
        }
    }
    return false;
}

} // namespace quic
} // namespace networking
}; // namespace faim
