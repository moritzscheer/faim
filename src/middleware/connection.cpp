// Copyright (C) 2025, Moritz Scheer

#include <cstdint>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include "connection.hpp"
#include "quic/encoder.hpp"
#include "webt/session.hpp"

namespace faim
{
namespace networking
{

connection *create_connection(ngtcp2_cid *dcid)
{
    connection *conn = (connection *)calloc(1, sizeof(connection));
    if (!conn)
    {
        return NULL;
    }

    connection_id *cid = (connection_id *)calloc(1, sizeof(connection_id));
    if (!cid)
    {
        return NULL;
    }

    memcpy(cid->id, dcid->data, NGTCP2_MAX_CIDLEN);

    cid->conn = conn;

    HASH_ADD(hh, connections, id, NGTCP2_MAX_CIDLEN, cid);

    return conn;
}

connection *find_connection(ngtcp2_cid *dcid)
{
    connection_id *cid;

    HASH_FIND(hh, connections, dcid->data, NGTCP2_MAX_CIDLEN, cid);

    if (cid)
    {
        return cid->conn;
    }

    return nullptr;
}

int add_connection_id(connection *conn, ngtcp2_cid *dcid)
{
    connection_id *cid = (connection_id *)calloc(1, sizeof(connection_id));
    if (!cid)
    {
        return -errno;
    }

    memcpy(cid->id, dcid->data, NGTCP2_MAX_CIDLEN);

    cid->conn = conn;

    HASH_ADD(hh, connections, id, NGTCP2_MAX_CIDLEN, cid);

    return 0;
}

int remove_connection_id(ngtcp2_conn *quic, const ngtcp2_cid *cid, void *user_data)
{
    connection_id *dcid;

    HASH_FIND(hh, connections, cid->data, NGTCP2_MAX_CIDLEN, dcid);

    if (!cid)
    {
        return 0;
    }

    HASH_DEL(connections, dcid);

    free(dcid);

    return 0;
}

void close_connection(connection *conn, ngtcp2_pkt_info *pi, ngtcp2_path *path, uint64_t ts)
{
    if (!conn)
    {
        return;
    }

    if (conn->http)
    {
        nghttp3_conn_del(conn->http);
    }

    if (conn->webt)
    {
    }

    if (conn->timer)
    {
        conn->timer->cancelled = true;
    }

    if (conn->quic)
    {
        size_t num_dcids = ngtcp2_conn_get_active_dcid(conn->quic, NULL);

        if (num_dcids <= 0)
        {
            return;
        }

        ngtcp2_cid_token dest[num_dcids];
        ngtcp2_conn_get_active_dcid(conn->quic, dest);

        for (int i = 0; i < num_dcids; i++)
        {
            ngtcp2_cid *dcid = &(dest + i)->cid;
            remove_connection_id(conn->quic, dcid, nullptr);
        }

        if (pi && path && ts)
        {
            quic::write_connection_close_packet(conn->quic, path, pi, &conn->error, ts);
        }

        ngtcp2_conn_del(conn->quic);
    }

    conn->streams.close();

    free(conn);
}

int connection_set_error(ngtcp2_ccerr *ccerr, int err)
{
    ngtcp2_ccerr_set_application_error(ccerr, webt::infer_quic_error_code(err), nullptr, 0);
    return NGTCP2_ERR_CALLBACK_FAILURE;
}

} // namespace networking
} // namespace faim
