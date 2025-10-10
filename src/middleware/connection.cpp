// Copyright (C) 2025, Moritz Scheer

#include "connection.hpp"
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

namespace faim
{
namespace networking
{

connection *create_connection(ngtcp2_cid &id)
{
    connection *conn = (connection *)calloc(sizeof(connection *), 1);
    if (!conn)
    {
        return NULL;
    }

    conn->id = id;

    HASH_ADD(hh, connections, id, sizeof(ngtcp2_cid), conn);

    int res = conn->ready_streams.construct();
    if (res < 0)
    {
        return NULL;
    }
}

connection *find_connection(ngtcp2_cid &id)
{
    connection *conn;

    HASH_FIND(hh, connections, &id, sizeof(ngtcp2_cid), conn);

    return conn;
}

void delete_connection(connection *conn)
{
    if (conn->quic)
    {
        ngtcp2_conn_del(conn->quic);
    }

    if (conn->http)
    {
        nghttp3_conn_del(conn->http);
    }

    if (conn)
    {
        free(conn);
    }
}

} // namespace networking
} // namespace faim
