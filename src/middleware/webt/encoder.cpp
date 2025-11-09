// Copyright (C) 2025, Moritz Scheer

#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace webt
{

ssize_t write_stream(connection *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen,
                     ngtcp2_tstamp ts)
{
    nghttp3_vec vec;

    while (true)
    {
        int64_t stream_id = -1;
        int fin = 0;

        ssize_t sveccnt = nghttp3_conn_writev_stream(conn->http, &stream_id, &fin, &vec, 1);

        if (sveccnt < 0)
        {
            ngtcp2_ccerr_set_application_error(
                &conn->error, nghttp3_err_infer_quic_app_error_code(static_cast<int>(sveccnt)), nullptr, 0);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | NGTCP2_WRITE_STREAM_FLAG_PADDING;
        if (fin)
        {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }

        ssize_t ndatalen;
        size_t vcnt = static_cast<size_t>(sveccnt);

        ssize_t nwrite = ngtcp2_conn_writev_stream(conn->quic, path, pi, dest, destlen, &ndatalen, flags, stream_id,
                                                   reinterpret_cast<const ngtcp2_vec *>(&vec), vcnt, ts);

        if (nwrite < 0)
        {
            switch (nwrite)
            {
            case NGTCP2_ERR_STREAM_DATA_BLOCKED:
            {
                nghttp3_conn_block_stream(conn->http, stream_id);
                continue;
            }
            case NGTCP2_ERR_STREAM_SHUT_WR:
            {
                nghttp3_conn_shutdown_stream_write(conn->http, stream_id);
                continue;
            }
            case NGTCP2_ERR_WRITE_MORE:
            {
                int res = nghttp3_conn_add_write_offset(conn->http, stream_id, ndatalen);
                if (res != 0)
                {
                    ngtcp2_ccerr_set_application_error(&conn->error, nghttp3_err_infer_quic_app_error_code(res),
                                                       nullptr, 0);
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
                continue;
            }
            }

            ngtcp2_ccerr_set_liberr(&conn->error, static_cast<int>(nwrite), nullptr, 0);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        if (ndatalen >= 0)
        {
            int res = nghttp3_conn_add_write_offset(conn->http, stream_id, (size_t)(ndatalen));
            if (res != 0)
            {
                return conn_set_application_error(&conn->error, res);
            }
        }

        return nwrite;
    }
}

} // namespace webt
} // namespace networking
} // namespace faim
