// Copyright (C) 2024 Moritz Scheer

#include <memory>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>
#include <vector>

#include "../connection.hpp"
#include "encoder.hpp"
#include "session.hpp"

namespace faim
{
namespace networking
{
namespace http
{

#define NO_CP_NAME NGHTTP3_NV_FLAG_NO_COPY_NAME

#define NO_CP_NAME_VALUE NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE

ssize_t read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                  void *conn_user_data, void *stream_user_data)
{
    stream_t *stream = reinterpret_cast<stream_t *>(stream_user_data);

    iovec *tx_buf = stream->get_tx_data();

    if (!tx_buf)
    {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    vec->base = (uint8_t *)tx_buf->iov_base;
    vec->len = tx_buf->iov_len;

    *pflags |= NGHTTP3_DATA_FLAG_EOF;

    return 1;
}

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

inline nghttp3_nv make_nv(const std::string_view &name, const std::string_view &value, uint8_t flags)
{
    return nghttp3_nv{
        reinterpret_cast<uint8_t *>(const_cast<char *>(name.data())),
        reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())),
        name.size(),
        value.size(),
        flags,
    };
}

int send_status_response(nghttp3_conn *conn, stream_t *stream, uint32_t status_code)
{
    std::string body = make_status_body(status_code);
    std::string content_length = to_string(body.size());
    std::string status_code_s = to_string(status_code);

    std::vector<nghttp3_nv> fields(4);
    fields[0] = make_nv(":status"sv, status_code_s, NO_CP_NAME);
    fields[1] = make_nv("server"sv, "", NO_CP_NAME_VALUE);
    fields[2] = make_nv("content-type"sv, "text/html; charset=utf-8", NO_CP_NAME_VALUE);
    fields[3] = make_nv("content-length"sv, content_length, NO_CP_NAME);

    stream->data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(body.data()));
    stream->datalen = body.size();

    nghttp3_data_reader dr{
        .read_data = read_data,
    };

    if (auto rv = nghttp3_conn_submit_response(conn, stream->id, fields.data(), fields.size(), &dr); rv != 0)
    {
        return -1;
    }

    return 0;
}

std::string make_status_body(uint32_t status_code)
{
    std::string status_string = std::to_string(status_code);
    std::string_view reason_phrase = http::get_reason_phrase(status_code);

    std::string body;
    body = "<html><head><title>";
    body += status_string;
    body += ' ';
    body += reason_phrase;
    body += "</title></head><body><h1>";
    body += status_string;
    body += ' ';
    body += reason_phrase;
    body += "</h1></body></html>";
    return body;
}

msghdr *encode_packets(connection *conn, msghdr *msg, int64_t *stream_id, int fin, nghttp3_vec *iov, size_t num_iovec)
{
    ssize_t ret = nghttp3_conn_writev_stream(conn->http, stream_id, &fin, iov, num_iovec);

    if (ret < 0)
    {
        // handle errors
        switch (ret)
        {
        case NGHTTP3_ERR_NOMEM:
            throw std::bad_alloc();
        case NGHTTP3_ERR_CALLBACK_FAILURE:
            throw std::runtime_error("nghttp3 callback failed");
        default:
            throw std::runtime_error("nghttp3 connection error");
        }
    }

    nghttp3_conn_add_write_offset(conn->http, *stream_id, ret);

    return NULL;
}

std::string_view get_reason_phrase(uint32_t status_code)
{
    switch (status_code)
    {
    case 100:
        return "Continue"sv;
    case 101:
        return "Switching Protocols"sv;
    case 200:
        return "OK"sv;
    case 201:
        return "Created"sv;
    case 202:
        return "Accepted"sv;
    case 203:
        return "Non-Authoritative Information"sv;
    case 204:
        return "No Content"sv;
    case 205:
        return "Reset Content"sv;
    case 206:
        return "Partial Content"sv;
    case 300:
        return "Multiple Choices"sv;
    case 301:
        return "Moved Permanently"sv;
    case 302:
        return "Found"sv;
    case 303:
        return "See Other"sv;
    case 304:
        return "Not Modified"sv;
    case 305:
        return "Use Proxy"sv;
    // case 306: return "(Unused)"sv;
    case 307:
        return "Temporary Redirect"sv;
    case 308:
        return "Permanent Redirect"sv;
    case 400:
        return "Bad Request"sv;
    case 401:
        return "Unauthorized"sv;
    case 402:
        return "Payment Required"sv;
    case 403:
        return "Forbidden"sv;
    case 404:
        return "Not Found"sv;
    case 405:
        return "Method Not Allowed"sv;
    case 406:
        return "Not Acceptable"sv;
    case 407:
        return "Proxy Authentication Required"sv;
    case 408:
        return "Request Timeout"sv;
    case 409:
        return "Conflict"sv;
    case 410:
        return "Gone"sv;
    case 411:
        return "Length Required"sv;
    case 412:
        return "Precondition Failed"sv;
    case 413:
        return "Payload Too Large"sv;
    case 414:
        return "URI Too Long"sv;
    case 415:
        return "Unsupported Media Type"sv;
    case 416:
        return "Requested Range Not Satisfiable"sv;
    case 417:
        return "Expectation Failed"sv;
    case 421:
        return "Misdirected Request"sv;
    case 426:
        return "Upgrade Required"sv;
    case 428:
        return "Precondition Required"sv;
    case 429:
        return "Too Many Requests"sv;
    case 431:
        return "Request Header Fields Too Large"sv;
    case 451:
        return "Unavailable For Legal Reasons"sv;
    case 500:
        return "Internal Server Error"sv;
    case 501:
        return "Not Implemented"sv;
    case 502:
        return "Bad Gateway"sv;
    case 503:
        return "Service Unavailable"sv;
    case 504:
        return "Gateway Timeout"sv;
    case 505:
        return "HTTP Version Not Supported"sv;
    case 511:
        return "Network Authentication Required"sv;
    default:
        return ""sv;
    }
}

}; // namespace http
}; // namespace networking
}; // namespace faim
