// Copyright (C) 2025, Moritz Scheer

#include <cstdint>
#include <ngtcp2/ngtcp2.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <system_error>
#include <thread>

#include "../core/buffer.hpp"
#include "../middleware/connection.hpp"
#include "../middleware/quic/encoder.hpp"
#include "../middleware/quic/session.hpp"
#include "scheduler.hpp"
#include "server.hpp"

namespace faim
{
namespace networking
{

int scheduler_t::setup(int &error) noexcept
{
    num_threads = std::thread::hardware_concurrency();

    threads = (std::thread *)calloc(sizeof(std::thread), num_threads);
    if (!threads)
    {
        return -errno;
    }

    for (int i = 0; i < num_threads; i++)
    {
        std::thread(&scheduler_t::worker_function, this);
    }

    app_error_r = error;

    return 0;
}

int scheduler_t::cleanup() noexcept
{
    for (int i = 0; i < num_threads; i++)
    {
        if (threads[i].joinable())
            threads[i].join();
    }
}

int scheduler_t::create_decoding_routine(connection *conn, uint8_t *pkt, size_t pktlen, ngtcp2_path path,
                                         uint64_t ts) noexcept
{
    routine_data *routine = (routine_data *)malloc(sizeof(routine_data));
    if (!routine)
    {
        return errno;
    }

    uint8_t *data = (uint8_t *)malloc(pktlen);
    if (!data)
    {
        return -errno;
    }

    memcpy(data, pkt, pktlen);

    *routine = routine_data{READ, conn, data, pktlen, path, ts};

    return 0;
}

int scheduler_t::create_encoding_routine(routine_data *t) noexcept
{

    return 0;
}

int scheduler_t::dequeue_routine(uint8_t &type, connection *&conn, uint8_t *&pkt, size_t &pktlen, ngtcp2_path &path,
                                 uint64_t &ts) noexcept
{
    routine_data *data;

    if (!data)
    {
    }

    type = data->type;
    conn = data->conn;
    pkt = data->pkt;
    pktlen = data->pktlen;
    path = data->path;
    ts = data->timestamp;

    free(data);
    return 0;
}

void scheduler_t::worker_function(std::function<int(msghdr *)> write_task) noexcept
{
    uint8_t action;
    connection *conn;
    uint8_t *pkt;
    size_t pktlen;
    ngtcp2_path path;
    timestamp_t ts;

    int res;
    msghdr *msg = nullptr;

    while (true)
    {
        if (msg)
        {
            res = server::prepare_write(msg);
            msg = nullptr;
        }

        if (res != 0)
        {
            return app_error(res);
        }

        res = dequeue_routine(action, conn, pkt, pktlen, path, ts);
        if (res != 0)
        {
            return app_error(res);
        }

        switch (action)
        {
        case READ:
        {
            res = ngtcp2_conn_read_pkt(conn->quic, &path, &conn->pi, pkt, pktlen, ts);

            switch (res)
            {
            case READ_SUCCESSFUL:
            {
                free(pkt);
                break;
            }
            case NGTCP2_ERR_DRAINING:
            {
                free(pkt);
                if (conn->timer)
                {
                    conn->timer->cancelled = true;
                }
                continue;
            }
            case NGTCP2_ERR_DROP_CONN:
            {
                free(pkt);
                if (conn)
                {
                    close_connection(conn);
                }
                continue;
            }
            case NGTCP2_ERR_CALLBACK_FAILURE:
            {
                free(pkt);
                if (critical_error(&conn->error))
                {
                    res = quic::write_connection_close_packet(msg, conn->quic, &path, &conn->pi, &conn->error, ts);
                    if (res != 0)
                    {
                        return app_error(res);
                    }
                    close_connection(conn);
                }
                continue;
            }
            case NGTCP2_ERR_CRYPTO:
            {
                free(pkt);
                if (!conn->error.error_code)
                {
                    ngtcp2_ccerr_set_tls_alert(&conn->error, ngtcp2_conn_get_tls_alert(conn->quic), nullptr, 0);
                }
                res = quic::write_connection_close_packet(msg, conn->quic, &path, &conn->pi, &conn->error, ts);
                if (res != 0)
                {
                    return app_error(res);
                }
                close_connection(conn);
                continue;
            }
            default:
            {
                free(pkt);
                res = quic::write_connection_close_packet(msg, conn->quic, &path, &conn->pi, &conn->error, ts);
                if (res != 0)
                {
                    return app_error(res);
                }
                close_connection(conn);
                continue;
            }
            }

            res = quic::update_timer(conn, ts, action);
        }
        case WRITE:
        {
            pktlen = ngtcp2_conn_get_send_quantum(conn->quic);
            if (pktlen <= 0)
            {
                continue;
            }

            pkt = (uint8_t *)calloc(pktlen, sizeof(uint8_t));
            if (!pkt)
            {
                return app_error(-ENOMEM);
            }

            size_t gso;

            res = ngtcp2_conn_write_aggregate_pkt(conn->quic, &path, &conn->pi, pkt, pktlen, &gso, quic::write_pkt, ts);

            switch (res)
            {
            case WRITE_SUCCESSFUL:
            {
                msg = buffer(pkt, pktlen, gso);
                break;
            }
            case NGTCP2_ERR_NOMEM:
            {
                free(pkt);
                return app_error(-ENOMEM);
            }
            case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
            {
                free(pkt);
                continue;
            }
            case NGTCP2_ERR_CALLBACK_FAILURE:
            {
                free(pkt);
                if (critical_error(&conn->error))
                {
                    res = quic::write_connection_close_packet(msg, conn->quic, &path, &conn->pi, &conn->error, ts);
                    if (res != 0)
                    {
                        return app_error(res);
                    }
                    close_connection(conn);
                }
                continue;
            }
            case NGTCP2_ERR_INVALID_ARGUMENT:
            {
                free(pkt);
                continue;
            }
            case NGTCP2_ERR_WRITE_MORE:
            {
                free(pkt);
                continue;
            }
            default:
            {
                free(pkt);
                res = quic::write_connection_close_packet(msg, conn->quic, &path, &conn->pi, &conn->error, ts);
                if (res != 0)
                {
                    return app_error(res);
                }
                close_connection(conn);
                continue;
            }
            }

            ts = get_timestamp_ns();
            quic::update_timer(conn, ts, action);
        }
        }
    }
}

void scheduler_t::app_error(int res) noexcept
{
    app_error_r = res;
}

int scheduler_t::critical_error(ngtcp2_ccerr *err) noexcept
{
    switch (err->error_code)
    {
    case 0:
    {
    }
    case 1:
    {
    }
    default:
    {
        return err->error_code;
    }
    }
}

} // namespace networking
} // namespace faim
