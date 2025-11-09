// Copyright (C) 2025, Moritz Scheer

#include <cstdint>
#include <ngtcp2/ngtcp2.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include "../middleware/connection.hpp"
#include "../middleware/quic/encoder.hpp"
#include "../middleware/quic/session.hpp"
#include "../utils/ringbuffer.hpp"
#include "signal.hpp"
#include "worker.hpp"
#include "write.hpp"

namespace faim
{
namespace networking
{
namespace worker
{

int setup(io_uring *ring_r, int *err_r) noexcept
{
    num_threads = std::thread::hardware_concurrency();

    main_thread = getpid();

    workers = (worker_t *)calloc(num_threads, sizeof(worker_t));
    if (!workers)
    {
        return -errno;
    }

    for (int i = 0; i < num_threads; i++)
    {
        worker_t &worker_args = workers[i];

        res = ringbuf::setup(&worker_args.ring, ring_r);
        if (res != 0)
        {
            return res;
        }

        worker_args.app_err = err_r;

        res = pthread_create(&worker_args.thread, NULL, worker_function, &worker_args);
        if (res != 0)
        {
            return res;
        }
    }

    return 0;
}

void cleanup() noexcept
{
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(workers[i].thread, NULL);
    }

    if (workers)
    {
        free(workers);
    }
}

int enqueue_read(connection *&conn, uint8_t *pkt, size_t pktlen, ngtcp2_path path, ngtcp2_pkt_info pi, uint64_t ts)
{
    routine_data *data = (routine_data *)malloc(sizeof(routine_data));
    if (!data)
    {
        return -ENOMEM;
    }

    data->type = READ;
    data->conn = conn;
    data->pkt = pkt;
    data->pktlen = pktlen;
    data->path = path;
    data->pi = pi;
    data->timestamp = ts;

    return 0;
}

int enqueue_write(connection *conn, uint64_t ts)
{
    routine_data *data = (routine_data *)malloc(sizeof(routine_data));
    if (!data)
    {
        return -ENOMEM;
    }

    data->type = WRITE;
    data->conn = conn;
    data->timestamp = ts;

    return 0;
}

static int dequeue_routine(uint8_t &type, connection *&conn, ngtcp2_path &path, ngtcp2_pkt_info &pi, uint8_t *&pkt,
                           size_t &pktlen, uint64_t &ts)
{
    routine_data *data;

    type = std::move(data->type);
    conn = std::move(data->conn);

    if (type == READ)
    {
        path = std::move(data->path);
        pi = std::move(data->pi);
        pkt = std::move(data->pkt);
        pktlen = std::move(data->pktlen);
    }

    ts = std::move(data->timestamp);

    return 0;
}

static void *worker_function(void *args) noexcept
{
    worker_t *arg = (worker_t *)args;

    pthread_t thread_id = arg->thread;
    write::buf_ring_t *ring = arg->ring;

    msghdr_t *msg = nullptr;

    uint8_t action;
    connection *conn;
    uint8_t *pkt;
    size_t pktlen;
    ngtcp2_path path;
    timestamp_t ts;
    ngtcp2_pkt_info pi;
    size_t gso;

    int res;

    while (true)
    {
        res = dequeue_routine(action, conn, path, pi, pkt, pktlen, ts);
        if (res != 0)
        {
            return app_error(res);
        }

        switch (action)
        {
        case READ:
        {
            res = ngtcp2_conn_read_pkt(conn->quic, &path, &pi, pkt, pktlen, ts);

            switch (res)
            {
            case READ_SUCCESSFUL:
            {
                free(pkt);
                break;
            }
            case NGTCP2_ERR_CALLBACK_FAILURE:
            {
                free(pkt);
                if (critical_error(&conn->error))
                {
                    close_connection(conn, &pi, &path, ts);
                }
                continue;
            }
            case NGTCP2_ERR_DRAINING:
            {
                free(pkt);
                timer::cancel(conn->timer);
                continue;
            }
            case NGTCP2_ERR_DROP_CONN:
            {
                free(pkt);
                close_connection(conn);
                continue;
            }
            case NGTCP2_ERR_CRYPTO:
            {
                free(pkt);
                if (!conn->error.error_code)
                {
                    ngtcp2_ccerr_set_tls_alert(&conn->error, ngtcp2_conn_get_tls_alert(conn->quic), nullptr, 0);
                }
                close_connection(conn, &pi, &path, ts);
                continue;
            }
            default:
            {
                free(pkt);
                close_connection(conn, &pi, &path, ts);
                continue;
            }
            }

            res = quic::update_timer(conn, ts, action);
            if (res < 0)
            {
                return app_error(res);
            }
        }
        case WRITE:
        {
            pktlen = ngtcp2_conn_get_send_quantum(conn->quic);

            if (pktlen <= 0)
            {
                continue;
            }

            msg = write::buffer(ring, pkt, pktlen, pi.ecn);

            if (!msg)
            {
                continue;
            }

            res = ngtcp2_conn_write_aggregate_pkt(conn->quic, &path, &pi, pkt, pktlen, &gso, quic::write_pkts, ts);

            switch (res)
            {
            case WRITE_SUCCESSFUL:
            {
                write::prepare(msg);
                break;
            }
            case NGTCP2_ERR_CALLBACK_FAILURE:
            {
                write::release(ring, msg);
                if (critical_error(&conn->error))
                {
                    close_connection(conn, &pi, &path, ts);
                }
                continue;
            }
            case NGTCP2_ERR_NOMEM:
            {
                write::release(ring, msg);
                return app_error(NGTCP2_ERR_NOMEM);
            }
            case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
            {
                write::release(ring, msg);
                close_connection(conn, &pi, &path, ts);
                continue;
            }
            case NGTCP2_ERR_INVALID_ARGUMENT:
            {
                write::release(ring, msg);
                continue;
            }
            default:
            {
                write::release(ring, msg);
                close_connection(conn, &pi, &path, ts);
                continue;
            }
            }

            res = quic::update_timer(conn, ts, action);
            if (res < 0)
            {
                return app_error(res);
            }
        }
        default:
        {
            return app_error(res);
        }
        }
    }
}

static void *app_error(int res) noexcept
{
    return 0;
}

static int critical_error(ngtcp2_ccerr *err) noexcept
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

} // namespace worker
} // namespace networking
} // namespace faim
