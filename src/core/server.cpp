// Copyright (C) 2025, Moritz Scheer

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ngtcp2/ngtcp2.h>

#include "../middleware/http/session.hpp"
#include "../middleware/quic/session.hpp"
#include "../utils/types.hpp"
#include "async.hpp"
#include "read.hpp"
#include "server.hpp"
#include "timer.hpp"
#include "worker.hpp"
#include "write.hpp"

namespace faim
{

using namespace networking;

int server::setup(int argc, char *argv[]) noexcept
{
    res = server::register_socket();
    if (res != 0)
    {
        return cleanup(res);
    }

    res = server::register_ring();
    if (res != 0)
    {
        return cleanup(res);
    }

    res = quic::setup();
    if (res != 0)
    {
        return cleanup(res);
    }

    res = http::setup();
    if (res != 0)
    {
        return cleanup(res);
    }

    res = worker::setup(&ring, &res);
    if (res != 0)
    {
        return cleanup(res);
    }

    return 0;
}

int server::run() noexcept
{
    if (res < 0)
    {
        return res;
    }

    while (true)
    {
        int count = io_uring_peek_batch_cqe(&ring, &cqes[0], CQES);

        if (count > 0)
        {
            for (int i = 0; i < count; i++)
            {
                msghdr_t *msg = (msghdr_t *)io_uring_cqe_get_data(cqes[i]);
                uint64_t event = (uint64_t)msg;

                switch (event)
                {
                case READ:
                {
                    res = read::validate(cqes[i]);
                    break;
                }
                case EVENT:
                {
                    res = async::validate(cqes[i]);
                    break;
                }
                case TIMER:
                {
                    res = timer::validate(cqes[i]);
                    break;
                }
                default:
                {
                    res = write::validate(cqes[i], msg);
                    break;
                }
                }

                if (res < 0)
                {
                    return cleanup(res);
                }
            }

            io_uring_cq_advance(&ring, count);
        }

        int flushed = write::flush();

        if (!count)
        {
            res = io_uring_submit_and_wait(&ring, 1);
        }
        else if (flushed)
        {
            res = io_uring_submit(&ring);
        }

        if (res < 0)
        {
            return cleanup(res);
        }
    }
}

int server::cleanup(int err) noexcept
{
    if (socket >= 0)
    {
        close(socket);
    }

    read::cleanup();

    async::cleanup();

    timer::cleanup();

    worker::cleanup();

    quic::cleanup();

    http::cleanup();

    io_uring_queue_exit(&ring);

    return err;
}

int server::register_socket() noexcept
{
    socket = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (socket == -1)
    {
        return -errno;
    }

    constexpr int dual_stack = ALLOW_IPV4;

    if (setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, &dual_stack, sizeof(dual_stack)) < 0)
    {
        return -errno;
    }

    const int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1 || fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        return -errno;
    }

    if (bind(socket, &local.ipv6.addr.a, sizeof(sockaddr)) == -1)
    {
        return -errno;
    }

    if (listen(socket, BACKLOG) == -1)
    {
        return -errno;
    }

    return 0;
}

int server::register_ring() noexcept
{
    io_uring_params params;

    params.cq_entries = SQES * 8;
    params.sq_thread_idle = 1000;
    params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_CQSIZE |
                   IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SQPOLL;

    res = io_uring_queue_init_params(SQES, &ring, &params);
    if (res != 0)
    {
        return res;
    }

    res = io_uring_register_files(&ring, &socket, 1);
    if (res != 0)
    {
        return res;
    }

    res = read::setup(&ring, &socket);
    if (res != 0)
    {
        return cleanup(res);
    }

    res = async::setup(&ring);
    if (res != 0)
    {
        return cleanup(res);
    }

    res = timer::setup(&ring);
    if (res != 0)
    {
        return cleanup(res);
    }

    return 0;
}

} // namespace faim
