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
#include "../middleware/quic/decoder.hpp"
#include "../middleware/quic/session.hpp"
#include "../utils/helper.hpp"
#include "../utils/types.hpp"
#include "scheduler.hpp"
#include "server.hpp"
#include "timer.hpp"

namespace faim
{

using namespace networking;

int server::setup(void) noexcept
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

    res = quic::context_init();
    if (res != 0)
    {
        return cleanup(res);
    }

    res = http::context_init();
    if (res != 0)
    {
        return cleanup(res);
    }

    res = timers.setup(res);
    if (res != 0)
    {
        return cleanup(res);
    }

    res = scheduler.setup(res);
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
        res = io_uring_submit_and_wait(&ring, 1);
        if (res == -EINTR)
        {
            continue;
        }

        int count = io_uring_peek_batch_cqe(&ring, &cqes[0], CQES);

        for (int i = 0; i < count; i++)
        {
            msghdr *event = reinterpret_cast<msghdr *>(io_uring_cqe_get_data(cqes[i]));

            switch (event_type(event))
            {
            case READ:
            {
                res = validate_read(cqes[i]);
                break;
            }
            case WRITE:
            {
                res = validate_write(cqes[i], event);
                break;
            }
            case EVENT:
            {
                res = validate_async(cqes[i], event);
                break;
            }
            case TIMER:
            {
                res = timerwheel::handle_timeouts();
                break;
            }
            default:
            {
                continue;
            }
            }

            if (res < 0)
            {
                break;
            }
        }

        io_uring_cq_advance(&ring, count);
    }

    return cleanup(res);
}

int server::cleanup(int err) noexcept
{
    if (socket >= 0)
    {
        close(socket);
    }

    io_uring_queue_exit(&ring);

    if (buf_ring && buf_ring != MAP_FAILED)
    {
        munmap(buf_ring, BUFFER_RING_SIZE);
    }

    timers.cleanup();

    scheduler.cleanup();

    quic::context_free();

    http::context_free();

    return err;
}

int server::prepare_read() noexcept
{
    io_uring_sqe *sqe;

    do
    {
        sqe = io_uring_get_sqe(&ring);
        if (sqe)
        {
            break;
        }

        io_uring_sqring_wait(&ring);

    } while (1);

    io_uring_prep_recvmsg_multishot(sqe, socket, &msg, MSG_TRUNC);

    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;

    io_uring_sqe_set_data(sqe, NULL);

    return 0;
}

int server::validate_read(io_uring_cqe *cqe) noexcept
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
    {
        prepare_read();
    }

    int buf_id = cqe->flags >> 16;

    if (cqe->res < 0)
    {
        recycle_buffer(buf_id);
        return 0;
    }

    if (!(cqe->flags & IORING_CQE_F_BUFFER))
    {
        return 0;
    }

    io_uring_recvmsg_out *msg_out = io_uring_recvmsg_validate(get_buffer(buf_id), cqe->res, &msg);
    if (!msg_out || msg_out->flags & MSG_CTRUNC || msg_out->namelen > msg.msg_namelen)
    {
        recycle_buffer(buf_id);
        return 0;
    }

    uint8_t *pkt = (uint8_t *)io_uring_recvmsg_payload(msg_out, &msg);
    size_t pktlen = (size_t)io_uring_recvmsg_payload_length(msg_out, BUFFER_SIZE, &msg);
    ngtcp2_path path = ngtcp2_path_create((sockaddr_storage *)io_uring_recvmsg_name(msg_out), msg_out->namelen);

    ngtcp2_pkt_info info = io_uring_get_ecn(msg_out, &msg, path.remote.addr->sa_family);
    uint64_t timestamp = get_timestamp_ns();

    msghdr *write = nullptr;
    connection *conn = nullptr;

    res = quic::validate_first_header(write, conn, pkt, pktlen, &path, timestamp, info);
    if (write)
    {
        res = prepare_write(write);
    }
    else if (conn)
    {
        res = scheduler.create_decoding_routine(conn, pkt, pktlen, path, timestamp);
    }

    recycle_buffer(buf_id);

    return res;
}

int server::prepare_write(msghdr *data) noexcept
{
    io_uring_sqe *sqe;

    do
    {
        sqe = io_uring_get_sqe(&ring);
        if (sqe)
        {
            break;
        }

        io_uring_sqring_wait(&ring);

    } while (1);

    io_uring_prep_sendmsg_zc(sqe, socket, data, 0);

    sqe->flags |= IOSQE_FIXED_FILE;
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;

    io_uring_sqe_set_data(sqe, data);

    return 0;
}

int server::validate_write(io_uring_cqe *cqe, msghdr *data) noexcept
{
    msgctr *ctrl = reinterpret_cast<msgctr *>(data->msg_control);

    if (cqe->res > 0)
    {
        ctrl->bytes_send += cqe->res;

        // If all bytes are send we are done
        if (ctrl->bytes_send >= ctrl->total_bytes)
        {
            return 0;
        }

        int remaining = cqe->res;

        // Otherwise adjust iovecs for remaining data and retry
        for (int i = 0; i < data->msg_iovlen && remaining > 0; ++i)
        {
            iovec &iov = data->msg_iov[i];

            if (remaining >= iov.iov_len)
            {
                remaining -= iov.iov_len;
                iov.iov_base = static_cast<uint8_t *>(iov.iov_base) + iov.iov_len;
                iov.iov_len = 0;
            }
            else
            {
                iov.iov_base = static_cast<uint8_t *>(iov.iov_base) + remaining;
                iov.iov_len -= remaining;
                remaining = 0;
            }
        }

        return prepare_write(data);
    }

    if (cqe->res == 0 && ctrl->tries < MAX_TRIES)
    {
        ctrl->tries++;
        return prepare_write(data);
    }

    if (cqe->res == -EINTR)
    {
        return prepare_write(data);
    }

    free(data);
    return 0;
}

int server::prepare_async() noexcept
{
    eventfd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (eventfd == -1)
    {
        return -errno;
    }

    void *mem = mmap(nullptr, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

    if (mem == MAP_FAILED)
    {
        return -errno;
    }

    io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe)
    {
        return -1;
    }

    io_uring_prep_poll_add(sqe, eventfd, POLLIN);
    io_uring_sqe_set_data(sqe, mem);

    return 0;
}

int server::validate_async(io_uring_cqe *cqe, msghdr *data) noexcept
{
    routine_data *routine = nullptr;
    return scheduler.create_encoding_routine(routine);
    return 0;
}

int server::prepare_timeout() noexcept
{
    io_uring_sqe *sqe;

    do
    {
        sqe = io_uring_get_sqe(&ring);
        if (sqe)
        {
            break;
        }

        io_uring_sqring_wait(&ring);

    } while (1);

    io_uring_prep_timeout(sqe, &timespec, 0, IORING_TIMEOUT_MULTISHOT);
    io_uring_sqe_set_data(sqe, nullptr);

    return 0;
}

int server::validate_timeout(io_uring_cqe *cqe, msghdr *data) noexcept
{
    return 0;
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

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(PORT);
    addr.sin6_addr = in6addr_any;

    if (bind(socket, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1)
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

    res = register_rcvmsg_buffer_ring();
    if (res != 0)
    {
        return res;
    }

    res = prepare_read();
    if (res < 0)
    {
        return res;
    }

    res = prepare_async();
    if (res < 0)
    {
        return res;
    }

    return 0;
}

int server::register_rcvmsg_buffer_ring() noexcept
{
    // Map memory for the io_uring registered buffer ring
    buf_ring = static_cast<io_uring_buf_ring *>(
        mmap(nullptr, BUFFER_RING_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0));

    if (buf_ring == MAP_FAILED)
    {
        return -errno;
    }

    io_uring_buf_ring_init(buf_ring);

    io_uring_buf_reg reg;
    reg.ring_addr = reinterpret_cast<uintptr_t>(buf_ring);
    reg.ring_entries = BUFFERS;
    reg.bgid = 0;

    buffer_base = (unsigned char *)(buf_ring) + sizeof(io_uring_buf) * BUFFERS;

    res = io_uring_register_buf_ring(&ring, &reg, 0);
    if (res < 0)
    {
        return res;
    }

    for (int i = 0; i < BUFFERS; i++)
    {
        io_uring_buf_ring_add(buf_ring, get_buffer(i), BUFFER_SIZE, i, io_uring_buf_ring_mask(BUFFERS), i);
    }

    io_uring_buf_ring_advance(buf_ring, BUFFERS);

    iov.iov_base = nullptr;
    iov.iov_len = BUFFER_SIZE;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    ctrl.type = READ;

    return 0;
}

uint8_t get_event_type(msghdr *user_data)
{
    if (user_data)
    {
        return reinterpret_cast<const msgctr *>(user_data->msg_control)->type;
    }

    return READ;
}

unsigned char *server::get_buffer(const int index) const
{
    return buffer_base + (index << BUFFER_SHIFT);
}

void server::recycle_buffer(const int index) const
{
    io_uring_buf_ring_add(buf_ring, get_buffer(index), BUFFER_SIZE, index, io_uring_buf_ring_mask(BUFFERS), 0);
    io_uring_buf_ring_advance(buf_ring, 1);
}

} // namespace faim
