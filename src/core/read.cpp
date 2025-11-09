// Copyright(C) 2025, Moritz Scheer

#include <cstdint>
#include <ctime>
#include <sys/mman.h>
#include <sys/socket.h>

#include "../middleware/quic/decoder.hpp"
#include "../utils/helper.hpp"
#include "read.hpp"
#include "worker.hpp"

namespace faim
{
namespace networking
{
namespace read
{

int setup(io_uring *ring_r, int *socket_r) noexcept
{
    void *mem = mmap(nullptr, BUFFER_RING_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if (mem == MAP_FAILED)
    {
        return -errno;
    }

    buf_ring = (io_uring_buf_ring *)mem;
    buffer_base = (unsigned char *)buf_ring + sizeof(io_uring_buf) * BUFFERS;

    io_uring_buf_ring_init(buf_ring);

    reg.ring_addr = (uintptr_t)buf_ring;
    reg.ring_entries = BUFFERS;
    reg.bgid = 0;

    res = io_uring_register_buf_ring(ring, &reg, 0);

    if (res != 0)
    {
        return res;
    }

    for (int i = 0; i < BUFFERS; i++)
    {
        io_uring_buf_ring_add(buf_ring, get_buffer(i), BUFFER_SIZE, i, io_uring_buf_ring_mask(BUFFERS), i);
    }

    io_uring_buf_ring_advance(buf_ring, BUFFERS);

    size_t cmsglen = CMSG_SPACE(sizeof(uint8_t));

    msg = (msghdr_t *)calloc(1, sizeof(msghdr_t) + cmsglen);
    if (!msg)
    {
        return -ENOMEM;
    }

    cmsghdr *cmsg = (cmsghdr *)msg + 1;

    *cmsg = (cmsghdr){
        .cmsg_len = cmsglen,
        .cmsg_level = IPPROTO_IPV6,
        .cmsg_type = IPV6_TCLASS,
    };

    msg->msg_name = nullptr;
    msg->msg_namelen = 0;
    msg->msg_iov = &msg->iov;
    msg->msg_iovlen = 1;
    msg->msg_control = cmsg;
    msg->msg_controllen = cmsglen;
    msg->msg_flags = 0;

    msg->iov.iov_base = nullptr;
    msg->iov.iov_len = BUFFER_SIZE;

    ring = ring_r;
    socket = socket_r;

    prepare();

    return 0;
}

void cleanup() noexcept
{
    if (buf_ring && buf_ring != MAP_FAILED)
    {
        munmap(buf_ring, BUFFER_RING_SIZE);
    }

    if (msg)
    {
        free(msg);
    }
}

void prepare() noexcept
{
    io_uring_sqe *sqe;

    do
    {
        sqe = io_uring_get_sqe(ring);
        if (sqe)
        {
            break;
        }

        io_uring_sqring_wait(ring);

    } while (1);

    io_uring_prep_recvmsg_multishot(sqe, *socket, msg, MSG_TRUNC);

    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;

    io_uring_sqe_set_data(sqe, (void *)READ);
}

int validate(io_uring_cqe *cqe) noexcept
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
    {
        prepare();
    }

    int buf_index = cqe->flags >> 16;
    uint8_t *buf = get_buffer(buf_index);

    if (cqe->res > 0 && !(cqe->flags & IORING_CQE_F_BUFFER))
    {
        io_uring_recvmsg_out *msg_out = io_uring_recvmsg_validate(buf, cqe->res, msg);

        if (msg_out && !(msg_out->flags & MSG_CTRUNC))
        {
            res = validate(msg_out);
        }
    }

    io_uring_buf_ring_add(buf_ring, buf, BUFFER_SIZE, buf_index, BUFFERS - 1, 0);

    return res;
}

static int validate(io_uring_recvmsg_out *msg_out) noexcept
{
    uint64_t ts = get_timestamp_ns();
    if (ts < 0)
    {
        return ts;
    }

    uint8_t *pkt = (uint8_t *)io_uring_recvmsg_payload(msg_out, msg);

    size_t pktlen = (size_t)io_uring_recvmsg_payload_length(msg_out, BUFFER_SIZE, msg);

    ngtcp2_path path = ngtcp2_path_create((sockaddr_storage *)io_uring_recvmsg_name(msg_out), msg_out->namelen);

    ngtcp2_pkt_info info = io_uring_get_ecn(msg_out, msg, path.remote.addr->sa_family);

    connection *conn = nullptr;

    res = quic::validate_first_header(conn, pkt, pktlen, &path, ts, info);

    if (conn)
    {
        return worker::enqueue_read(conn, pkt, pktlen, path, info, ts);
    }

    return res;
}

static unsigned char *get_buffer(int i) noexcept
{
    return buffer_base + (i << BUFFER_SHIFT);
}

}; // namespace read
}; // namespace networking
}; // namespace faim
