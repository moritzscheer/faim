// Copyright(C) 2025, Moritz Scheer

#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "../utils/bitmap.hpp"
#include "../utils/types.hpp"
#include "async.hpp"
#include "write.hpp"

namespace faim
{
namespace networking
{
namespace write
{

int setup(buf_ring_t **buf_ring_r, io_uring *ring_r) noexcept
{
    void *mem = mmap(nullptr, BUFFER_RING_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if (mem == MAP_FAILED)
    {
        return -errno;
    }

    buf_ring_t *bufring = (buf_ring_t *)mem;

    io_uring_rsrc_register reg = {
        .nr = 1,
        .flags = 0,
        .data = (__aligned_u64)&bufring->reg,
        .tags = 0,
    };

    int res = io_uring_register(ring_r->ring_fd, IORING_REGISTER_BUFFERS2, &reg, sizeof(reg));
    if (res < 0)
    {
        return res;
    }

    ring = ring_r;

    return 0;
}

void cleanup(buf_ring_t *buf_ring) noexcept
{
    if (buf_ring && buf_ring != MAP_FAILED)
    {
        munmap(buf_ring, BUFFER_RING_SIZE);
    }
}

msghdr_t *buffer(size_t payload_len, uint8_t ecn) noexcept
{
    size_t len = META_DATA_LEN + payload_len;

    uint8_t *mem = (uint8_t *)calloc(1, len);
    if (!mem)
    {
        return NULL;
    }

    msghdr_t *msg = (msghdr_t *)(mem);

    cmsghdr *cmsg = (cmsghdr *)(mem + sizeof(msghdr_t));

    *cmsg = (cmsghdr){
        .cmsg_len = ECN,
        .cmsg_level = IPPROTO_IPV6,
        .cmsg_type = IPV6_TCLASS,
    };

    *CMSG_DATA(cmsg) = ecn;

    msg->msg_control = cmsg;
    msg->msg_controllen = ECN;

    iovec *iov = &msg->iov;

    *iov = (iovec){
        .iov_base = mem + META_DATA_LEN,
        .iov_len = payload_len,
    };

    msg->msg_iov = &msg->iov;
    msg->msg_iovlen = 1;

    return msg;
}

msghdr_t *buffer(buf_ring_t *ring, uint8_t *&dest, size_t &destlen, uint8_t ecn) noexcept
{
    if (destlen == 0)
    {
        return nullptr;
    }

    int num_bufs = (destlen + BUFFER_SIZE - 1) >> BUFFER_SHIFT;

    if (num_bufs >= BUFFERS)
    {
        num_bufs = BUFFERS;
    }

    size_t last_buf_fill = destlen & (BUFFER_SIZE - 1);

    if (last_buf_fill && last_buf_fill < (BUFFER_SIZE >> 1))
    {
        num_bufs--;
    }

    int start_index = bitmap::claim(ring->bitmap, num_bufs);

    if (start_index == -1)
    {
        return nullptr;
    }

    dest = ring->base + ((start_index) & (BUFFERS - 1)) * BUFFER_SIZE;
    destlen = num_bufs * BUFFER_SIZE;

    msghdr_t *msg = (msghdr_t *)dest;

    if (ecn)
    {
        cmsghdr *cmsg = (cmsghdr *)(msg + 1);

        msg->msg_control = cmsg;
        msg->msg_controllen = CMSG_SPACE(sizeof(uint8_t));

        *cmsg = (cmsghdr){
            .cmsg_len = CMSG_SPACE(sizeof(ecn)),
            .cmsg_level = IPPROTO_IPV6,
            .cmsg_type = IPV6_TCLASS,
        };

        uint8_t *ecn_ptr = (uint8_t *)CMSG_DATA(cmsg);
        *ecn_ptr = ecn;
    }

    msg->msg_iov = &msg->iov;
    msg->msg_iovlen = 1;

    msg->iov.iov_base = dest + sizeof(msghdr_t);
    msg->iov.iov_len = destlen - sizeof(msghdr_t);

    msg->total_bytes = destlen;
    msg->ring_num = ring->num;
    msg->num_buf = (uint8_t)num_bufs;

    ring->head = start_index + num_bufs;

    return msg;
}

int resize(buf_ring_t *ring, msghdr_t *msg) noexcept
{
    uint8_t *start = ring->base + ((msg->start_buf) & (BUFFERS - 1)) * BUFFER_SIZE;

    memset(start, 0, BUFFER_SIZE * msg->num_buf);

    bitmap::release(ring->bitmap, msg->start_buf, msg->num_buf);

    return 0;
}

void release(buf_ring_t *ring, msghdr_t *msg) noexcept
{
    uint8_t *start = ring->base + ((msg->start_buf) & (BUFFERS - 1)) * BUFFER_SIZE;

    bitmap::release(ring->bitmap, msg->start_buf, msg->num_buf);

    memset(start, 0, BUFFER_SIZE * msg->num_buf);
}

int prepare(msghdr_t *msg) noexcept
{
    int slot = batch_count.fetch_add(1, std::memory_order_acq_rel);

    if (slot >= SQES)
    {
        batch_count.fetch_sub(1, std::memory_order_acq_rel);
        return 0;
    }

    pending[slot] = msg;

    if (slot == 0)
    {
        return async::prepare();
    }

    return 0;
}

int flush() noexcept
{
    msghdr_t *item;
    io_uring_sqe *sqe;

    int index = batch_count.load(std::memory_order_acquire);
    int remaining_index = 0;
    int flushed = 0;

    for (int i = 0; i < index; i++)
    {
        item = pending[i];

        if (!item)
        {
            break;
        }

        sqe = io_uring_get_sqe(ring);

        if (!sqe)
        {
            if (i != remaining_index)
            {
                pending[remaining_index] = item;
                pending[i] = nullptr;
            }
            remaining_index++;
        }

        io_uring_prep_sendmsg_zc(sqe, *socket, item, 0);

        sqe->flags |= IOSQE_FIXED_FILE;
        sqe->flags |= IOSQE_BUFFER_SELECT;

        io_uring_sqe_set_data(sqe, item);

        pending[i] = nullptr;
        flushed++;
    }

    batch_count.store(remaining_index, std::memory_order_release);

    return flushed;
}

int validate(io_uring_cqe *cqe, msghdr_t *msg) noexcept
{
    if (cqe->res > 0)
    {
        msg->bytes_send += cqe->res;

        if (msg->bytes_send >= msg->total_bytes)
        {
            return 0;
        }

        int remaining = cqe->res;

        // Otherwise adjust iovecs for remaining data and retry
        for (int i = 0; i < msg->msg_iovlen && remaining > 0; ++i)
        {
            iovec &iov = msg->msg_iov[i];

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

        return prepare(msg);
    }

    if (cqe->res == 0 && msg->tries < MAX_TRIES)
    {
        msg->tries++;
        return prepare(msg);
    }

    if (cqe->res == -EINTR)
    {
        return prepare(msg);
    }

    free(msg);
    return 0;
}

}; // namespace write
}; // namespace networking
}; // namespace faim
