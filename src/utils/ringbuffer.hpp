// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <sys/mman.h>

#include "bitmap.hpp"
#include "types.hpp"

namespace faim
{
namespace networking
{
namespace ringbuf
{

#define BUFFERS 256

#define N_BITMAP BUFFERS / 64

#define BUFFER_SHIFT 12 // 4KB

#define BUFFER_SIZE (1U << BUFFER_SHIFT)

#define BUFFER_RING_SIZE (sizeof(struct buf_ring_t) + (BUFFERS * BUFFER_SIZE))

#define CMSG_LENGTH CMSG_SPACE(sizeof(uint8_t))

struct buf_ring_t
{
    uint64_t bitmap[N_BITMAP];
    uint8_t *base;
    iovec reg;
    uint8_t head = 0;
    uint8_t num = 0;
};

inline int setup(buf_ring_t **buf_ring_r, io_uring *ring_r) noexcept
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

    return 0;
}

inline void cleanup(buf_ring_t *buf_ring) noexcept
{
    if (buf_ring && buf_ring != MAP_FAILED)
    {
        munmap(buf_ring, BUFFER_RING_SIZE);
    }
}

inline msghdr_t *claim_buffer(buf_ring_t *ring, uint8_t *&dest, size_t &destlen, uint8_t ecn) noexcept
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

inline int resize_buffer(buf_ring_t *ring, msghdr_t *msg) noexcept
{
    uint8_t *start = ring->base + ((msg->start_buf) & (BUFFERS - 1)) * BUFFER_SIZE;

    memset(start, 0, BUFFER_SIZE * msg->num_buf);

    bitmap::release(ring->bitmap, msg->start_buf, msg->num_buf);

    return 0;
}

inline void release_buffer(buf_ring_t *ring, msghdr_t *&msg) noexcept
{
    uint8_t *start = ring->base + ((msg->start_buf) & (BUFFERS - 1)) * BUFFER_SIZE;

    bitmap::release(ring->bitmap, msg->start_buf, msg->num_buf);

    memset(start, 0, BUFFER_SIZE * msg->num_buf);

    msg = nullptr;
}

}; // namespace ringbuf
}; // namespace networking
}; // namespace faim
