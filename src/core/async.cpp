// Copyright(C) 2025, Moritz Scheer

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <liburing.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/poll.h>

#include "async.hpp"
#include "worker.hpp"
#include "write.hpp"

namespace faim
{
namespace networking
{
namespace async
{

int setup(io_uring *ring_r) noexcept
{
    asyncfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (asyncfd == -1)
    {
        return -errno;
    }

    void *mem = mmap(nullptr, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

    if (mem == MAP_FAILED)
    {
        return -errno;
    }

    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe)
    {
        return -1;
    }

    io_uring_prep_poll_add(sqe, asyncfd, POLLIN);

    io_uring_sqe_set_data(sqe, (void *)EVENT);

    ring = ring_r;

    return 0;
}

void cleanup() noexcept
{
    if (asyncfd)
    {
        close(asyncfd);
    }
}

int prepare(uint64_t num) noexcept
{
    return eventfd_write(asyncfd, num);
}

void validate() noexcept
{
    uint64_t num;

    res = eventfd_read(asyncfd, &num);

    if (res == -1)
    {
        return;
    }

    while (num)
    {

        num--;
    }
}

}; // namespace async
}; // namespace networking
}; // namespace faim
