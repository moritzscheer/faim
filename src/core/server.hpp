// Copyright(C) 2025, Moritz Scheer

#pragma once

#include <liburing.h>
#include <ngtcp2/ngtcp2.h>

#include "../utils/types.hpp"
#include "scheduler.hpp"
#include "timer.hpp"

namespace faim
{

using namespace networking;

class server
{
  public:
    server();

    int setup(void) noexcept;

    int run(void) noexcept;

    int cleanup(int err) noexcept;

  private:
    //
    // Functions for reading events
    //
    int prepare_read() noexcept;

    //
    // Functions for reading events
    //
    int validate_read(io_uring_cqe *cqe) noexcept;

  public:
    //
    // Functions for writing events
    //
    static int prepare_write(msghdr *data) noexcept;

    //
    // Functions for writing events
    //
    int validate_write(io_uring_cqe *cqe, msghdr *data) noexcept;

  private:
    //
    // Functions for specialized events
    //
    int prepare_async() noexcept;

    //
    // Functions for specialized events
    //
    int validate_async(io_uring_cqe *cqe, msghdr *data) noexcept;

  private:
    //
    // Functions for timer events
    //
    int prepare_timeout() noexcept;

    //
    // Functions for timer events
    //
    int validate_timeout(io_uring_cqe *cqe, msghdr *data) noexcept;

  private:
    int register_socket() noexcept;

    int register_ring() noexcept;

    int register_rcvmsg_buffer_ring() noexcept;

    unsigned char *get_buffer(const int index) const;

    void recycle_buffer(const int index) const;

    uint8_t event_type(msghdr *user_data);

  private:
    static io_uring ring;

    io_uring_buf_ring *buf_ring = nullptr;

    unsigned char *buffer_base = nullptr;

    io_uring_cqe *cqes[CQES]{};

    msgctr ctrl{};

    msghdr msg{};

    iovec iov{};

    __kernel_timespec timespec = {0, 1000000};

    scheduler_t scheduler;

    timerwheel timers;

    int eventfd = -1;

    static int socket;

    int res;
};

}; // namespace faim
