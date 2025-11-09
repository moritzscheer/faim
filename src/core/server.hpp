// Copyright(C) 2025, Moritz Scheer

#pragma once

#include <liburing.h>
#include <ngtcp2/ngtcp2.h>

#include "read.hpp"

namespace faim
{

using namespace networking;

class server
{
  public:
    server();

    int setup(int argc, char *argv[]) noexcept;

    int run(void) noexcept;

    int cleanup(int err) noexcept;

  private:
    int register_socket() noexcept;

    int register_ring() noexcept;

    void handle_submission(int signo, siginfo_t *info, void *context);

    io_uring ring;

    io_uring_cqe *cqes[CQES]{};

    __kernel_timespec timespec = {0, 1000000};

    int socket;

    int res;
};

}; // namespace faim
