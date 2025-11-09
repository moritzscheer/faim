// Copyright(C) 2025, Moritz Scheer

#pragma once

#include <csignal>
#include <pthread.h>

#include "../utils/types.hpp"
#include "signal.hpp"
#include "write.hpp"

namespace faim
{
namespace networking
{
namespace signal
{

int setup() noexcept
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));

    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &act.sa_mask, NULL);

    act.sa_sigaction = handle_submission;
    act.sa_flags = SA_SIGINFO;

    sigaction(SIGUSR1, &act, NULL);

    return 0;
}

int submit(pthread_t target, void *data) noexcept
{
    sigval_t val;
    val.sival_ptr = data;

    res = pthread_sigqueue(main_thread, SIGUSR1, val);

    return res;
}

void handle_submission(int signo, siginfo_t *info, void *context)
{
    msghdr_t *msg = (msghdr_t *)info->si_value.sival_ptr;

    int flushed = write::pending.flush(write::prepare);

    if (flushed > 0)
    {
        res = io_uring_submit(&ring);
        if (res < 0)
        {
            return cleanup(res);
        }
    }

    if (write::pending.empty())
    {
    }

    int res = write::prepare(msg);
    if (res != 0)
    {
        write::pending.push(msg);
    }
}

}; // namespace signal
}; // namespace networking
}; // namespace faim
