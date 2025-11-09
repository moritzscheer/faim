// Copyright(C) 2025, Moritz Scheer

#pragma once

#include <pthread.h>
#include <signal.h>

namespace faim
{
namespace networking
{
namespace signal
{

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

extern pthread_t main_thread;

static int res;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

int setup() noexcept;

int submit(pthread_t target, void *data) noexcept;

void handle_submission(int signo, siginfo_t *info, void *context);

/* ------------------------------------------------------------------------------------------------------------------ */

}; // namespace signal
}; // namespace networking
}; // namespace faim
