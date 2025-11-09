// Copyright(C) 2025, Moritz Scheer

#pragma once

#include <liburing.h>
#include <liburing/io_uring.h>
#include <sys/socket.h>

namespace faim
{
namespace networking
{
namespace async
{

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

//
//
//
extern io_uring *ring;

//
//
//
static std::atomic<uint64_t> batch_count = 0;

//
//
//
static int asyncfd;

//
//
//
static int res;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

//
//
//
int setup(io_uring *ring_r) noexcept;

//
//
//
void cleanup() noexcept;

//
//
//
int prepare(uint64_t num = 1) noexcept;

//
//
//
int validate(io_uring_cqe *cqe) noexcept;

/* ------------------------------------------------------------------------------------------------------------------ */

}; // namespace async
}; // namespace networking
}; // namespace faim
