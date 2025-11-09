// Copyright(C) 2025, Moritz Scheer

#pragma once

#include <liburing.h>
#include <liburing/io_uring.h>

#include "../utils/types.hpp"

namespace faim
{
namespace networking
{
namespace read
{

/* -------------------------------------------- MACRO DECLARATIONS -------------------------------------------------- */

#define SQES 64

#define CQES (SQES * 16)

#define BUFFERS CQES

#define BUFFER_SHIFT 12 // 4KB

#define BUFFER_SIZE (1U << BUFFER_SHIFT)

#define BUFFER_RING_SIZE ((sizeof(struct io_uring_buf) + BUFFER_SIZE) * BUFFERS)

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

//
//
//
extern int *socket;

//
//
//
extern io_uring *ring;

//
//
//
static io_uring_buf_reg reg;

//
//
//
static io_uring_buf_ring *buf_ring;

//
//
//
static unsigned char *buffer_base = nullptr;

//
//
//
static msghdr_t *msg;

//
//
//
static int res;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

//
//
//
int setup(io_uring *ring_r, int *socket_r) noexcept;

//
//
//
void cleanup() noexcept;

//
//
//
void prepare() noexcept;

//
//
//
int validate(io_uring_cqe *cqe) noexcept;

//
//
//
static int validate(io_uring_recvmsg_out *msgout) noexcept;

//
//
//
static unsigned char *get_buffer(int i) noexcept;

/* ------------------------------------------------------------------------------------------------------------------ */

}; // namespace read
}; // namespace networking
}; // namespace faim
