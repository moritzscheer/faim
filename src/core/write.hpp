// Copyright(C) 2025, Moritz Scheer

#pragma once

#include <liburing.h>
#include <liburing/io_uring.h>

#include "../utils/queue.hpp"
#include "../utils/types.hpp"
#include "read.hpp"

namespace faim
{
namespace networking
{
namespace write
{

/* -------------------------------------------- MACRO DECLARATIONS -------------------------------------------------- */

#define BUFFERS 256

#define N_BITMAP BUFFERS / 64

#define BUFFER_SHIFT 12 // 4KB

#define BUFFER_SIZE (1U << BUFFER_SHIFT)

#define BUFFER_RING_SIZE (sizeof(struct buf_ring_t) + (BUFFERS * BUFFER_SIZE))

#define ECN CMSG_SPACE(sizeof(uint8_t))

#define META_DATA_LEN sizeof(msghdr_t) + ECN

struct buf_ring_t
{
    uint64_t bitmap[N_BITMAP];
    uint8_t *base;
    iovec reg;
    uint8_t head = 0;
    uint8_t num = 0;
};

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
static msghdr_t *pending[SQES];

//
//
//
static std::atomic<int> batch_count = 0;

//
//
//
static int res;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

//
//
//
int setup(buf_ring_t **buf_ring_r, io_uring *ring_r) noexcept;

//
//
//
void cleanup(buf_ring_t *buf_ring) noexcept;

//
//
//
msghdr_t *buffer(size_t payload_len, uint8_t ecn = 0) noexcept;

//
//
//
msghdr_t *buffer(buf_ring_t *ring, uint8_t *&dest, size_t &destlen, uint8_t ecn) noexcept;

//
//
//
int resize(buf_ring_t *ring, msghdr_t *msg) noexcept;

//
//
//
void release(buf_ring_t *ring, msghdr_t *msg) noexcept;

//
//
//
int prepare(msghdr_t *data) noexcept;

//
//
//
int flush() noexcept;

//
//
//
int validate(io_uring_cqe *cqe, msghdr *data) noexcept;

/* ------------------------------------------------------------------------------------------------------------------ */

}; // namespace write
}; // namespace networking
}; // namespace faim
