// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <liburing.h>
#include <ngtcp2/ngtcp2.h>

#include "../middleware/connection.hpp"
#include "write.hpp"

namespace faim
{
namespace networking
{
namespace worker
{

/* -------------------------------------------- MACRO DECLARATIONS -------------------------------------------------- */

#define READ_SUCCESSFUL 0

#define WRITE_SUCCESSFUL 0

/* ------------------------------------------- STRUCT DECLARATIONS -------------------------------------------------- */

struct routine_data
{
    uint8_t type;
    connection *conn;
    uint8_t *pkt;
    size_t pktlen;
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
    uint64_t timestamp;
};

struct worker_t
{
    int *app_err;
    pthread_t thread;
    write::buf_ring_t *ring;
    queue<msghdr_t> pending;
};

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

//
//
//
extern worker_t *workers;

//
//
//
extern pthread_t main_thread;

//
//
//
static uint32_t num_threads;

//
//
//
static int res;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

//
//
//
int setup(io_uring *ring_r, int *err_r) noexcept;

//
//
//
void cleanup() noexcept;

//
//
//
int enqueue_read(connection *&conn, uint8_t *pkt, size_t pktlen, ngtcp2_path path, ngtcp2_pkt_info pi, uint64_t ts);

//
//
//
int enqueue_write(connection *conn, uint64_t ts);

//
//
//
static int dequeue_routine(uint8_t &type, connection *&conn, ngtcp2_path &path, ngtcp2_pkt_info &pi, uint8_t *&pkt,
                           size_t &pktlen, uint64_t &ts);

//
//
//
static void *worker_function(void *args) noexcept;

//
//
//
static void *app_error(int res) noexcept;

//
//
//
static int critical_error(ngtcp2_ccerr *err) noexcept;

/* ------------------------------------------------------------------------------------------------------------------ */

}; // namespace worker
}; // namespace networking
}; // namespace faim
