// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstdint>
#include <functional>
#include <sys/socket.h>

namespace faim
{
namespace networking
{

#define QUIC_TIMEOUT 1
#define WEBTRANSPORT_TIMEOUT 2

#define LEVEL_0_BUCKETS 256
#define LEVEL_1_BUCKETS 128
#define LEVEL_2_BUCKETS 64
#define LEVEL_3_BUCKETS 32

#define NUM_LEVELS 4

#define BASE_MEMORY_SIZE sizeof(bucket_t) * (LEVEL_0_BUCKETS + LEVEL_1_BUCKETS + LEVEL_2_BUCKETS + LEVEL_3_BUCKETS)

struct timer_t
{
    uint64_t expiry;
    void *conn;
    bool cancelled = false;
    timer_t *next;
};

struct bucket_t
{
    timer_t *head;
};

struct level_t
{
    bucket_t *buckets;
    uint32_t num_buckets;
    uint64_t interval;
    uint32_t cursor = 0;
};

class timerwheel
{
  public:
    timerwheel();

    int setup(int &error) noexcept;

    void cleanup() noexcept;

    static timer_t *add_timer(uint64_t timeout, void *conn) noexcept;

    static int handle_timeouts() noexcept;

  private:
    static void insert_timer(timer_t *timer, uint8_t level_index) noexcept;

    static std::function<int(msghdr *)> write_pkt;

    static level_t levels[NUM_LEVELS];

    static uint64_t current_tick;

    static bucket_t *base;

    static uint64_t num_timers;
};

}; // namespace networking
}; // namespace faim
