// Copyright (C) 2025, Moritz Scheer

#include <cstdint>
#include <liburing/io_uring.h>
#include <malloc.h>
#include <ngtcp2/ngtcp2.h>

#include <cstdint>
#include <sys/socket.h>

#include "timer.hpp"
#include "worker.hpp"

namespace faim
{
namespace networking
{
namespace timer
{

int setup(io_uring *ring_r) noexcept
{
    base = (bucket_t *)malloc(BASE_MEMORY_SIZE);
    if (!base)
    {
        return -errno;
    }

    // Level 0: 5 ms ticks, 256 buckets
    levels[0].interval = 5;
    levels[0].num_buckets = 256;
    levels[0].cursor = 0;
    levels[0].buckets = base;

    // Level 1: 50 ms ticks, 64 buckets
    levels[1].interval = 50;
    levels[1].num_buckets = 64;
    levels[1].cursor = 0;
    levels[1].buckets = base + LEVEL_0_BUCKETS;

    // Level 2: 500 ms ticks, 64 buckets
    levels[2].interval = 1000;
    levels[2].num_buckets = 64;
    levels[2].cursor = 0;
    levels[2].buckets = base + LEVEL_0_BUCKETS + LEVEL_1_BUCKETS;

    // Level 3: 60000 ms ticks, 32 buckets
    levels[3].interval = 1000;
    levels[3].num_buckets = 64;
    levels[3].cursor = 0;
    levels[3].buckets = base + LEVEL_0_BUCKETS + LEVEL_1_BUCKETS + LEVEL_2_BUCKETS;

    current_tick = 0;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring_r);
    if (!sqe)
    {
        return -1;
    }

    int flags = IORING_TIMEOUT_MULTISHOT;

    io_uring_prep_timeout(sqe, &timespec, 0, flags);

    sqe->flags |= IOSQE_ASYNC;

    io_uring_sqe_set_data(sqe, (void *)TIMER);

    return 0;
}

void cleanup() noexcept
{
    int i = 0;

    bucket_t *bucket;

    timer_t *current;
    timer_t *tmp;

    while (i < BASE_MEMORY_SIZE)
    {
        bucket = &base[i];
        current = bucket->head;

        while (current)
        {
            tmp = current->next;

            if (current->cancelled)
            {
                free(current);
            }

            int res = worker::enqueue_write((connection *)current->conn, current->expiry);
            if (res != 0)
            {
                free(current);
            }

            current = tmp;
        }

        i++;
    }

    if (base)
    {
        free(base);
    }
}

timer_t *add(uint64_t timeout, void *conn) noexcept
{
    timer_t *timer = (timer_t *)calloc(1, sizeof(timer_t));
    if (!timer)
    {
        return NULL;
    }

    uint64_t ticks = timeout / levels[0].interval;
    if (ticks == 0)
    {
        ticks = 1;
    }

    uint64_t expiry = current_tick + ticks;

    timer->cancelled = false;
    timer->expiry = expiry;
    timer->conn = conn;

    int i = 0;

    uint64_t delta = expiry - current_tick;

    while (i < NUM_LEVELS)
    {
        if (delta < levels[i].num_buckets)
        {
            break;
        }

        delta /= levels[i].num_buckets;

        ++i;
    }

    ++num_timers;

    insert_timer(timer, i);

    return timer;
}

void cancel(timer_t *timer)
{
    if (timer)
    {
        timer->cancelled = true;
    }

    timer = nullptr;
}

int handle_timeouts() noexcept
{
    if (num_timers == 0)
    {
        return 0;
    }

    int i = 0;
    int res = 0;

    level_t *level;

    timer_t *prev = NULL;
    timer_t *current = levels[i].buckets[level->cursor].head;
    timer_t *next;

    msghdr *msg;

    while (i < NUM_LEVELS)
    {
        level = &levels[i];

        prev = NULL;
        current = level->buckets[level->cursor].head;

        while (current)
        {
            next = current->next;

            if (current->expiry <= current_tick)
            {
                res = worker::enqueue_write((connection *)current->conn, current->expiry);
                if (res != 0)
                {
                    return res;
                }

                if (res != 0)
                {
                    return res;
                }

                if (prev)
                {
                    prev->next = next;
                }
                else
                {
                    current = next;
                }

                free(current);

                --num_timers;
            }
            else if (i + 1 < NUM_LEVELS)
            {
                insert_timer(current, i + 1);
                if (prev)
                {
                    prev->next = next;
                }
                else
                {
                    level->buckets[level->cursor].head = next;
                }
            }
            else
            {
                prev = current;
            }

            current = next;
        }

        level->cursor = (level->cursor + 1) % level->num_buckets;

        if (level->cursor != 0)
        {
            break;
        }

        ++i;
    }

    ++current_tick;

    return 0;
}

static void insert_timer(timer_t *timer, uint8_t level_index) noexcept
{
    level_t &level = levels[level_index];
    uint16_t index = (timer->expiry / (level.interval) % level.num_buckets);
    timer->next = level.buckets[index].head;
    level.buckets[index].head = timer;
}

}; // namespace timer
}; // namespace networking
}; // namespace faim
