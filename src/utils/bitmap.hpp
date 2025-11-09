// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#define BITS 256
#define WORDS 4

namespace bitmap
{

inline int construct(uint64_t **bits)
{
    *bits = (uint64_t *)calloc(WORDS, sizeof(uint64_t));
    if (!bits)
    {
        return -ENOMEM;
    }

    return 0;
}

inline void destruct(uint64_t *bits)
{
    if (bits)
    {
        free(bits);
    }
}

inline int claim(uint64_t *bits, size_t n)
{
    if (n == 0 || n > BITS)
    {
        return -1;
    }

    for (size_t w = 0; w < WORDS; ++w)
    {
        uint64_t free_mask = ~bits[w];

        if (!free_mask)
        {
            continue;
        }

        if (n == 1)
        {
            int bit = __builtin_ctzll(free_mask);
            bits[w] |= (1ULL << bit);
            return int(w * 64 + bit);
        }

        for (int b = 0; b <= 64 - int(n); ++b)
        {
            uint64_t mask = ((1ULL << n) - 1) << b;

            if ((bits[w] & mask) == 0)
            {
                bits[w] |= mask;
                return int(w * 64 + b);
            }
        }
    }

    return -1;
}

inline void release(uint64_t *bits, size_t start_bit, size_t n)
{
    if (start_bit + n <= BITS)
    {
        return;
    }

    while (n > 0)
    {
        size_t w = start_bit / 64;
        size_t b = start_bit % 64;
        size_t cnt = (n < 64 - b) ? n : 64 - b;
        uint64_t mask = ((1ULL << cnt) - 1) << b;
        bits[w] &= ~mask;

        start_bit += cnt;
        n -= cnt;
    }
}

} // namespace bitmap
