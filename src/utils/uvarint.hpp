// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>

namespace faim
{
namespace networking
{

inline uint64_t ntohll(uint64_t netlong64)
{
    return ((netlong64 & 0xFF00000000000000ULL) >> 56) | ((netlong64 & 0x00FF000000000000ULL) >> 40) |
           ((netlong64 & 0x0000FF0000000000ULL) >> 24) | ((netlong64 & 0x000000FF00000000ULL) >> 8) |
           ((netlong64 & 0x00000000FF000000ULL) << 8) | ((netlong64 & 0x0000000000FF0000ULL) << 24) |
           ((netlong64 & 0x000000000000FF00ULL) << 40) | ((netlong64 & 0x00000000000000FFULL) << 56);
}

struct uvarint_t
{
    union uvarint
    {
        uint8_t n8;

        uint16_t n16;

        uint32_t n32;

        uint64_t n64;
    } v{};

    size_t len;

    uvarint_t() = default;

    uvarint_t(const uint8_t *start)
    {
        len = (size_t)(1u << (*start >> 6));

        switch (len)
        {
        case 1:
            memcpy(&v, start, 1);
            break;
        case 2:
            memcpy(&v, start, 2);
            v.n8 &= 0x3f;
            v.n16 = ntohs(v.n16);
            break;
        case 4:
            memcpy(&v, start, 4);
            v.n8 &= 0x3f;
            v.n32 = ntohl(v.n32);
            break;
        case 8:
            memcpy(&v, start, 8);
            v.n8 &= 0x3f;
            v.n64 = ntohll(v.n64);
            break;
        }
    }

    static size_t length(const uint8_t *start)
    {
        return (size_t)(1u << (*start >> 6));
    }

    operator uint64_t() const noexcept
    {
        return v.n64;
    }

    bool operator==(int64_t comp) const noexcept
    {
        return v.n64 == comp;
    }
};

}; // namespace networking
}; // namespace faim
