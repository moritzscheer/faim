// Copyright (C) 2025, Moritz Scheer

#pragma once

#include "helper.hpp"
#include <cstdint>
#include <cstring>
#include <liburing.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>

namespace faim
{
namespace networking
{

/* Event types macros */
#define READ 0
#define EVENT 1
#define WRITE 2
#define TIMER 3

/* Action specific macros */
#define STREAM_DONE 1
#define RESPOND -1
#define DROP -2
#define MAX_TRIES 3

#define BACKLOG 128
#define PORT 8060
#define ALLOW_IPV4 0 // [0 = yes | 1 = no]

#define CONTROLLEN 0

#define SQES 64
#define CQES (SQES * 16)
#define BUFFERS CQES
#define BUFFER_SHIFT 12 // 4KB
#define BUFFER_SIZE (1U << BUFFER_SHIFT)
#define BUFFER_RING_SIZE ((sizeof(struct io_uring_buf) + BUFFER_SIZE) * BUFFERS)

#define READ_SUCCESSFUL 0
#define WRITE_SUCCESSFUL 0

inline ngtcp2_ccerr app_error;

struct connection;

typedef uint64_t timestamp_t;

union sockaddr_u
{
    sockaddr_storage s;
    sockaddr_in in;
    sockaddr_in6 in6;
    sockaddr a;
};

struct ipv4_address
{
    sockaddr_u addr;
    socklen_t addrlen = AF_INET;
};

struct ipv6_address
{
    sockaddr_u addr;
    socklen_t addrlen = AF_INET6;
};

struct unix_address
{
    sockaddr_u addr;
    socklen_t addrlen = AF_UNIX;
};

inline struct local
{
    ipv4_address ipv4;
    ipv6_address ipv6;
    unix_address un;

} local;

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
    bool operator==(uint64_t comp) const noexcept
    {
        return v.n64 == comp;
    }
};

struct quic_hd
{
    ngtcp2_cid dcid;

    ngtcp2_cid scid;

    ngtcp2_cid odcid;

    uint32_t version;

    uvarint_t token;

    ngtcp2_token_type token_type;
};

struct msgctr
{
    uint8_t type;

    uint8_t tries;

    ssize_t bytes_send;

    ssize_t total_bytes;
};

struct quic_dc
{
    connection *conn;
    ngtcp2_path path;
    uint8_t *pkt;
    size_t pktlen;
    ngtcp2_pkt_info pi;
    uint64_t timestamp;
};

struct error
{
    uint64_t code;
    const uint8_t *reason;
    size_t reason_len;

    error(int err_code, const char *r) : code(err_code), reason((uint8_t *)r), reason_len(std::strlen(r))
    {
    }
};

}; // namespace networking
}; // namespace faim
