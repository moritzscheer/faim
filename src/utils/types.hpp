// Copyright (C) 2025, Moritz Scheer

#pragma once

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

/* -------------------------------------------- MACRO DECLARATIONS -------------------------------------------------- */

/* Event types macros */

#define READ 1

#define READ_SUCCESSFUL 0

#define WRITE 2

#define WRITE_SUCCESSFUL 0

#define EVENT 3

#define TIMER 4

/* Action specific macros */

#define STREAM_DONE 1

#define RESPOND -1

#define DROP -2

#define MAX_TRIES 3

#define BACKLOG 128

#define PORT 8060

#define ALLOW_IPV4 0 // [0 = yes | 1 = no]

#define CONTROLLEN 0

/* ------------------------------------------- STRUCT DECLARATIONS -------------------------------------------------- */

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

struct msghdr_t : msghdr
{
    iovec iov;

    uint16_t total_bytes;
    uint16_t bytes_send;
    uint8_t ring_num;
    uint8_t num_buf;
    uint8_t start_buf;
    uint8_t tries;

    msghdr_t *next;
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

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

struct connection;

typedef uint64_t timestamp_t;

/* ------------------------------------------------------------------------------------------------------------------ */

}; // namespace networking
}; // namespace faim
