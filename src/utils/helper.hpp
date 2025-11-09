// Copyright (C) 2025, Moritz Scheer

#pragma once

#define IPTOS_ECN_MASK 0x03

#include <cstdint>
#include <cstring>
#include <liburing.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>

#include "types.hpp"

namespace faim
{
namespace networking
{

inline uint64_t get_timestamp_ns()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    {
        return UINT64_MAX;
    }

    return ts.tv_sec * (uint64_t)NGTCP2_SECONDS + ts.tv_nsec;
}

inline ngtcp2_pkt_info io_uring_get_ecn(io_uring_recvmsg_out *msg_out, struct msghdr *msgh, int family)
{
    struct cmsghdr *cmsg;

    // Iterate through control messages
    for (cmsg = io_uring_recvmsg_cmsg_firsthdr(msg_out, msgh); cmsg;
         cmsg = io_uring_recvmsg_cmsg_nexthdr(msg_out, msgh, cmsg))
    {
        if (family == AF_INET && cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS && cmsg->cmsg_len)
        {
            uint8_t ecn = *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg)) & IPTOS_ECN_MASK;
            return ngtcp2_pkt_info{ecn};
        }
        else if (family == AF_INET6 && cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS &&
                 cmsg->cmsg_len)
        {
            unsigned int tos;
            memcpy(&tos, CMSG_DATA(cmsg), sizeof(int));
            uint8_t ecn = tos & IPTOS_ECN_MASK;
            return ngtcp2_pkt_info{ecn};
        }
    }

    return ngtcp2_pkt_info{NGTCP2_ECN_NOT_ECT};
}

template <typename node, typename id> node find(node head, id target)
{
    while (head)
    {
        if (head->id == target)
        {
            return head;
        }
        head = head->next;
    }

    return nullptr;
}

inline extern ngtcp2_path ngtcp2_path_create(sockaddr_storage *addr, socklen_t addrlen)
{
    ngtcp2_path path;

    switch (addrlen)
    {
    case AF_INET:
    {
        path.local = {
            .addr = const_cast<sockaddr *>(&local.ipv4.addr.a),
            .addrlen = local.ipv4.addrlen,
        };
    }
    case AF_INET6:
    {
        path.local = {
            .addr = const_cast<sockaddr *>(&local.ipv6.addr.a),
            .addrlen = local.ipv6.addrlen,
        };
    }
    case AF_UNIX:
    {
    }
        path.local = {
            .addr = const_cast<sockaddr *>(&local.un.addr.a),
            .addrlen = local.un.addrlen,
        };
    }

    path.remote = {
        .addr = reinterpret_cast<sockaddr *>(addr),
        .addrlen = addrlen,
    };

    return path;
}

}; // namespace networking
}; // namespace faim
