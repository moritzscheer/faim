// Copyright (C) 2024 Moritz Scheer

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>

#include "../utils/types.hpp"
#include "buffer.hpp"
#include "server.hpp"

namespace faim
{
namespace networking
{

#define BASE_SIZE sizeof(msghdr) + sizeof(msgctr)

int buffer(uint8_t *data, size_t datalen, size_t gso)
{
    size_t len = sizeof(msghdr) + sizeof(iovec) + sizeof(cmsghdr) + sizeof(sockaddr_storage);

    uint8_t *mem = (uint8_t *)malloc(len);
    if (!mem)
    {
        return -errno;
    }

    msghdr *msg = (msghdr *)mem;
    iovec *iov = (iovec *)(mem + sizeof(msghdr));
    cmsghdr *cmsg = (cmsghdr *)(mem + sizeof(msghdr) + sizeof(iovec));
    sockaddr_storage *name = (sockaddr_storage *)(mem + sizeof(msghdr) + sizeof(iovec) + sizeof(cmsghdr));

    *iov = (iovec){
        .iov_base = data,
        .iov_len = datalen,
    };

    *msg = (msghdr){
        .msg_name = name,
        .msg_iov = iov,
        .msg_iovlen = 1,
    };

    *cmsg = (cmsghdr){};

    return server::prepare_write(msg);
}

msghdr *buffer(uint8_t *data, size_t datalen, size_t gso)
{
    size_t len = sizeof(msghdr) + sizeof(iovec) + sizeof(cmsghdr);

    uint8_t *mem = (uint8_t *)malloc(len);
    if (!mem)
    {
        return NULL;
    }

    msghdr *msg = (msghdr *)mem;
    iovec *iov = (iovec *)(mem + sizeof(msghdr));
    uint8_t *payload = mem + sizeof(msghdr) + sizeof(iovec);
    void *name = (void *)(mem + sizeof(msghdr) + sizeof(iovec) + payload_len);

    *iov = (iovec){
        .iov_base = payload,
        .iov_len = payload_len,
    };

    *msg = (msghdr){
        .msg_name = name,
        .msg_iov = iov,
        .msg_iovlen = 1,
    };

    return msg;
}

msghdr *buffer(size_t payload_len)
{
    size_t len = sizeof(msghdr) + sizeof(iovec) + payload_len;

    uint8_t *mem = (uint8_t *)malloc(len);
    if (!mem)
    {
        return NULL;
    }

    msghdr *msg = (msghdr *)mem;
    iovec *iov = (iovec *)(mem + sizeof(msghdr));
    uint8_t *payload = mem + sizeof(msghdr) + sizeof(iovec);
    void *name = (void *)(mem + sizeof(msghdr) + sizeof(iovec) + payload_len);

    *iov = (iovec){
        .iov_base = payload,
        .iov_len = payload_len,
    };

    *msg = (msghdr){
        .msg_name = name,
        .msg_iov = iov,
        .msg_iovlen = 1,
    };

    return msg;
}

msghdr *buffer(size_t payload_len, socklen_t addrlen, void *addr)
{
    size_t len = sizeof(msghdr) + sizeof(iovec) + payload_len + addrlen;

    uint8_t *mem = (uint8_t *)malloc(len);
    if (!mem)
    {
        return NULL;
    }

    msghdr *msg = (msghdr *)mem;
    iovec *iov = (iovec *)(mem + sizeof(msghdr));
    uint8_t *payload = mem + sizeof(msghdr) + sizeof(iovec);
    void *name = (void *)(mem + sizeof(msghdr) + sizeof(iovec) + payload_len);

    *iov = (iovec){
        .iov_base = payload,
        .iov_len = payload_len,
    };

    *msg = (msghdr){
        .msg_name = name,
        .msg_namelen = addrlen,
        .msg_iov = iov,
        .msg_iovlen = 1,
    };

    if (addr)
    {
        memcpy(name, addr, addrlen);
    }

    return msg;
}

msghdr *buffer1(size_t payload_len, uint8_t *pkt, socklen_t addrlen, void *addr)
{
    size_t len = sizeof(msghdr) + sizeof(iovec) + payload_len + addrlen;

    uint8_t *mem = (uint8_t *)malloc(len);
    if (!mem)
    {
        return NULL;
    }

    msghdr *msg = (msghdr *)mem;
    iovec *iov = (iovec *)(mem + sizeof(msghdr));
    uint8_t *payload = mem + sizeof(msghdr) + sizeof(iovec);
    void *name = (void *)(mem + sizeof(msghdr) + sizeof(iovec) + payload_len);

    *iov = (iovec){
        .iov_base = payload,
        .iov_len = payload_len,
    };

    *msg = (msghdr){
        .msg_name = name,
        .msg_namelen = addrlen,
        .msg_iov = iov,
        .msg_iovlen = 1,
    };

    if (addr)
    {
        memcpy(name, addr, addrlen);
    }

    if (pkt)
    {
        memcpy(payload, pkt, payload_len);
    }

    return msg;
}

size_t calc_total_len(size_t datalen, socklen_t addrlen)
{
    size_t num_iovs = 1;
    size_t offset = datalen;

    while (offset > NGTCP2_MAX_UDP_PAYLOAD_SIZE)
    {
        offset -= NGTCP2_MAX_UDP_PAYLOAD_SIZE;
        num_iovs++;
    }

    return sizeof(msghdr) + sizeof(msgctr) + num_iovs * sizeof(iovec) + datalen + addrlen;
}

msghdr *buffer(uint8_t *pkt, size_t payload_len, void *addr, socklen_t addrlen)
{
    size_t num_iovs = calc_total_len(payload_len, addrlen);
    size_t len = sizeof(msghdr) + sizeof(msgctr) + num_iovs * sizeof(iovec) + +addrlen;

    uint8_t *mem = reinterpret_cast<uint8_t *>(malloc(len));
    if (!mem)
    {
        return NULL;
    }

    iovec *iovs = reinterpret_cast<iovec *>(mem + sizeof(msghdr));
    uint8_t *payload = mem + BASE_SIZE;

    uint8_t *base;
    for (int i = 0; i < num_iovs; i++)
    {
        ;

        iovs[i] = (iovec){
            .iov_base = base,
            .iov_len = payload_len,
        };
    }

    msghdr *msg = reinterpret_cast<msghdr *>(mem);
    uint8_t *name = mem + BASE_SIZE + num_iovs * sizeof(iovec) + payload_len;

    *msg = (msghdr){
        .msg_name = name,
        .msg_namelen = addrlen,
        .msg_iov = iovs,
        .msg_iovlen = 1,
    };

    if (addr)
    {
        memcpy(name, addr, addrlen);
    }

    if (pkt)
    {
        memcpy(payload, pkt, payload_len);
    }

    return msg;
}

}; // namespace networking
}; // namespace faim
