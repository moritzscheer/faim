// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/socket.h>

namespace faim
{
namespace networking
{

int buffer(uint8_t *data, size_t datalen, size_t gso);
msghdr *buffer(uint8_t *data, size_t datalen, size_t gso);
msghdr *buffer(size_t payload_len);
msghdr *buffer(size_t payload_len, socklen_t addrlen, void *addr);
msghdr *buffer(size_t payload_len, uint8_t *pkt, socklen_t addrlen, void *addr);

} // namespace networking
} // namespace faim
