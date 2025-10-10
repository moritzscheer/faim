// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cstddef>

#include "../stream.hpp"

namespace faim
{
namespace networking
{

ssize_t ngwebtr_conn_writev_stream(stream_t *stream, int *pfin, iovec *vec, size_t veccnt);

} // namespace networking
} // namespace faim
