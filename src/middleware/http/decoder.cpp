// Copyright (C) 2024 Moritz Scheer

#include "decoder.hpp"
#include "../stream.hpp"

namespace faim
{
namespace networking
{
namespace http
{

int start_response(rstream *stream, nghttp3_conn *conn)
{
    if (stream->uri.empty() || stream->method.empty())
    {
    }
    return 0;
}

}; // namespace http
}; // namespace networking
}; // namespace faim
