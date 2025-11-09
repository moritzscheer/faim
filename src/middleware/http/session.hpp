// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <nghttp3/nghttp3.h>

#include "../connection.hpp"

namespace faim
{
namespace networking
{
namespace http
{

static inline nghttp3_settings *default_settings;

int setup();

void cleanup();

int session_new(connection *c);

void session_del();

int session_new();

extern nghttp3_callbacks callbacks;

}; // namespace http
}; // namespace networking
}; // namespace faim
