// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <functional>
#include <thread>

#include "../utils/types.hpp"

namespace faim
{
namespace networking
{

struct routine_data
{
    uint8_t type;
    connection *conn;
    uint8_t *pkt;
    size_t pktlen;
    ngtcp2_path path;
    uint64_t timestamp;
};

class scheduler_t
{
  public:
    scheduler_t();

    int setup(int &error) noexcept;

    int cleanup() noexcept;

    int create_decoding_routine(connection *conn, uint8_t *pkt, size_t pktlen, ngtcp2_path path, uint64_t ts) noexcept;

    int create_encoding_routine(routine_data *t) noexcept;

  private:
    int dequeue_routine(uint8_t &type, connection *&conn, uint8_t *&pkt, size_t &pktlen, ngtcp2_path &path,
                        uint64_t &ts) noexcept;

    void worker_function(std::function<int(msghdr *)> write_task) noexcept;

    void app_error(int res) noexcept;

    int critical_error(ngtcp2_ccerr *err) noexcept;

    uint8_t num_threads;

    int &app_error_r;

    std::thread *threads;
};

}; // namespace networking
}; // namespace faim
