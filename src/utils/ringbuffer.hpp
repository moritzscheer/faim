// Copyright (C) 2025, Moritz Scheer

#pragma once

#include "../middleware/connection.hpp"
#include "../middleware/quic/encoder.hpp"
#include "../middleware/stream.hpp"
#include <cerrno>
#include <cstdlib>
#include <string.h>

using namespace faim::networking;

class ringbuf_t
{
    stream_t **base = nullptr;

    size_t head = 0;

    size_t tail = 0;

    size_t size = 8;

    size_t num_items = 0;

  public:
    int construct()
    {
        base = (stream_t **)calloc(size, sizeof(stream_t *));
        if (!base)
        {
            return -errno;
        }

        return 0;
    }

    operator bool()
    {
        return num_items <= 0;
    }

    int push(stream_t *item)
    {
        size_t next = ((head + 1) & (size - 1));

        if (next == tail)
        {
            size_t new_size = size * 2;

            stream_t **tmp = (stream_t **)realloc(base, sizeof(stream_t *) * new_size);
            if (!tmp)
            {
                return -errno;
            }

            base = tmp;
            size = new_size;
            next = (head + 1) & (size - 1);
        }

        num_items++;
        base[head] = item;
        head = next;
        return 0;
    }

    ssize_t flush_and_process(connection *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen,
                              size_t max_pkt_size, uint64_t ts)
    {
        if (head == tail)
        {
            return 0;
        }

        size_t read = tail;
        size_t write = 0;

        stream_t **tmp = (stream_t **)malloc(sizeof(stream_t *) * size);

        if (tmp)
        {
            while (read != head)
            {
                stream_t *item = base[read];

                auto res = quic::write_pkt(conn, item, path, pi, data, datalen, max_pkt_size, ts);
                if (res < 0)
                {
                    return res;
                }

                tmp[write++] = item;
                read = (read + 1) & (size - 1);
            }

            memcpy(base, tmp, write * sizeof(stream_t *));
            free(tmp);
        }
        else
        {
            while (read != head)
            {
                stream_t *item = base[read];

                auto res = quic::write_pkt(conn, item, path, pi, data, datalen, max_pkt_size, ts);
                if (res < 0)
                {
                    return res;
                }

                if (read != write)
                {
                    base[write] = item;
                }

                read = (read + 1) & (size - 1);
                write++;
            }
        }

        tail = 0;
        head = write;

        if (write < size / 2 && size > 8)
        {
            size_t new_size = size / 2;
            stream_t **resized = (stream_t **)realloc(base, sizeof(stream_t *) * new_size);
            if (resized)
            {
                base = resized;
                size = new_size;
            }
        }
    }

    void destruct()
    {
        if (base)
        {
            free(base);
        }
    }
};
