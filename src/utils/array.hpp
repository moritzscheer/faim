// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <string.h>

template <typename t> class array_t
{
    t *base = nullptr;

    uint16_t size = 0;

    uint16_t count = 0;

  public:
    array_t<t> *construct(uint16_t initial_size)
    {
        base = reinterpret_cast<t>(calloc(sizeof(t), initial_size));
        if (!base)
        {
            return NULL;
        }

        size = initial_size;
        count = 0;

        return this;
    }

    int add(t item)
    {
        if (count >= size)
        {
            uint16_t new_size = size * 2;

            t *tmp = reinterpret_cast<t *>(realloc(base, sizeof(t) * new_size));
            if (!tmp)
            {
                return -errno;
            }

            base = tmp;
            size = new_size;
        }
        base[count++] = item;
        return true;
    }

    void remove(t item)
    {
        uint16_t idx = 0;

        while (idx < count)
        {
            if (base[idx] == item)
            {
                break;
            }
            idx++;
        }
        if (idx == count)
            return -1; // not found

        // shift remaining elements down
        for (uint16_t i = idx; i < count - 1; ++i)
        {
            base[i] = base[i + 1];
        }
        --count;
        return 0; // success
    }

    void destruct()
    {
        if (base)
        {
            free(base);
        }
    }
};
