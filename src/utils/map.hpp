// Copyright (C) 2025, Moritz Scheer

#pragma once

#include "../../includes/uthash.h"
#include <functional>
#include <string.h>

template <typename k, typename v> class hashmap
{
    UT_hash_handle hh;

    v head;

  public:
    v find(k key)
    {
        v item;
        HASH_FIND(hh, head, &key, sizeof(k), item);
        return item;
    }

    v create(k key)
    {
        v item = reinterpret_cast<v>(calloc(sizeof(k), 1));
        if (!item)
        {
            return NULL;
        }

        memcpy(&item->id, &key, sizeof(k));

        HASH_ADD(hh, head, key, sizeof(k), item);
        return item;
    }

    void add(k key, v value)
    {
        memcpy(value->id, &key, sizeof(k));

        HASH_ADD(hh, head, key, sizeof(k), value);
    }

    bool swap(k old_key, k new_key)
    {
        v item = find(old_key);
        if (!item)
        {
            return false;
        }

        HASH_DEL(head, item);
        HASH_ADD(hh, head, id, sizeof(k), item);
        return true;
    }

    void del(k key)
    {
        HASH_DEL(head, key);
    }

    void del(k key, std::function<void(v current)> custom_delete)
    {
        custom_delete();
        HASH_DEL(head, key);
    }

    void del_all()
    {
        v current;
        v tmp;

        HASH_ITER(hh, head, current, tmp)
        {
            HASH_DEL(head, current);
            free(current);
        }
    }

    int del_all(std::function<bool(v current)> custom_delete)
    {
        v current;
        v tmp;

        int count = 0;

        HASH_ITER(hh, head, current, tmp)
        {
            bool del = custom_delete(current);
            if (del)
            {
                count++;
                HASH_DEL(head, current);
            }
        }

        return count;
    }

    explicit operator bool() const noexcept
    {
        return head != nullptr;
    }
};
