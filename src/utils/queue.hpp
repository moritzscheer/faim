// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>

namespace safe
{

template <typename T> class queue
{
    std::queue<T> queue;
    std::mutex mtx;
    std::condition_variable cv;

  public:
    void push(T *item)
    {
        {
            std::lock_guard<std::mutex> lock(mtx);
            queue.push(item);
        }
        cv.notify_one();
    }

    T *pop()
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&] { return !queue.empty(); });
        T *item = queue.front();
        queue.pop();
        return item;
    }

    bool try_pop(T &item)
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (queue.empty())
            return false;
        item = std::move(queue.front());
        queue.pop();
        return true;
    }
};
} // namespace safe
