// Copyright (C) 2025, Moritz Scheer

#pragma once

template <typename type> class queue
{
  private:
    type *head;
    type *tail;

  public:
    queue() : head(nullptr), tail(nullptr) {};

    void push(type *item)
    {
        item->next = nullptr;

        if (!head)
        {
            head = tail = item;
        }
        else
        {
            tail->next = item;
            tail = item;
        }
    }

    type *pop()
    {
        if (!head)
        {
            return nullptr;
        }

        type *item = head;
        head = head->next;

        if (!head)
        {
            tail = nullptr;
        }

        item->next = nullptr;
        return item;
    }

    int flush(int (*f)(type *) noexcept)
    {
        type *curr = head;
        type *prev = nullptr;

        int count = 0;

        while (curr)
        {
            type *next = curr->next;

            int res = f(curr);

            if (res == 0)
            {
                count++;

                if (prev)
                {
                    prev->next = next; // skip curr
                }
                else
                {
                    head = next; // remove head
                }

                if (next == nullptr) // remove tail
                {
                    tail = prev;
                }

                curr->next = nullptr; // detach node
            }
            else
            {
                prev = curr; // curr stays in queue
            }

            curr = curr->next; // move to next node
        }

        return count;
    }

    bool empty()
    {
        return head == nullptr;
    }

    type *front()
    {
        return head;
    }
};
