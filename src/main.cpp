// Copyright (C) 2025, Moritz Scheer

#include "core/server.hpp"

int main(int argc, char *argv[])
{
    faim::server server;

    int res = server.setup();
    if (res != 0)
    {
        res = server.run();
    }

    return res;
}
