/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "StdinReader.h"

#include <iostream>
#include <system_error>

extern "C" {
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
}

StdinReader::StdinReader()
{
    _fd = 0;
    int flags;
    if (-1 == (flags = fcntl(_fd, F_GETFL, 0))) {
        flags = 0;
    }
    if (fcntl(_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        throw std::system_error(errno, std::system_category());
    }
}

int StdinReader::Read(void *buf, size_t buf_size, int timeout)
{
    struct pollfd fds;
    fds.fd = _fd;
    fds.events = POLLIN;
    fds.revents = 0;

    auto ret = poll(&fds, 1, timeout);
    if (ret < 0) {
        if (errno != EINTR) {
            throw std::system_error(errno, std::system_category());
        }
        return StdinReader::INTERRUPTED;
    } else if (ret == 0) {
        return StdinReader::TIMEOUT;
    }

    if ((fds.revents & POLLIN) != 0) {
        auto ret = read(_fd, buf, buf_size);
        if (ret == 0) {
            return StdinReader::CLOSED;
        } else if (ret < 0) {
            if (errno != EINTR) {
                throw std::system_error(errno, std::system_category());
            }
            return StdinReader::INTERRUPTED;
        }
        return ret;
    }

    throw std::runtime_error("Poll returned a fd status other than POLLIN");
}
