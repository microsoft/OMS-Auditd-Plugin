/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "UnixDomainWriter.h"

#include "Logger.h"

#include <cstring>
#include <system_error>
#include <thread>

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
}

bool UnixDomainWriter::Open()
{
    struct sockaddr_un unaddr;
    memset(&unaddr, 0, sizeof(struct sockaddr_un));
    unaddr.sun_family = AF_UNIX;
    _addr.copy(unaddr.sun_path, sizeof(unaddr.sun_path));

    // If the first character is a '@', then this is an abstract socket address
    // Replace all '@' bytes with null bytes.
    if (unaddr.sun_path[0] == '@') {
        for (int i = 0; i < sizeof(unaddr.sun_path); i++) {
            if (unaddr.sun_path[i] == '@') {
                unaddr.sun_path[i] = 0;
            }
        }
    }

    int fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (-1 == fd) {
        throw std::system_error(errno, std::system_category(), "socket() failed");
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&unaddr), sizeof(unaddr)) != 0) {
        auto err = errno;
        ::close(fd);
        errno = err;
        return false;
    }

    _fd.store(fd);
    _rclosed.store(false);
    _wclosed.store(false);

    return true;
}
