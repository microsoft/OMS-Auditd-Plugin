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
#include <chrono>
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
    Logger::Warn("Connecting to '%s'", _addr.c_str());

    struct sockaddr_un unaddr;
    memset(&unaddr, 0, sizeof(struct sockaddr_un));
    unaddr.sun_family = AF_UNIX;
    _addr.copy(unaddr.sun_path, sizeof(unaddr.sun_path));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd) {
        throw std::system_error(errno, std::system_category(), "socket() failed");
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&unaddr), sizeof(unaddr)) != 0) {
        ::close(fd);
        Logger::Warn("Failed to connect to '%s': %s", _addr.c_str(), std::strerror(errno));
        return false;
    }

    _fd.store(fd);

    return true;
}

bool UnixDomainWriter::CanRead()
{
    return true;
}

int UnixDomainWriter::Read(void *buf, size_t size)
{
    int fd = _fd.load();
    size_t nleft = size;
    do
    {
        errno = 0;
        ssize_t nr = read(fd, reinterpret_cast<char*>(buf) + (size - nleft), nleft);
        if (nr < 0)
        {
            if (errno != EINTR) {
                return OutputBase::FAILED;
            }
        }
        else
        {
            nleft -= nr;

            if (nleft > 0 && nr == 0)
            {
                return OutputBase::CLOSED;
            }
        }
    } while (nleft > 0);

    return OutputBase::OK;
}
