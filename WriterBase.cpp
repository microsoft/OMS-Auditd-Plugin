/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "WriterBase.h"

#include "Signals.h"

#include <cassert>
#include <system_error>

extern "C" {
#include <unistd.h>
}

bool WriterBase::IsOpen()
{
    return _fd.load() >= 0;
}

bool WriterBase::Open()
{
    throw std::runtime_error("WriterBase::Open: Operation Not Supported");
}

void WriterBase::Close()
{
    int fd = _fd.load();
    if (fd >= 0) {
        _fd.store(-1);
        close(fd);
    }
}

bool WriterBase::CanRead()
{
    return true;
}

int WriterBase::Read(void *buf, size_t size)
{
    size_t nleft = size;
    do {
        int fd = _fd.load();
        if (_fd < 0) {
            return WriterBase::CLOSED;
        }
        errno = 0;
        ssize_t nr = read(fd, reinterpret_cast<char*>(buf) + (size - nleft), nleft);
        if (nr < 0) {
            if (errno != EINTR) {
                return WriterBase::FAILED;
            } else if (!Signals::IsExit()) {
                return INTERRUPTED;
            }
        } else if (nr == 0) {
            return WriterBase::CLOSED;
        } else {
            nleft -= nr;
        }
    } while (nleft > 0);

    return WriterBase::OK;
}

int WriterBase::Write(const void * buf, size_t size)
{
    size_t nleft = size;
    do {
        int fd = _fd.load();
        if (_fd < 0) {
            return WriterBase::CLOSED;
        }
        auto nw = write(fd, reinterpret_cast<const char*>(buf)+(size-nleft), nleft);
        if (nw < 0) {
            if (errno != EINTR) {
                return WriterBase::FAILED;
            } else if (!Signals::IsExit()) {
                return INTERRUPTED;
            }
        } else if (nw == 0) {
            // This shouldn't happen, but treat as a EOF if it does in order to avoid infinite loop.
            return WriterBase::CLOSED;
        } else {
            nleft -= nw;
        }
    } while (nleft > 0);

    return WriterBase::OK;
}
