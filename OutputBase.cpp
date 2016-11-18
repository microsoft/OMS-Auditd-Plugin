/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "OutputBase.h"

#include <cassert>

extern "C" {
#include <unistd.h>
}

bool OutputBase::IsOpen()
{
    return _fd.load() >= 0;
}

void OutputBase::Close()
{
    int fd = _fd.load();
    if (fd >= 0) {
        _fd.store(-1);
        close(fd);
    }
}

bool OutputBase::CanRead()
{
    return false;
}

int OutputBase::Read(void *buf, size_t buf_size)
{
    throw std::runtime_error("IOutput::Read: Operation Not Supported");
}

int OutputBase::Write(const void * buf, size_t size)
{
    int fd = _fd.load();
    if (fd < 0) {
        return CLOSED;
    }

    size_t nleft = size;
    do {
        auto nw = write(fd, reinterpret_cast<const char*>(buf)+(size-nleft), nleft);
        if (nw < 0) {
            if (errno != EINTR) {
                return FAILED;
            }
        } else {
            nleft -= nw;
        }
    } while (nleft > 0);

    return OutputBase::OK;
}
