/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "StdoutWriter.h"

extern "C" {
#include <unistd.h>
}

bool StdoutWriter::IsOpen()
{
    return _fd >= 0;
}

bool StdoutWriter::Open()
{
    return false;
}

void StdoutWriter::Close()
{
    if (_fd >= 0) {
        close(_fd);
        _fd = -1;
    }
}

int StdoutWriter::Write(const void * buf, size_t size)
{
    if (_fd < 0) {
        return CLOSED;
    }

    auto nw = write(_fd, buf, size);
    if (nw != size) {
        if (errno != EINTR) {
            return FAILED;
        }
        return INTERRUPTED;
    }

    return OutputBase::OK;
}
