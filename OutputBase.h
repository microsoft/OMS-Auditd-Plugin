/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_OUTPUT_BASE_H
#define AUOMS_OUTPUT_BASE_H

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <atomic>

extern "C" {
#include <sys/uio.h>
};

class operation_interrupted_exception : public std::runtime_error {
public:
    operation_interrupted_exception()
            : std::runtime_error("Operation Interrupted")
    {}
};

class OutputBase {
public:
    static constexpr int OK = 1;
    static constexpr int FAILED = 0;
    static constexpr int CLOSED = -1;
    static constexpr int INTERRUPTED = -2;

    virtual bool IsOpen();
    virtual bool Open() = 0;
    virtual void Close();

    virtual bool CanRead();
    virtual int Read(void *buf, size_t buf_size);

    // Return true if all bytes written.
    // Return false non-recoverable error, Signal
    virtual int Write(const void *buf, size_t size);

protected:
    std::atomic<int> _fd;
};

#endif //AUOMS_OUTPUT_BASE_H
