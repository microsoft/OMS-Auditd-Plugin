/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_IO_H
#define AUOMS_IO_H

#include <cstdio>
#include <atomic>
#include <functional>

extern "C" {
#include <unistd.h>
}

class IO {
public:
    static constexpr ssize_t OK = 1;
    static constexpr ssize_t CLOSED = 0;
    static constexpr ssize_t FAILED = -1;
    static constexpr ssize_t TIMEOUT = -2;
    static constexpr ssize_t INTERRUPTED = -3;
};

class IReader: public IO {
public:
    virtual ssize_t WaitReadable(long timeout) = 0;

    /*
     * Return >0 on success
     * Return CLOSED if fd closed
     * Return FAILED if read failed
     * Return INTERRUPTED if signal received
     */
    virtual ssize_t Read(void *buf, size_t buf_size, const std::function<bool()>& fn) = 0;
    ssize_t Read(void *buf, size_t buf_size) {
        return Read(buf, buf_size, nullptr);
    }

    /*
     * Return >0 on success
     * Return CLOSED if fd closed
     * Return FAILED if read failed
     * Return TIMEOUT if read timeout occurred
     * Return INTERRUPTED if signal received
     */
    virtual ssize_t Read(void *buf, size_t buf_size, long timeout, const std::function<bool()>& fn) = 0;
    ssize_t Read(void *buf, size_t buf_size, long timeout) {
        return Read(buf, buf_size, timeout, nullptr);
    }

    /*
     * Return OK on success
     * Return CLOSED if fd closed
     * Return FAILED if read failed
     * Return TIMEOUT if read timeout occurred
     * Return INTERRUPTED if signal received
     */
    virtual ssize_t ReadAll(void *buf, size_t buf_size, const std::function<bool()>& fn) = 0;
    ssize_t ReadAll(void *buf, size_t buf_size) {
        return ReadAll(buf, buf_size, nullptr);
    }

    /*
     * Return OK on success
     * Return CLOSED if fd closed
     * Return FAILED if read failed
     * Return TIMEOUT if read timeout occurred
     * Return INTERRUPTED if signal received
     */
    virtual ssize_t DiscardAll(size_t size, const std::function<bool()>& fn) = 0;
    ssize_t DiscardAll(size_t size) {
        return DiscardAll(size, nullptr);
    }
};

class IWriter: public IO {
public:
    virtual ssize_t WaitWritable(long timeout) = 0;

    /*
     * Return OK on success
     * Return CLOSED if fd closed
     * Return FAILED if read failed
     * Return INTERRUPTED if signal received
     */
    virtual ssize_t WriteAll(const void *buf, size_t size, long timeout, const std::function<bool()>& fn) = 0;
    inline ssize_t WriteAll(const void *buf, size_t size, const std::function<bool()>& fn) {
        return WriteAll(buf, size, -1, std::move(fn));
    }
    inline ssize_t WriteAll(const void *buf, size_t size) {
        return WriteAll(buf, size, -1, nullptr);
    }
};

class IOBase: public IReader, public IWriter {
public:
    explicit IOBase(int fd): _fd(fd), _rclosed(fd < 0), _wclosed(fd < 0) {}

    virtual ~IOBase() {
        Close();
    }

    int GetFd() { return _fd.load(); }

    virtual bool IsOpen();
    virtual bool Open();
    virtual void Close();
    virtual void CloseRead();
    virtual void CloseWrite();

    virtual void SetNonBlock(bool enable);

    ssize_t WaitReadable(long timeout) override;
    ssize_t WaitWritable(long timeout) override;
    ssize_t Read(void *buf, size_t buf_size, const std::function<bool()>& fn) override;
    ssize_t Read(void *buf, size_t buf_size, long timeout, const std::function<bool()>& fn) override;
    ssize_t ReadAll(void *buf, size_t buf_size, const std::function<bool()>& fn) override;
    ssize_t DiscardAll(size_t size, const std::function<bool()>& fn) override;
    ssize_t WriteAll(const void *buf, size_t size, long timeout, const std::function<bool()>& fn) override;

protected:
    std::atomic<int> _fd;
    std::atomic<bool> _rclosed;
    std::atomic<bool> _wclosed;
};
#endif //AUOMS_IO_H
