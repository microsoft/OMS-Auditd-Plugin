/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "IO.h"
#include "Signals.h"

#include <cassert>
#include <system_error>

extern "C" {
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
}

bool IOBase::IsOpen()
{
    return _fd.load() >= 0;
}

bool IOBase::Open()
{
    throw std::runtime_error("WriterBase::Open: Operation Not Supported");
}

void IOBase::Close()
{
    int fd = _fd.load();
    if (fd >= 0) {
        _fd.store(-1);
        close(fd);
    }
    _rclosed.store(true);
    _wclosed.store(true);
}

void IOBase::CloseRead() {
    _rclosed.store(true);
    if (_wclosed.load()) {
        Close();
    }
}

void IOBase::CloseWrite() {
    _wclosed.store(true);
    if (_rclosed.load()) {
        Close();
    }
}

void IOBase::SetNonBlock(bool enable) {
    int fd = _fd.load();
    if (_fd < 0) {
        return;
    }

    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    if (enable) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    if (fcntl(fd, F_SETFL, flags) != 0) {
        throw std::system_error(errno, std::system_category());
    }
}

ssize_t IOBase::WaitReadable(long timeout) {
    int fd = _fd.load();
    if (_fd < 0 || _rclosed.load()) {
        return CLOSED;
    }
    struct pollfd fds;
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents = 0;

    auto ret = poll(&fds, 1, static_cast<int>(timeout));
    if (ret < 0) {
        if (errno != EINTR) {
            return FAILED;
        } else {
            return INTERRUPTED;
        }
    } else if (ret == 0) {
        return TIMEOUT;
    }

    if ((fds.revents & POLLIN) != 0) {
        return OK;
    } if ((fds.revents & (POLLHUP&POLLRDHUP)) != 0) {
        return CLOSED;
    } else {
        return FAILED;
    }
}

ssize_t IOBase::WaitWritable(long timeout) {
    int fd = _fd.load();
    if (_fd < 0 || _wclosed.load()) {
        return CLOSED;
    }
    struct pollfd fds;
    fds.fd = fd;
    fds.events = POLLOUT;
    fds.revents = 0;

    auto ret = poll(&fds, 1, static_cast<int>(timeout));
    if (ret < 0) {
        if (errno != EINTR) {
            return FAILED;
        } else {
            return INTERRUPTED;
        }
    } else if (ret == 0) {
        return TIMEOUT;
    }

    if ((fds.revents & POLLOUT) != 0) {
        return OK;
    } if ((fds.revents & (POLLHUP&POLLRDHUP)) != 0) {
        return CLOSED;
    } else {
        return FAILED;
    }
}

ssize_t IOBase::Read(void *buf, size_t size, const std::function<bool()>& fn)
{
    int fd = _fd.load();
    if (_fd < 0 || _rclosed.load()) {
        return CLOSED;
    }
    errno = 0;
    ssize_t nr = read(fd, buf, size);
    if (nr < 0) {
        if (errno != EINTR) {
            if (errno == ECONNRESET) {
                return CLOSED;
            }
            return FAILED;
        } else if (fn && fn()) {
            return INTERRUPTED;
        }
    } else if (nr == 0) {
        return CLOSED;
    }
    return nr;
}

ssize_t IOBase::Read(void *buf, size_t size, long timeout, const std::function<bool()>& fn)
{
    int ret = 0;
    do {
        ret = WaitReadable(timeout);
        if (ret == INTERRUPTED && fn && fn()) {
            return ret;
        }
    } while (ret == INTERRUPTED);
    if (ret != OK) {
        return ret;
    }
    return Read(buf, size, fn);
}

ssize_t IOBase::ReadAll(void *buf, size_t size, const std::function<bool()>& fn)
{
    size_t nleft = size;
    do {
        int fd = _fd.load();
        if (_fd < 0 || _rclosed.load()) {
            return CLOSED;
        }
        errno = 0;
        ssize_t nr = read(fd, reinterpret_cast<char*>(buf) + (size - nleft), nleft);
        if (nr < 0) {
            if (errno != EINTR) {
                if (errno == ECONNRESET) {
                    return CLOSED;
                }
                return FAILED;
            } else if (fn && fn()) {
                return INTERRUPTED;
            } else {
                continue;
            }
        } else if (nr == 0) {
            return CLOSED;
        } else {
            nleft -= nr;
        }
    } while (nleft > 0);

    return OK;
}

ssize_t IOBase::DiscardAll(size_t size, const std::function<bool()>& fn)
{
    uint8_t buffer[1024*32];
    size_t nleft = size;
    do {
        int fd = _fd.load();
        if (_fd < 0 || _rclosed.load()) {
            return CLOSED;
        }
        errno = 0;
        size_t n = nleft;
        if (n > sizeof(buffer)) {
            n = sizeof(buffer);
        }
        ssize_t nr = read(fd, buffer, n);
        if (nr < 0) {
            if (errno != EINTR) {
                return FAILED;
            } else if (fn && fn()) {
                return INTERRUPTED;
            } else {
                continue;
            }
        } else if (nr == 0) {
            return CLOSED;
        } else {
            nleft -= nr;
        }
    } while (nleft > 0);

    return OK;
}

ssize_t IOBase::WriteAll(const void * buf, size_t size, long timeout, const std::function<bool()>& fn)
{
    size_t nleft = size;
    do {
        int fd = _fd.load();
        if (_fd < 0 || _wclosed.load()) {
            return CLOSED;
        }
        auto ret = WaitWritable(timeout);
        if (ret != OK) {
            return ret;
        }
        auto nw = write(fd, reinterpret_cast<const char*>(buf)+(size-nleft), nleft);
        if (nw < 0) {
            if (errno != EINTR) {
                return FAILED;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else if (fn && fn()) {
                return INTERRUPTED;
            }
        } else if (nw == 0) {
            // This shouldn't happen, but treat as a EOF if it does in order to avoid infinite loop.
            return CLOSED;
        } else {
            nleft -= nw;
        }
    } while (nleft > 0);

    return OK;
}
