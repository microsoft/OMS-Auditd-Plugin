/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "UnixDomainListener.h"

#include "Logger.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <poll.h>
#include <cstring>

bool UnixDomainListener::Open() {
    struct sockaddr_un addr;

    // maxLength: maximum permitted length of a path of a Unix domain socket
    constexpr auto maxLength = sizeof(addr.sun_path);
    if (_socket_path.size() > maxLength) {
        Logger::Error("socketaddr '%s' exceeds max allowed length %ld", _socket_path.c_str(), maxLength);
        return false;
    }

    int lfd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (lfd < 0)
    {
        Logger::Error("socket(AF_UNIX, SOCK_STREAM, 0) failed: %s", std::strerror(errno));
        return false;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    _socket_path.copy(addr.sun_path, sizeof(addr.sun_path));

    // If the first character is a '@', then this is an abstract socket address
    // Replace all '@' bytes with null bytes.
    if (addr.sun_path[0] == '@') {
        for (int i = 0; i < sizeof(addr.sun_path); i++) {
            if (addr.sun_path[i] == '@') {
                addr.sun_path[i] = 0;
            }
        }
    }

    if (addr.sun_path[0] != 0) {
        unlink(_socket_path.c_str());
    }

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(lfd);
        Logger::Error("Inputs: bind(%s) failed: %s", _socket_path.c_str(), std::strerror(errno));
        return false;
    }

    if (addr.sun_path[0] != 0) {
        // Only allow process uid access to the socket file
        if (chmod(_socket_path.c_str(), _socket_file_mode) < 0) {
            close(lfd);
            Logger::Error("Inputs: chmod('%s', 0%03o) failed: %s", _socket_path.c_str(), _socket_file_mode, std::strerror(errno));
            return false;
        }
    }

    if (listen(lfd, 5) != 0) {
        close(lfd);
        Logger::Error("Inputs: listen() failed: %s", std::strerror(errno));
        return false;
    }

    _listen_fd = lfd;

    return true;
}

int UnixDomainListener::Accept() {
    while(_listen_fd != -1) {
        struct pollfd fds;
        fds.fd = _listen_fd;
        fds.events = POLLIN;
        fds.revents = 0;

        int r = poll(&fds, 1, 10000);
        if (r < 0)
        {
            if (errno == EINTR && _listen_fd != -1)
            {
                continue;
            }

            if (_listen_fd != -1)
            {
                Logger::Error("UnixDomainListener: Fatal error while polling listener fd: %s", std::strerror(errno));
            }

            return -1;
        }
        if (r == 1)
        {
            if (fds.revents & (POLLERR|POLLNVAL|POLLHUP)) {
                return -1;
            } else {
                int newfd = accept(fds.fd, NULL, 0);
                if (newfd >= 0) {
                    if (_listen_fd != -1) {
                        return newfd;
                    } else {
                        close(newfd);
                    }
                } else {
                    // If accept was interrupted, or the connection was reset (RST)
                    // before it could be accepted, then just continue.
                    if (errno == EINTR || errno == ECONNABORTED) {
                        continue;
                    }

                    if (_listen_fd != -1) {
                        Logger::Error("UnixDomainListener: unexpected error from accept(%d): %s", fds.fd, std::strerror(errno));
                    }

                    return -1;
                }
            }
        }
    }
    return -1;
}

void UnixDomainListener::Close() {
    if (_listen_fd != -1) {
        close(_listen_fd);
        _listen_fd = -1;
    }
    unlink(_socket_path.c_str());
}
