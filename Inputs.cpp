/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <cstring>
#include "Inputs.h"
#include "Logger.h"

extern "C" {
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <poll.h>
}

bool Inputs::Initialize() {
    Logger::Info("Inputs initializing");

    struct sockaddr_un addr;

    // maxLength: maximum permitted length of a path of a Unix domain socket
    constexpr auto maxLength = sizeof(addr.sun_path);
    if (_addr.size() > maxLength) {
        Logger::Error("Inputs: socketaddr '%s' exceeds max allowed length %d", _addr.c_str(), maxLength);
        return false;
    }

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0)
    {
        Logger::Error("Inputs: socket(AF_UNIX, SOCK_STREAM, 0) failed: %s", std::strerror(errno));
        return false;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    _addr.copy(addr.sun_path, sizeof(addr.sun_path));

    unlink(_addr.c_str());

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(lfd);
        Logger::Error("Inputs: bind(%s) failed: %s", _addr.c_str(), std::strerror(errno));
        return false;
    }

    // Only allow process uid access to the socket file
    if (chmod(_addr.c_str(), 0600) < 0) {
        close(lfd);
        Logger::Error("Inputs: chmod('%s', 0600) failed: %s", _addr.c_str(), std::strerror(errno));
        return false;
    }

    if (listen(lfd, 5) != 0) {
        close(lfd);
        Logger::Error("Inputs: listen() failed: %s", std::strerror(errno));
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(_run_mutex);
        _listener_fd = lfd;
    }
    return true;
}

void Inputs::on_stopping() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    if (_listener_fd > -1) {
        close(_listener_fd);
        _listener_fd = -1;
    }
}

void Inputs::on_stop() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _buffer->Close();

    if (_listener_fd > -1) {
        close(_listener_fd);
        _listener_fd = -1;
    }
    unlink(_addr.c_str());

    while(!_inputs.empty()) {
        auto i = _inputs.begin()->second;
        lock.unlock();
        i->Stop();
        lock.lock();
    }

    _inputs.clear();
    Logger::Info("Inputs stopped");
}

void Inputs::run() {
    Logger::Info("Inputs starting");

    int lfd;
    {
        std::lock_guard<std::mutex> lock(_run_mutex);
        lfd = _listener_fd;
    }

    Logger::Info("Inputs ready");
    while(!IsStopping()) {
        struct pollfd fds;
        fds.fd = lfd;
        fds.events = POLLIN;
        fds.revents = 0;

        int r = poll(&fds, 1, 10000);
        if (r < 0)
        {
            if (errno == EINTR && !IsStopping())
            {
                continue;
            }

            if (!IsStopping())
            {
                Logger::Error("Inputs: Fatal error while polling listener fd: %s", std::strerror(errno));
            }

            return;
        }
        if (r == 1)
        {
            if (fds.revents & (POLLERR|POLLNVAL|POLLHUP)) {
                return;
            } else {
                int newfd = accept(lfd, NULL, 0);
                if (newfd > 0) {
                    Logger::Info("Inputs: new connection: fd == %d", newfd);
                    if (!IsStopping()) {
                        add_connection(newfd);
                    } else {
                        close(newfd);
                    }
                } else {
                    // If accept was interrupted, or the connection was reset (RST)
                    // before it could be accepted, then just continue.
                    if (errno == EINTR || errno == ECONNABORTED) {
                        continue;
                    }

                    if (!IsStopping()) {
                        Logger::Error("Inputs: unexpected error from accept(%d): %s", lfd, std::strerror(errno));
                    }

                    return;
                }
            }
        }
    }
}

void Inputs::add_connection(int fd) {
    std::lock_guard<std::mutex> lock(_run_mutex);

    auto input = std::make_shared<Input>(std::make_unique<IOBase>(fd), _buffer, [this, fd]() { _inputs.erase(fd); });
    _inputs.insert(std::make_pair(fd, input));
    input->Start();
}
