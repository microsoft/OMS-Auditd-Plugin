/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <iostream>
#include <thread>
#include <mutex>
#include <string>

extern "C" {
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
}

int main(int argc, char**argv) {
    if (argc < 2) {
        std::cerr << "socket path missing!" << std::endl;
        exit(1);
    }

    std::string file_path = argv[1];

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == lfd)
    {
        throw std::system_error(errno, std::system_category(), "socket(AF_UNIX, SOCK_STREAM)");
    }

    unlink(file_path.c_str());

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    file_path.copy(addr.sun_path, sizeof(addr.sun_path));
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)))
    {
        close(lfd);
        throw std::system_error(errno, std::system_category(), std::string("bind(AF_UNIX, ") + file_path + ")");
    }

    chmod(file_path.c_str(), 0666);

    if (listen(lfd, 1) != 0) {
        throw std::system_error(errno, std::system_category(), "listen()");
    }

    for (;;) {
        std::cerr << "Waiting for connection" << std::endl;
        socklen_t x = 0;
        int fd = accept(lfd, NULL, &x);
        if (-1 == fd) {
            throw std::system_error(errno, std::system_category(), "accept()");
        }

        std::cerr << "Connected" << std::endl;
        char data[1024];
        for (;;) {
            ssize_t n = read(fd, data, sizeof(data));
            if (n < 0)
            {
                throw std::system_error(errno, std::system_category(), "read()");
            }
            else if (n == 0)
            {
                close(fd);
                break;
            }

            ssize_t nw = write(1, data, n);
            if (nw < 0 || nw != n) {
                throw std::system_error(errno, std::system_category(), "write()");
            }
        }
    }
}