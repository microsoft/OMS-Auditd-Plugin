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
#include <cstring>

extern "C" {
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
}

void usage()
{
    std::cerr <<
              "Usage:\n"
                      "fakepipe -s <socket path> -f <event file>\n"
                      "\n"
                      "-f <event file>   - The path to the event data file or '-' for stdin.\n"
                      "-s <socket path>  - The path to the input socket.\n"
            ;
    exit(1);
}

int open_socket(const std::string& addr)
{
    std::cerr << "Connecting to " << addr << std::endl;

    struct sockaddr_un unaddr;
    memset(&unaddr, 0, sizeof(struct sockaddr_un));
    unaddr.sun_family = AF_UNIX;
    addr.copy(unaddr.sun_path, sizeof(unaddr.sun_path));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd) {
        throw std::system_error(errno, std::system_category(), "socket() failed");
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&unaddr), sizeof(unaddr)) != 0) {
        ::close(fd);
        std::cerr << "Failed to connect to " << addr << ":" << std::strerror(errno) << std::endl;
        return -1;
    }

    return fd;
}

int do_write(int fd, const void * buf, size_t size)
{
    size_t nleft = size;
    do {
        auto nw = write(fd, reinterpret_cast<const char*>(buf)+(size-nleft), nleft);
        if (nw < 0) {
            if (errno != EINTR) {
                return size-nleft;
            }
        } else if (nw == 0) {
            // This shouldn't happen, but treat as a EOF if it does in order to avoid infinite loop.
            return size-nleft;
        } else {
            nleft -= nw;
        }
    } while (nleft > 0);

    return size-nleft;
}

int main(int argc, char**argv) {
    std::string data_file;
    std::string socket_path;

    int opt;
    while ((opt = getopt(argc, argv, "f:s:")) != -1) {
        switch (opt) {
            case 'f':
                data_file = optarg;
                break;
            case 's':
                socket_path = optarg;
                break;
            default:
                usage();
        }
    }

    if (data_file.empty() || socket_path.empty()) {
        usage();
    }

    int fd = -1;
    if (data_file == "-") {
        fd = 1;
    } else {
        fd = open(data_file.c_str(), O_RDONLY);
        if (fd < 0) {
            throw std::system_error(errno, std::system_category(), "open()");
        }
    }

    int outfd = open_socket(socket_path);
    if (outfd < 0) {
        exit(1);
    }

    char data[64*1024];
    for (;;) {
        auto ret = read(fd, data, sizeof(data));
        if (ret < 0) {
            throw std::system_error(errno, std::system_category(), "read()");
        } else if (ret == 0) {
            close(outfd);
            exit(0);
        }
        auto nw = do_write(outfd, data, ret);
        if (nw != ret) {
            close(outfd);
            exit(1);
        }
    }
}
