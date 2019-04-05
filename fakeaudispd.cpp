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
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <wait.h>
}

void usage()
{
    std::cerr <<
        "Usage:\n"
        "fakeaudispd -s <socket path> -b <auoms path>\n"
        "\n"
        "-b <auoms path>   - The path to the auoms binary.\n"
        "-c <config path>  - The path to the auoms config file.\n"
        "-s <socket path>  - The path to the input socket.\n"
        ;
    exit(1);
}

class Plugin {
public:
    Plugin(const std::string& bin_path, const std::string& config_path): _bin_path(bin_path), _config_path(config_path), _pid(-1), _fd(-1) {}

    void Start() {
        char *argv[3];
        int pipe[2];
        int pid, i;

        printf("Starting plugin\n");

        _inode = get_inode();

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) != 0) {
            throw std::system_error(errno, std::system_category(), "sockpair(AF_UNIX, SOCK_STREAM)");
        }

        _pid = fork();
        if (_pid > 0) {
            _fd = pipe[1];
            return;
        }
        if (pid < 0) {
            close(pipe[0]);
            close(pipe[1]);
            throw std::system_error(errno, std::system_category(), "fork()");
        }

        dup2(pipe[0], 0);

        char carg[3] = "-c";
        argv[0] = (char *)_bin_path.c_str();
        argv[1] = carg;
        argv[2] = (char *)_config_path.c_str();
        argv[3] = NULL;
        execve(_bin_path.c_str(), argv, NULL);
        exit(1);
    }

    void Stop(bool do_wait) {
        printf("Stopping plugin\n");
        if (_pid > 0) {
            kill(_pid, SIGTERM);
            _pid = -1;
            if (do_wait) {
                usleep(50000);
            }
        }
        if (_fd > -1) {
            close(_fd);
            _fd = -1;
        }
    }

    void Hup() {
        kill(_pid, SIGHUP);
    }

    int GetFd() { return _fd; }

    bool HasBinChanged() {
        ino_t inode = get_inode();
        printf("Old inode %ld, new inode %ld\n", _inode, inode);
        return inode != _inode;
    }

private:
    std::string _bin_path;
    std::string _config_path;
    int _pid;
    int _fd;
    ino_t _inode;

    ino_t get_inode() {
        struct stat st;
        if (stat(_bin_path.c_str(), &st) != 0) {
            throw std::system_error(errno, std::system_category(), "stat()");
        }
        return st.st_ino;
    }
};

volatile bool hup = false;
volatile bool stop = false;

void handle_sighup(int sig) {
    write(1, "SIGHUP\n", 7);
    hup = true;
}

void handle_stop(int sig) {
    write(1, "STOP\n", 5);
    stop = true;
}

void handle_sigchld( int sig )
{
    int status;

    waitpid(-1, &status, WNOHANG);
}

int main(int argc, char**argv) {
    std::string bin_path;
    std::string config_path;
    std::string socket_path;

    int opt;
    while ((opt = getopt(argc, argv, "b:c:s:")) != -1) {
        switch (opt) {
            case 'b':
                bin_path = optarg;
                break;
            case 'c':
                config_path = optarg;
                break;
            case 's':
                socket_path = optarg;
                break;
            default:
                usage();
        }
    }

    signal(SIGHUP, handle_sighup);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, handle_sigchld);

    int lfd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (-1 == lfd)
    {
        throw std::system_error(errno, std::system_category(), "socket(AF_UNIX, SOCK_STREAM)");
    }

    unlink(socket_path.c_str());

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    socket_path.copy(addr.sun_path, sizeof(addr.sun_path));
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)))
    {
        close(lfd);
        throw std::system_error(errno, std::system_category(), std::string("bind(AF_UNIX, ") + socket_path + ")");
    }

    chmod(socket_path.c_str(), 0666);

    if (listen(lfd, 1) != 0) {
        throw std::system_error(errno, std::system_category(), "listen()");
    }

    Plugin plugin(bin_path, config_path);

    plugin.Start();

    while (!stop) {
        struct pollfd fds;
        fds.fd = lfd;
        fds.events = POLLIN;
        fds.revents = 0;

        if (hup) {
            hup = false;

            if (plugin.HasBinChanged()) {
                plugin.Stop(true);
                plugin.Start();
            } else {
                plugin.Hup();
            }
        }

        auto ret = poll(&fds, 1, -1);
        if (ret < 0) {
            if (errno != EINTR) {
                throw std::system_error(errno, std::system_category());
            }
            continue;
        }

        if ((fds.revents & POLLIN) == 0) {
            continue;
        }

        std::cerr << "Waiting for connection" << std::endl;
        socklen_t x = 0;
        int fd = accept(lfd, NULL, &x);
        if (-1 == fd) {
            if (errno != EINTR) {
                throw std::system_error(errno, std::system_category());
            }
            continue;
        }

        int flags;
        if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
            flags = 0;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            throw std::system_error(errno, std::system_category());
        }

        std::cerr << "Connected" << std::endl;
        char data[1024];
        size_t idx = 0;
        while (!stop) {
            struct pollfd fds;
            fds.fd = fd;
            fds.events = POLLIN;
            fds.revents = 0;

            if (hup) {
                hup = false;

                if (plugin.HasBinChanged()) {
                    plugin.Stop(true);
                    plugin.Start();
                } else {
                    plugin.Hup();
                }
            }

            auto ret = poll(&fds, 1, -1);
            if (ret < 0) {
                if (errno != EINTR) {
                    throw std::system_error(errno, std::system_category());
                }
                continue;
            }

            if ((fds.revents & POLLIN) != 0) {
                auto ret = read(fd, data, sizeof(data));
                if (ret == 0) {
                    close(fd);
                    break;
                } else if (ret < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        exit(0);
                    }
                    throw std::system_error(errno, std::system_category());
                }
                ssize_t nw = write(plugin.GetFd(), data, ret);
                if (nw < 0 || nw != ret) {
                    throw std::system_error(errno, std::system_category(), "write()");
                }
            }
        }
    }
    plugin.Stop(false);
}