/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "ExecUtil.h"
#include "Gate.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <poll.h>

#include <stdexcept>
#include <sstream>
#include <unordered_map>
#include <cstring>
#include <pthread.h>
#include <functional>

void write_error(int reason, int err, int fd) {
    uint32_t code = (static_cast<uint32_t>(reason) << 16) | static_cast<uint32_t>(err);
    auto ignored = write(fd, &code, sizeof(code));
}

void Cmd::cleanup() {
    if (_stdin > -1) {
        close(_stdin);
        _stdin = -1;
    }
    if (_stdout > -1) {
        close(_stdout);
        if (_stderr == _stdout) {
            _stderr = -1;
        }
        _stdout = -1;
    }
    if (_stderr > -1) {
        close(_stderr);
        _stderr = -1;
    }

    _pid = 0;
    _fail_reason = 0;
    _errno = 0;
    _stdin = -1;
    _stdout = -1;
    _stderr = -1;
    _exitcode = -1;
    _signal = -1;
}

int Cmd::Start() {
    if (_pid > 0) {
        return -EBUSY;
    }

    cleanup();

    int sigpipe[2];
    int inpipe[2] = {-1, -1};
    int outpipe[2] = {-1, -1};
    int errpipe[2] = {-1, -1};
    int ret = 0;

    ret = pipe2(sigpipe, O_CLOEXEC);
    if (ret != 0) {
        _fail_reason = FAILED_PIPE2;
        _errno = errno;
        return -errno;
    }

    if (STDIN_FLAGS(_flags) == PIPE_STDIN) {
        ret = pipe(inpipe);
        if (ret != 0) {
            _fail_reason = FAILED_PIPE;
            _errno = errno;
            return -errno;
        }
    }

    if (STDOUT_FLAGS(_flags) & PIPE_STDOUT) {
        ret = pipe(outpipe);
        if (ret != 0) {
            _fail_reason = FAILED_PIPE;
            _errno = errno;
            return -errno;
        }
    }

    if (STDERR_FLAGS(_flags) == PIPE_STDERR) {
        ret = pipe(errpipe);
        if (ret != 0) {
            _fail_reason = FAILED_PIPE;
            _errno = errno;
            return -errno;
        }
    }

    if ((_flags & COMBINE_OUTPUT) == COMBINE_OUTPUT) {
        errpipe[0] = outpipe[0];
        errpipe[1] = outpipe[1];
    }

    auto pid = fork();
    if (pid < 0) {
        _fail_reason = FAILED_FORK;
        _errno = errno;
        return -errno;
    }

    if (pid == 0) {
        close(sigpipe[_PIPE_READ]);
        char *args[_args.size()+2];
        args[0] = new char[_path.size()+1];
        _path.copy(args[0], _path.size());
        args[0][_path.size()] = 0;

        int idx = 1;
        for(auto& arg: _args) {
            args[idx] = new char[arg.size()+1];
            arg.copy(args[idx], arg.size());
            args[idx][arg.size()] = 0;
            idx++;
        }
        args[idx] = nullptr;

        if (inpipe[_PIPE_READ] != -1) {
            ret = dup2(inpipe[_PIPE_READ], 0);
            if (ret != 0) {
                write_error(FAILED_DUP2, errno, sigpipe[_PIPE_WRITE]);
                exit(1);
            }
        } else if (STDIN_FLAGS(_flags) == NULL_STDIN) {
            int in = open("/dev/null", O_RDONLY);
            if (in < 0) {
                write_error(FAILED_OPEN, errno, sigpipe[_PIPE_WRITE]);
                exit(1);
            }

            ret = dup2(in, 0);
            if (ret != 0) {
                write_error(FAILED_DUP2, errno, sigpipe[_PIPE_WRITE]);
                exit(1);
            }
        }

        if (outpipe[_PIPE_WRITE] != -1) {
            ret = dup2(outpipe[_PIPE_WRITE], 1);
            if (ret != 1) {
                write_error(FAILED_DUP2, errno, sigpipe[_PIPE_WRITE]);
                exit(1);
            }
        }

        if (errpipe[_PIPE_WRITE] != -1) {
            ret = dup2(errpipe[_PIPE_WRITE], 2);
            if (ret != 2) {
                write_error(FAILED_DUP2, errno, sigpipe[_PIPE_WRITE]);
                exit(1);
            }
        }

        ::execve(_path.c_str(), args, environ);
        write_error(FAILED_EXECVE, errno, sigpipe[_PIPE_WRITE]);
        exit(1);
    } else {
        _pid = pid;
        close(sigpipe[_PIPE_WRITE]);
        _stdin = inpipe[_PIPE_WRITE];
        _stdout = outpipe[_PIPE_READ];
        _stderr = errpipe[_PIPE_READ];
        if (inpipe[_PIPE_READ] != -1) {
            close(inpipe[_PIPE_READ]);
        }
        if (outpipe[_PIPE_WRITE] != -1) {
            close(outpipe[_PIPE_WRITE]);
        }
        if (errpipe[_PIPE_WRITE] != -1) {
            close(errpipe[_PIPE_WRITE]);
        }

        uint32_t code;
        // The return code is unimportant, the read will return once the child process exits or execs
        auto nr = read(sigpipe[_PIPE_READ], &code, sizeof(code));
        if (nr == sizeof(code)) {
            _fail_reason = static_cast<int>(code>>16);
            _errno = static_cast<int>(code&0xFFFF);
        } else {
            _fail_reason = 0;
            _errno = 0;
        }
        close(sigpipe[_PIPE_READ]);
        return (-_errno);
    }
}

// Send a signal to the process
int Cmd::Kill(int signum) {
    if (_pid <= 0) {
        return ESRCH;
    }
    return kill(_pid, signum);
}

// Wait for the process to exit. Returns 0, if the process is still running, 1 if the process has exited, -errno if the wait call failed.
int Cmd::Wait(bool wait) {
    if (_pid <= 0) {
        return 1;
    }
    int wstatus = 0;
    errno = 0;
    int ret;
    do {
        ret = waitpid(_pid, &wstatus, WNOHANG);
        if (ret < 0 && errno != EINTR) {
            return -errno;
        }
    } while (errno == EINTR);

    if (ret != 0) {
        if (ret == _pid) {
            _pid = 0;
            if (WIFEXITED(wstatus)) {
                _exitcode = WEXITSTATUS(wstatus);
            } else if (WIFSIGNALED(wstatus)) {
                _signal = WTERMSIG(wstatus);
            }
            return 1;
        } else if (errno == ECHILD) {
            // waitpid will return ECHILD if the specified pid doesn't exist.
            // If the caller has reaped the child via some other mechanism, then we'll get a ECHILD when we try to wait for it.
            _pid = 0;
            return 1;
        }
    } else if (wait) {
        while(true) {
            ret = waitpid(_pid, &wstatus, 0);
            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -errno;
            }
            if (ret == _pid) {
                _pid = 0;
                if (WIFEXITED(wstatus)) {
                    _exitcode = WEXITSTATUS(wstatus);
                } else if (WIFSIGNALED(wstatus)) {
                    _signal = WTERMSIG(wstatus);
                }
                return 1;
            } else if (errno == ECHILD) {
                // waitpid will return ECHILD if the specified pid doesn't exist.
                // If the caller has reaped the child via some other mechanism, then we'll get a ECHILD when we try to wait for it.
                _pid = 0;
                return 1;
            }
        }
    }
    return 0;
}

static std::unordered_map<int, std::string> s_failed_call({
    {Cmd::FAILED_FORK, "fork()"},
    {Cmd::FAILED_PIPE, "pipe()"},
    {Cmd::FAILED_PIPE2, "pipe2()"},
    {Cmd::FAILED_OPEN, "open(/dev/null)"},
    {Cmd::FAILED_DUP2, "dup2()"},
    {Cmd::FAILED_PRCTL, "prctl()"},
    {Cmd::FAILED_EXECVE, "execve()"},
});

std::string Cmd::FailMsg() {
    std::string str = s_failed_call[_fail_reason];
    str.append(" failed: ");
    str.append(std::strerror(_errno));
    return str;
}

int is_readable(int fd, int timeout) {
    if (fd <= 0) {
        return false;
    }
    struct pollfd fds;
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents = 0;

    auto ret = poll(&fds, 1, timeout);
    if (ret < 0) {
        if (errno != EINTR) {
            return -1;
        } else {
            return 0;
        }
    } else if (ret == 0) {
        return 0;
    }

    if ((fds.revents & POLLIN) != 0) {
        return 1;
    } if ((fds.revents & (POLLHUP&POLLRDHUP)) != 0) {
        return -1;
    } else {
        return -1;
    }
}

void* io_thread_entry(void* ptr) {
    (*static_cast<std::function<void()>*>(ptr))();
    return nullptr;
}

int Cmd::Run(std::string& output) {
    auto ret = Start();
    if (ret != 0) {
        output = "Cmd::Start(): " + FailMsg();
        return -1;
    }


    int fd = StdOutFd();

    Gate io_gate1;
    Gate io_gate2;

    std::function<void()> fn = [&io_gate1, &io_gate2, &output, fd]() {
        sigset_t set;

        // Make sure this thread doesn't receive unwanted signals
        sigfillset(&set);
        pthread_sigmask(SIG_BLOCK, &set, NULL);

        // Make sure the thread will get interrupted by SIGQUIT
        sigemptyset(&set);
        sigaddset(&set, SIGQUIT);
        pthread_sigmask(SIG_UNBLOCK, &set, NULL);

        std::array<char, 1024> buf;
        ssize_t nr = 0;
        do {
            nr = read(fd, buf.data(), buf.size());
            if (nr > 0) {
                output.append(buf.data(), nr);
            }
        } while (nr > 0 || (nr < 0 && errno == EINTR && io_gate1.GetState() == Gate::CLOSED));
        io_gate2.Open();
        return nullptr;
    };

    pthread_t thread_id;
    auto err = pthread_create(&thread_id, nullptr, io_thread_entry, &fn);
    if (err != 0) {
        throw std::system_error(err, std::system_category());
    }

    ret = Wait(true);

    // Wait up to 100 milliseconds for io thread to finish
    if (!io_gate2.Wait(Gate::OPEN, 100)) {
        // io thread has not exited, kill it
        io_gate1.Open();
        pthread_kill(thread_id, SIGQUIT);
    }
    pthread_join(thread_id, nullptr);

    if (ret < 0) {
        auto err = errno;
        output = "Failed to get process exit status: " + std::string(std::strerror(err));
    }
    if (Signal() > 0) {
        output = "Process terminated with signal (" + std::to_string(Signal()) + ")";
        return 1;
    }
    return ExitCode();
}
