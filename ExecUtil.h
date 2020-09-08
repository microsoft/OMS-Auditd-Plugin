/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_EXECUTIL_H
#define AUOMS_EXECUTIL_H

#include <string>
#include <vector>
#include <atomic>

class Cmd {
public:
    static constexpr int STDIN_FLAG_MASK = 0x03;
    static constexpr int STDOUT_FLAG_MASK = 0x0C;
    static constexpr int STDERR_FLAG_MASK = 0x30;
    static constexpr int NULL_STDIN = 2;
    static constexpr int PIPE_STDIN = 1;
    static constexpr int PIPE_STDOUT = 1<<2;
    static constexpr int PIPE_STDERR = 1<<4;
    static constexpr int COMBINE_OUTPUT = 0xF<<2;
    static constexpr int STDIN_FLAGS(int flags) { return flags & STDIN_FLAG_MASK; }
    static constexpr int STDOUT_FLAGS(int flags) { return flags & STDOUT_FLAG_MASK; }
    static constexpr int STDERR_FLAGS(int flags) { return flags & STDERR_FLAG_MASK; }

    static constexpr int FAILED_FORK = 1;
    static constexpr int FAILED_PIPE = 2;
    static constexpr int FAILED_PIPE2 = 3;
    static constexpr int FAILED_OPEN = 4;
    static constexpr int FAILED_DUP2 = 5;
    static constexpr int FAILED_PRCTL = 6;
    static constexpr int FAILED_EXECVE = 7;

    // Args does not include args0.
    explicit Cmd(const std::string& path, const std::vector<std::string>& args, int flags):
            _path(path), _args(args), _flags(flags), _fail_reason(0), _errno(0), _pid(0), _stdin(-1), _stdout(-1), _stderr(-1), _exitcode(-1), _signal(-1) {}

    ~Cmd() {
        cleanup();
    }

    int StdInFd() { return _stdin; }
    int StdOutFd() { return _stdout; }
    int StdErrFd() { return _stderr; }
    int Pid() { return _pid; }

    // Start the process, return 0 if successful, -errno if failed to start process
    int Start();

    // Indicates which syscall failed inside Start();
    int FailedReason() { return _fail_reason; };

    std::string FailMsg();

    // Send a signal to the process
    int Kill(int signum);

    // Wait for the process to exit. Returns 0, if the process is still running, 1 if the process has exited, -errno if the wait call failed.
    int Wait(bool wait);

    // The exit code if the process exited. Return value will be 0 until Wait() returns non-zero
    int ExitCode() { return _exitcode; }

    // The signal that terminated the process. Return value will be 0 until Wait() returns non-zero. Will return 0, if process exited.
    int Signal() { return _signal; }

    // >= 0 for process exit code, < 0 for errno. Error message in output.
    int Run(std::string& output);

private:
    static constexpr int _PIPE_READ = 0;
    static constexpr int _PIPE_WRITE = 1;

    void cleanup();

    std::string _path;
    std::vector<std::string> _args;
    int _flags;
    int _fail_reason;
    int _errno;
    pid_t _pid;
    int _stdin;
    int _stdout;
    int _stderr;
    int _exitcode;
    int _signal;
};

#endif //AUOMS_EXECUTIL_H
