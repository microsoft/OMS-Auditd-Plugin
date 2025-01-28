/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "ProcessInfo.h"
#include "Logger.h"
#include "StringUtils.h"
#include "ExecveConverter.h"

#include <algorithm>
#include <climits>
#include <cerrno>
#include <cstring>
#include <dirent.h>

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
}

// Return boot time in seconds since epoch
time_t boot_time() {
    struct sysinfo sinfo;
    struct timespec ts;
    ::sysinfo(&sinfo);
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec - sinfo.uptime;
}

bool read_file(const char* path, std::vector<uint8_t>& data, size_t limit, bool& truncated) {
    errno = 0;
    int fd = ::open(path, O_RDONLY|O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    data.resize(limit+1);
    if (data.size() > 0) {
        ssize_t nr = read(fd, data.data(), data.size());
        if (nr < 0) {
            int err_save = errno;
            close(fd);
            errno = err_save;
            return false;
        } else {
            if (nr > limit) {
                data.resize(limit);
                truncated = true;
            } else {
                data.resize(nr);
                truncated = false;
            }
        }
    }
    close(fd);
    return true;
}

// Return 1 on success, 0 if there is no exe (the case for kernel processes), or -1 on error.
int read_link(const char* path, std::string& data) {
    char buff[PATH_MAX];
    data.clear();
    errno = 0;
    ssize_t len = ::readlink(path, buff, sizeof(buff)-1);
    if (len < 0) {
        // For kernel processes errno will be ENOENT
        if (errno == ENOENT) {
            return 1;
        }
        return -1;
    }
    data.assign(buff, len);
    return 1;
}

int ProcessInfo::read_and_parse_stat(int pid) {
    std::array<char, 64> path;
    std::array<char, 2048> data;

    snprintf(path.data(), path.size(), "/proc/%d/stat", pid);

    int fd = ::open(path.data(), O_RDONLY|O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to open /proc/%d/stat: %s", pid, strerror(errno));
        }
        return -1;
    }

    auto nr = ::read(fd, data.data(), data.size());
    if (nr <= 0) {
        close(fd);
        // Only generate a log message if the error was something other than ENOENT (No such file or directory) or ESRCH (No such process)
        if (nr < 0 && errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to read /proc/%d/stat: %s", pid, strerror(errno));
        }
        return -1;
    }
    close(fd);

    char *ptr = reinterpret_cast<char*>(data.data());
    char *end = reinterpret_cast<char*>(ptr+nr);

    // pid
    char *f_end = ptr;

    errno = 0;
    _pid = static_cast<int>(strtol(ptr, &f_end, 10));
    if (errno != 0 || *f_end != ' ') {
        return 1;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return 1;
    }

    // comm
    if (*ptr != '(') {
        return 1;
    }
    f_end = strstr(ptr, ") ");
    if (f_end != nullptr && f_end+1 < end && f_end[1] == ')') {
        f_end += 1;
    }
    if (f_end == nullptr || f_end >= end) {
        return 1;
    }

    _comm_size = f_end-ptr-1;
    if (_comm_size >= _comm.max_size()) {
        _comm_size = _comm.max_size()-1;
    }
    std::copy_n(ptr+1, _comm_size, _comm.data());
    _comm[_comm_size] = 0;

    ptr = f_end+1;
    if (ptr < end && *ptr == ' ') {
        ptr = ptr+1;
    }

    if (ptr >= end) {
        return 1;
    }

    // Skip state
    f_end = strchr(ptr, ' ');
    if (f_end == nullptr || f_end >= end) {
        return 1;
    }
    ptr = f_end+1;
    if (ptr >= end) {
        return 1;
    }

    // ppid
    errno = 0;
    _ppid = static_cast<int>(strtol(ptr, &f_end, 10));
    if (errno != 0 || *f_end != ' ') {
        return 1;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return 1;
    }

    // Skip pgrp
    f_end = strchr(ptr, ' ');
    if (f_end == nullptr || f_end >= end) {
        return 1;
    }
    ptr = f_end+1;
    if (ptr >= end) {
        return 1;
    }

    // sid
    errno = 0;
    _ses = static_cast<int>(strtol(ptr, &f_end, 10));
    if (errno != 0 || *f_end != ' ') {
        return 1;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return 1;
    }

    // Skip to utime
    for (int i = 0; i < 7; ++i) {
        f_end = strchr(ptr, ' ');
        if (f_end == nullptr || f_end >= end) {
            return 1;
        }
        ptr = f_end + 1;
        if (ptr >= end) {
            return 1;
        }
    }

    // utime
    errno = 0;
    _utime = strtoull(ptr, &f_end, 10);
    if (errno != 0 || *f_end != ' ') {
        return 1;
    }

    ptr = f_end+1;
    if (ptr >= end) {
        return 1;
    }

    // stime
    errno = 0;
    _stime = strtoull(ptr, &f_end, 10);
    if (errno != 0 || *f_end != ' ') {
        return 1;
    }

    ptr = f_end+1;
    if (ptr >= end) {
        return 1;
    }

    // Skip to starttime
    for (int i = 0; i < 6; ++i) {
        f_end = strchr(ptr, ' ');
        if (f_end == nullptr || f_end >= end) {
            return 1;
        }
        ptr = f_end + 1;
        if (ptr >= end) {
            return 1;
        }
    }

    // starttime
    errno = 0;
    _starttime = strtoull(ptr, &f_end, 10);
    if (errno != 0 || *f_end != ' ') {
        return 1;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return 1;
    }

    return 0;
}

int ProcessInfo::read_and_parse_status(int pid) {
    std::array<char, 64> path;
    std::array<char, 8192> data;

    snprintf(path.data(), path.size(), "/proc/%d/status", pid);

    int fd = ::open(path.data(), O_RDONLY|O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to open /proc/%d/status: %s", pid, strerror(errno));
        }
        return -1;
    }

    auto nr = ::read(fd, data.data(), data.size());
    if (nr <= 0) {
        close(fd);
        // Only generate a log message if the error was something other than ENOENT (No such file or directory) or ESRCH (No such process)
        if (nr < 0 && errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to read /proc/%d/status: %s", pid, strerror(errno));
        }
        return -1;
    }
    close(fd);

    char *ptr = reinterpret_cast<char*>(data.data());
    char *end = reinterpret_cast<char*>(ptr+nr);

    char *uid_line = strstr(ptr, "Uid:");
    if (uid_line == nullptr || uid_line >= end) {
        return 1;
    }

    char *uid_line_end = strchr(uid_line, '\n');
    if (uid_line_end == nullptr || uid_line_end >= end) {
        return 1;
    }

    char *gid_line = strstr(uid_line_end, "Gid:");
    if (gid_line == nullptr || gid_line >= end) {
        return 1;
    }

    char *gid_line_end = strchr(gid_line, '\n');
    if (gid_line_end == nullptr || gid_line_end >= end) {
        return 1;
    }

    ptr = uid_line;
    ptr += 4; // Skip "Uid:"
    ptr = strchr(ptr, '\t');
    if (ptr == nullptr) {
        return 1;
    }

    int uids[4];
    for (int i = 0; i < 4; i++) {
        errno = 0;
        uids[i] = static_cast<int>(strtol(ptr, &end, 10));
        if (errno != 0) {
            return 1;
        }
        while(*ptr == '\t') {
            ++ptr;
        }
    }

    ptr = gid_line;
    ptr += 4; // Skip "Gid:"
    ptr = strchr(ptr, '\t');
    if (ptr == nullptr) {
        return 1;
    }

    int gids[4];
    for (int i = 0; i < 4; i++) {
        errno = 0;
        gids[i] = static_cast<int>(strtol(ptr, &end, 10));
        if (errno != 0) {
            return 1;
        }
        while(*ptr == '\t') {
            ++ptr;
        }
    }

    _uid = uids[0];
    _euid = uids[1];
    _suid = uids[2];
    _fsuid = uids[3];

    _gid = gids[0];
    _egid = gids[1];
    _sgid = gids[2];
    _fsgid = gids[3];

    return 0;
}

int ProcessInfo::ExtractCGroupContainerId(const std::string& content) {
    const char* ptr = content.c_str();
    const char* line_end = nullptr;

    const char *containerd_prefix = "/containerd-";
    const size_t containerd_prefix_len = strlen(containerd_prefix);
    const char *docker_prefix = "/docker/";
    const size_t docker_prefix_len = strlen(docker_prefix);
    const char *system_docker_prefix = "/system.slice/docker-";
    const size_t system_docker_prefix_len = strlen(system_docker_prefix);
    const char *complex_docker_service_prefix = "/system.slice/docker.service/";


    while ((line_end = strchr(ptr, '\n')) != nullptr) {
        // Check for containerd format
        const char *containerd_pos = strstr(ptr, containerd_prefix);
        if (containerd_pos != nullptr && containerd_pos < line_end) {
            if (containerd_pos + containerd_prefix_len + 12 <= line_end) {
                _container_id = std::string(containerd_pos + containerd_prefix_len, 12); // Extract the first 12 characters of the container ID
                return 0;
            }
        }

        // Check for Docker format
        const char *docker_pos = strstr(ptr, docker_prefix);
        if (docker_pos != nullptr && docker_pos < line_end) {
            if (docker_pos + docker_prefix_len + 12 <= line_end) {
                _container_id = std::string(docker_pos + docker_prefix_len, 12); // Extract the first 12 characters of the container ID
                return 0;
            }
        }

        // Check for system.slice Docker format
        const char *system_docker_pos = strstr(ptr, system_docker_prefix);
        if (system_docker_pos != nullptr && system_docker_pos < line_end) {
            if (system_docker_pos + system_docker_prefix_len + 12 <= line_end) {
                _container_id = std::string(system_docker_pos + system_docker_prefix_len, 12); // Extract the first 12 characters of the container ID
                return 0;
            }
        }

        // Check for complex docker format
        const char *complex_format_pos = strstr(ptr, complex_docker_service_prefix);
        if (complex_format_pos != nullptr && complex_format_pos < line_end) {
             // Search for '/' before line_end
            const char *id_start = nullptr;
            for (const char *p = line_end; p >= complex_format_pos; --p) {
                if (*p == '/') {
                    id_start = p + 1;
                    break;
                }
            }
            if (id_start != nullptr) {                            
                // make sure we have 12 characters left in the line before i read them
                if (line_end > id_start && id_start + 12 <= line_end) { 
                    _container_id = std::string(id_start, 12); // Extract the container ID from the end of the line                      
                    return 0;
                }
            }
        }

        ptr = line_end + 1;
    }

    return 1;
}

int ProcessInfo::read_and_parse_cgroup(int pid) {
    std::array<char, 64> path;
    std::array<char, 2048> data;

    snprintf(path.data(), path.size(), "/proc/%d/cgroup", pid);

    int fd = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to open /proc/%d/cgroup: %s", pid, strerror(errno));
        }
        return -1;
    }

    auto nr = ::read(fd, data.data(), data.size());
    if (nr <= 0) {
        close(fd);
        if (nr < 0 && errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to read /proc/%d/cgroup: %s", pid, strerror(errno));
        }
        return -1;
    }
    close(fd);

    std::string content(data.data(), nr);
    return ExtractCGroupContainerId(content);
}

bool ProcessInfo::read(int pid) {
    std::array<char, 64> path;

    snprintf(path.data(), path.size(), "/proc/%d/exe", pid);

    int pret = read_and_parse_stat(pid);
    if (pret != 0) {
        if (pret > 0) {
            Logger::Warn("Failed to parse /proc/%d/stat", pid);
        }
        return false;
    }

    pret = read_and_parse_status(pid);
    if (pret != 0) {
        if (pret > 0) {
            Logger::Warn("Failed to parse /proc/%d/status", pid);
        }
        return false;
    }

    // Try to read the cgroup file to get the container ID
    // Its not a critical error if this fails
    read_and_parse_cgroup(pid);    

    auto exe_status = read_link(path.data(), _exe);
    if (exe_status < 0) {
            // EACCES (Permission denied) will be seen occasionally (probably due to racy nature of /proc iteration)
            // ONly emit error if it wasn't EACCES or ESRCH
            if (errno != EACCES && errno != ESRCH) {
                Logger::Warn("Failed to readlink /proc/%d/exe: %s", pid, strerror(errno));
            }
            return false;
    }

    // Only try to read the cmdline file if there was an exe link.
    // Kernel processes will not have anything in the cmdline file.
    if (exe_status == 1 && _cmdline_size_limit > 0) {
        // The Event field value size limit is UINT16_MAX (including NULL terminator)
        snprintf(path.data(), path.size(), "/proc/%d/cmdline", pid);
        if (!read_file(path.data(), _cmdline, _cmdline_size_limit, _cmdline_truncated)) {
            // Only generate a log message if the error was something other than ENOENT (No such file or directory) or ESRCH (No such process)
            if (errno != ENOENT && errno != ESRCH) {
                Logger::Warn("Failed to read /proc/%d/cmdline: %s", pid, strerror(errno));
            }
            return false;
        }
    }


    return true;
}

void ProcessInfo::format_cmdline(std::string& str) {
    ExecveConverter::ConvertRawCmdline(std::string_view(reinterpret_cast<char*>(_cmdline.data()), _cmdline.size()), str);
}

std::string ProcessInfo::starttime() {
    static auto clk_tick = sysconf(_SC_CLK_TCK);
    if (_starttime_str.empty()) {
        char fmt[256];
        char buf[256];
        struct tm tm;
        uint64_t st = _boot_time + ((_starttime * 1000) / clk_tick);
        time_t st_s = st / 1000;
        uint32_t st_m = static_cast<uint32_t>(st - (st_s * 1000));

        sprintf(fmt, "%%Y-%%m-%%dT%%H:%%M:%%S.%03uZ", st_m);
        gmtime_r(&st_s, &tm);
        auto tsize = strftime(buf, sizeof(buf), fmt, &tm);
        _starttime_str.assign(buf, tsize);
    }
    return _starttime_str;
}

ProcessInfo::ProcessInfo(void* dp, int cmdline_size_limit) {
    _dp = reinterpret_cast<DIR*>(dp);
    _cmdline_size_limit = cmdline_size_limit;
    _boot_time = boot_time() * 1000;
}

ProcessInfo::~ProcessInfo() {
    if (_dp != nullptr) {
        closedir(reinterpret_cast<DIR*>(_dp));
        _dp = nullptr;
    }
}

void ProcessInfo::clear() {
    _pid = -1;
    _ppid = -1;
    _ses = -1;
    _starttime = 0;
    _uid = -1;
    _euid = -1;
    _suid = -1;
    _fsuid = -1;
    _gid = -1;
    _egid = -1;
    _sgid = -1;
    _fsgid = -1;
    _exe.clear();
    _comm.fill(0);
    _cmdline.clear();
    _cmdline_truncated = false;
    _starttime_str.clear();
    _container_id.clear();
}

std::unique_ptr<ProcessInfo> ProcessInfo::Open(int cmdline_size_limit) {
    DIR *dp = opendir("/proc");

    if (dp == nullptr) {
        return std::unique_ptr<ProcessInfo>();
    }

    return std::unique_ptr<ProcessInfo>(new ProcessInfo(dp, cmdline_size_limit));
}

std::unique_ptr<ProcessInfo> ProcessInfo::OpenPid(int pid, int cmdline_size_limit) {
    auto proc = std::unique_ptr<ProcessInfo>(new ProcessInfo(nullptr, cmdline_size_limit));
    if (proc->read(pid)) {
        return proc;
    }
    return std::unique_ptr<ProcessInfo>();
}

bool ProcessInfo::next() {
    if (_dp == nullptr) {
        return false;
    }

    struct dirent *dirp;

    while ((dirp = readdir(reinterpret_cast<DIR*>(_dp))) != nullptr) {
        if (dirp->d_name[0] >= '0' && dirp->d_name[0] <= '9') {
            int pid = std::stoi(std::string(dirp->d_name));
            clear();
            if (read(pid)) {
                return true;
            }
        }
    }
    return false;
}
