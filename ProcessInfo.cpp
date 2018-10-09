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

bool read_file(const std::string& path, std::vector<uint8_t>& data, size_t limit, bool& truncated) {
    errno = 0;
    int fd = ::open(path.c_str(), O_RDONLY);
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
int read_link(const std::string& path, std::string& data) {
    char buff[PATH_MAX];
    data.clear();
    errno = 0;
    ssize_t len = ::readlink(path.c_str(), buff, sizeof(buff)-1);
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

bool ProcessInfo::parse_stat() {
    if (_stat.empty()) {
        return false;
    }

    char *ptr = reinterpret_cast<char*>(_stat.data());
    char *end = reinterpret_cast<char*>(ptr+_stat.size());

    // pid
    char *f_end = ptr;

    errno = 0;
    _pid = static_cast<int>(strtol(ptr, &f_end, 10));
    if (errno != 0 || *f_end != ' ') {
        return false;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return false;
    }

    // comm
    if (*ptr != '(') {
        return false;
    }
    f_end = strchr(ptr, ')');
    if (f_end == nullptr || f_end >= end) {
        return false;
    }
    _comm.assign(ptr+1, f_end-ptr-1);

    ptr = f_end+1;
    if (ptr < end && *ptr == ' ') {
        ptr = ptr+1;
    }

    if (ptr >= end) {
        return false;
    }

    // Skip state
    f_end = strchr(ptr, ' ');
    if (f_end == nullptr || f_end >= end) {
        return false;
    }
    ptr = f_end+1;
    if (ptr >= end) {
        return false;
    }

    // ppid
    errno = 0;
    _ppid = static_cast<int>(strtol(ptr, &f_end, 10));
    if (errno != 0 || *f_end != ' ') {
        return false;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return false;
    }

    // Skip pgrp
    f_end = strchr(ptr, ' ');
    if (f_end == nullptr || f_end >= end) {
        return false;
    }
    ptr = f_end+1;
    if (ptr >= end) {
        return false;
    }

    // sid
    errno = 0;
    _ses = static_cast<int>(strtol(ptr, &f_end, 10));
    if (errno != 0 || *f_end != ' ') {
        return false;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return false;
    }

    // Skip to starttime
    for (int i = 0; i < 15; ++i) {
        f_end = strchr(ptr, ' ');
        if (f_end == nullptr || f_end >= end) {
            return false;
        }
        ptr = f_end + 1;
        if (ptr >= end) {
            return false;
        }
    }

    // starttime
    errno = 0;
    _starttime = strtoull(ptr, &f_end, 10);
    if (errno != 0 || *f_end != ' ') {
        return false;
    }

    ptr = f_end+1;

    if (ptr >= end) {
        return false;
    }

    return true;
}

bool ProcessInfo::parse_status() {
    if (_status.empty()) {
        return false;
    }

    char *ptr = reinterpret_cast<char*>(_status.data());
    char *end = reinterpret_cast<char*>(ptr+_status.size());

    char *uid_line = strstr(ptr, "Uid:");
    if (uid_line == nullptr || uid_line >= end) {
        return false;
    }

    char *uid_line_end = strchr(uid_line, '\n');
    if (uid_line_end == nullptr || uid_line_end >= end) {
        return false;
    }

    char *gid_line = strstr(uid_line_end, "Gid:");
    if (gid_line == nullptr || gid_line >= end) {
        return false;
    }

    char *gid_line_end = strchr(gid_line, '\n');
    if (gid_line_end == nullptr || gid_line_end >= end) {
        return false;
    }

    ptr = uid_line;
    ptr += 4; // Skip "Uid:"
    ptr = strchr(ptr, '\t');
    if (ptr == nullptr) {
        return false;
    }

    int uids[4];
    for (int i = 0; i < 4; i++) {
        errno = 0;
        uids[i] = static_cast<int>(strtol(ptr, &end, 10));
        if (errno != 0) {
            return false;
        }
        while(*ptr == '\t') {
            ++ptr;
        }
    }

    ptr = gid_line;
    ptr += 4; // Skip "Gid:"
    ptr = strchr(ptr, '\t');
    if (ptr == nullptr) {
        return false;
    }

    int gids[4];
    for (int i = 0; i < 4; i++) {
        errno = 0;
        gids[i] = static_cast<int>(strtol(ptr, &end, 10));
        if (errno != 0) {
            return false;
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

    return true;
}

bool ProcessInfo::read(int pid) {
    const std::string path = "/proc/" + std::to_string(pid);
    bool truncated;

    if (!read_file(path+"/stat", _stat, 2048, truncated)) {
        // Only generate a log message if the error was something other than ENOENT (No such file or directory) or ESRCH (No such process)
        if (errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to read /proc/%d/stat: %s", pid, strerror(errno));
        }
        return false;
    }

    if (!read_file(path+"/status", _status, 8192, truncated)) {
        // Only generate a log message if the error was something other than ENOENT (No such file or directory) or ESRCH (No such process)
        if (errno != ENOENT && errno != ESRCH) {
            Logger::Warn("Failed to read /proc/%d/status: %s", pid, strerror(errno));
        }
        return false;
    }

    auto exe_status = read_link(path+"/exe", _exe);
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
    if (exe_status == 1) {
        // The Event field value size limit is UINT16_MAX (including NULL terminator)
        if (!read_file(path + "/cmdline", _cmdline, UINT16_MAX - 1, _cmdline_truncated)) {
            // Only generate a log message if the error was something other than ENOENT (No such file or directory) or ESRCH (No such process)
            if (errno != ENOENT && errno != ESRCH) {
                Logger::Warn("Failed to read /proc/%d/cmdline: %s", pid, strerror(errno));
            }
            return false;
        }
    }


    if (!parse_stat()) {
        Logger::Warn("Failed to parse /proc/%d/stat", pid);
        return false;
    }

    if (!parse_status()) {
        Logger::Warn("Failed to parse /proc/%d/status", pid);
        return false;
    }

    return true;
}

void ProcessInfo::format_cmdline(std::string& str) {
    const char* ptr = reinterpret_cast<const char*>(_cmdline.data());
    size_t size = _cmdline.size();

    str.clear();

    while(size > 0) {
        if (!str.empty()) {
            str.push_back(' ');
        }
        size_t n = bash_escape_string(str, ptr, size);
        size -= n;
        ptr += n;
        while(size > 0 && *ptr == 0) {
            --size;
            ++ptr;
        }
    }
}

bool ProcessInfo::get_arg1(std::string& str) {
    str.clear();

    const char* ptr = reinterpret_cast<const char*>(_cmdline.data());

    // Skip arg 0
    const char* end = ptr+_cmdline.size();
    while(ptr < end && *ptr != 0) {
        ++ptr;
    }

    if (*ptr != 0) {
        return false;
    }

    ++ptr;

    size_t size = bash_escape_string(str, ptr, end-ptr);
    return size != 0;
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

ProcessInfo::ProcessInfo(void* dp) {
    _dp = reinterpret_cast<DIR*>(dp);
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
    _comm.clear();
    _cmdline.clear();
    _cmdline_truncated = false;
    _starttime_str.clear();
}

std::unique_ptr<ProcessInfo> ProcessInfo::Open() {
    DIR *dp = opendir("/proc");

    if (dp == nullptr) {
        return std::unique_ptr<ProcessInfo>();
    }

    return std::unique_ptr<ProcessInfo>(new ProcessInfo(dp));
}

std::unique_ptr<ProcessInfo> ProcessInfo::Open(int pid) {
    auto proc = std::unique_ptr<ProcessInfo>(new ProcessInfo(nullptr));
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
