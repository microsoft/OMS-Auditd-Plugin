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

#include <climits>
#include <cerrno>
#include <cstring>
#include <dirent.h>

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
}

// code meanings:
//      'Z' - NULL end of string
//      '-' - Character needs to be quoted
//      '*' - Character doesn't need escaping or quoting.
//      other - Character must be escaped
const char* escape_codes =
    "Z---------------"  // 0x00 - 0x0F
    "----------------"  // 0x10 - 0x1F
    "-*\"*$***********"  // 0x20 - 0x2F
    "****************"  // 0x30 - 0x3F
    "****************"  // 0x40 - 0x4F
    "************\\***" // 0x50 - 0x5F
    "`***************"  // 0x60 - 0x6F
    "***************-"  // 0x70 - 0x7F
    "----------------"  // 0x80 - 0x8F
    "----------------"  // 0x90 - 0x9F
    "****************"  // 0xA0 - 0xAF
    "****************"  // 0xB0 - 0xBF
    "****************"  // 0xC0 - 0xCF
    "****************"  // 0xD0 - 0xDF
    "****************"  // 0xE0 - 0xEF
    "****************"; // 0xF0 - 0xFF

const char* hex_codes = "0123456789ABCDEF";

size_t escape_string(const uint8_t* start, const uint8_t* end, std::string& str) {
    bool quote_needed = false;
    size_t size = 0;
    size_t size_needed = 0;
    for(const uint8_t *ptr = start; ptr < end; ++ptr) {
        switch (*ptr) {
            default:
                switch (escape_codes[*ptr]) {
                    case 'Z':
                        ptr = end;
                        break;
                    case '-':
                        quote_needed = true;
                        size_needed += 1;
                        break;
                    case '*':
                        size_needed += 1;
                        break;
                    default:
                        size_needed += 2;
                        break;
                }
        }
    }

    if (quote_needed) {
        size_needed += 2;
    }

    if (str.capacity() - str.size() < size_needed) {
        str.reserve(str.size() + size_needed);
    }

    if (quote_needed) {
        str.push_back('"');
    }

    for(const uint8_t *ptr = start; ptr < end; ++ptr, ++size) {
        switch (escape_codes[*ptr]) {
            case 'Z':
                ptr = end;
                break;
            case '-':
            case '*':
                str.push_back(*ptr);
                break;
            default:
                str.push_back('\\');
                str.push_back(*ptr);
                break;
        }
    }

    if (quote_needed) {
        str.push_back('"');
    }

    return size;
}

size_t append_escaped_string(const char* ptr, size_t len, std::string& str) {
    const uint8_t* start = reinterpret_cast<const uint8_t*>(ptr);
    const uint8_t* end = start+len;
    return escape_string(start, end, str);
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
        // Only generate a log message if the error was something other than ENOENT
        if (errno != ENOENT) {
            Logger::Warn("Failed to read /proc/%d/stat: %s", pid, strerror(errno));
        }
        return false;
    }

    if (!read_file(path+"/status", _status, 8192, truncated)) {
        Logger::Warn("Failed to read /proc/%d/status: %s", pid, strerror(errno));
        return false;
    }

    auto exe_status = read_link(path+"/exe", _exe);
    if (exe_status < 0) {
            Logger::Warn("Failed to readlink /proc/%d/exe: %s", pid, strerror(errno));
            return false;
    }

    // Only try to read the cmdline file if there was an exe link.
    // Kernel processes will not have anything in the cmdline file.
    if (exe_status == 1) {
        // The Event field value size limit is UINT16_MAX (including NULL terminator)
        if (!read_file(path + "/cmdline", _cmdline, UINT16_MAX - 1, _cmdline_truncated)) {
            Logger::Warn("Failed to read /proc/%d/cmdline: %s", pid, strerror(errno));
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
    uint8_t *ptr = _cmdline.data();
    uint8_t *end = ptr+_cmdline.size();

    str.clear();

    while(ptr < end) {
        if (!str.empty()) {
            str.push_back(' ');
        }
        size_t size = escape_string(ptr, end, str);
        ptr += size+1;
    }
}

bool ProcessInfo::get_arg1(std::string& str) {
    uint8_t *ptr = _cmdline.data();
    uint8_t *end = ptr+_cmdline.size();

    // Skip arg 0
    while(ptr < end && *ptr != 0) {
        ++ptr;
    }

    if (*ptr != 0) {
        return false;
    }

    ++ptr;
    str.clear();

    size_t size = escape_string(ptr, end, str);
    return size != 0;
}

ProcessInfo::ProcessInfo(void* dp) {
    _dp = reinterpret_cast<DIR*>(dp);
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
