/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_PROCESS_INFO_H
#define AUOMS_PROCESS_INFO_H

#include <string>
#include <vector>
#include <memory>
#include <array>

size_t append_escaped_string(const char* ptr, size_t len, std::string& str);

class ProcessInfo {
public:
    ~ProcessInfo();

    static std::unique_ptr<ProcessInfo> Open(int cmdline_size_limit);
    static std::unique_ptr<ProcessInfo> OpenPid(int pid, int cmdline_size_limit);

    bool next();

    void format_cmdline(std::string& str);

    inline int pid()   { return _pid; }
    inline int ppid()  { return _ppid; }
    inline int ses()   { return _ses; }
    inline int uid()   { return _uid; }
    inline int euid()  { return _euid; }
    inline int suid()  { return _suid; }
    inline int fsuid() { return _fsuid; }
    inline int gid()   { return _gid; }
    inline int egid()  { return _egid; }
    inline int sgid()  { return _sgid; }
    inline int fsgid() { return _fsgid; }
    inline std::string_view container_id() { return std::string_view(_container_id.data(), _container_id.size()); }

    inline std::string_view comm() { return std::string_view(_comm.data(), _comm_size); }
    inline std::string exe() { return _exe; }

    inline uint64_t utime() { return _utime; }
    inline uint64_t stime() { return _stime; }

    std::string starttime();

    inline bool is_cmdline_truncated() { return _cmdline_truncated; }
    
protected:
    int ExtractCGroupContainerId(const std::string& content);


private:
    explicit ProcessInfo(void* dp, int cmdline_size_limit);

    int read_and_parse_stat(int pid);
    int read_and_parse_status(int pid);
    int read_and_parse_cgroup(int pid);

    bool read(int pid);
    void clear();

    void* _dp;
    int _cmdline_size_limit;
    time_t _boot_time;

    int _pid;
    int _ppid;
    int _ses;
    uint64_t _utime;
    uint64_t _stime;
    uint64_t _starttime;
    int _uid;
    int _gid;
    int _euid;
    int _egid;
    int _suid;
    int _sgid;
    int _fsuid;
    int _fsgid;
    size_t _comm_size;
    std::array<char, 16> _comm;
    std::string _exe;
    std::vector<uint8_t> _cmdline;
    std::string _starttime_str;
    bool _cmdline_truncated;
    std::string _container_id;

    // Declare the test class as a friend
    friend class ProcessInfoTests;
};

#endif //AUOMS_PROCESS_INFO_H
