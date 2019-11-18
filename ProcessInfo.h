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

size_t append_escaped_string(const char* ptr, size_t len, std::string& str);

class ProcessInfo {
public:
    ~ProcessInfo();

    static std::unique_ptr<ProcessInfo> Open();
    static std::unique_ptr<ProcessInfo> Open(int pid);

    bool next();

    void format_cmdline(std::string& str);
    bool get_arg1(std::string& str);

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

    inline std::string comm() { return _comm; }
    inline std::string exe() { return _exe; }

    inline uint64_t utime() { return _utime; }
    inline uint64_t stime() { return _stime; }

    std::string starttime();

    inline bool is_cmdline_truncated() { return _cmdline_truncated; }

private:
    explicit ProcessInfo(void* dp);

    bool parse_stat();
    bool parse_status();

    bool read(int pid);
    void clear();

    void* _dp;

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
    std::string _comm;
    std::string _exe;
    std::vector<uint8_t> _stat;
    std::vector<uint8_t> _status;
    std::vector<uint8_t> _statm;
    std::vector<uint8_t> _cmdline;
    std::string _starttime_str;
    bool _cmdline_truncated;
};

#endif //AUOMS_PROCESS_INFO_H
