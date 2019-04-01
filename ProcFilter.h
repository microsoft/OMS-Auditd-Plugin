/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_PROC_FILTER_H
#define AUOMS_PROC_FILTER_H

#include<sys/time.h>
#include <string>
#include <memory>
#include <set>
#include <unordered_set>
#include <list>
#include <unordered_map>
#include <queue>
#include "Config.h"
#include "UserDB.h"
#include "ProcessInfo.h"
#include "OMSEventWriterConfig.h"

struct ProcInfo {
    int pid;
    int ppid;
    int uid;
    std::string exe;
    std::string args;

    ProcInfo(ProcessInfo* proc);
    static const ProcInfo Empty;

    inline bool operator==(const ProcInfo& x) const;
    inline bool operator!=(const ProcInfo& x) const;
};

struct procSyscall {
    int propagates;
    std::string syscall;
};

struct ProcFilterSpec {
    ProcFilterSpec(const std::string& exe, const std::string& args, uint32_t flags, const std::string& user) {
        _exe = exe;
        _args = args;
        _flags = flags;
        _user = user;
    }

    std::string _exe;
    std::string _args;
    uint32_t _flags;
    std::string _user;
};

class ProcFilter {
public:
    
    ~ProcFilter() = default;
    ProcFilter(const std::shared_ptr<UserDB>& user_db);
    void UpdateProcesses(std::multimap<uint64_t, ProcInfo>& procs);
    void AddProcess(int pid, int ppid, std::string exe, std::string args, std::string user);
    bool FilterProcessSyscall(int pid, std::string syscall);

    bool ParseConfig(std::unique_ptr<Config>& config);

private:
    std::unordered_map<int, std::vector<procSyscall>> _filter_pids;
    std::unordered_map<int, std::vector<procSyscall>> _previous_filter_pids;
    std::vector<ProcSyscallFilterSpec> _filters;
    std::shared_ptr<UserDB> _user_db;
    struct timeval _last_time_initiated;

    std::vector<procSyscall> is_root_filter_proc(const std::string exe, const std::string args, const std::string user_name);
};

#endif //AUOMS_PROC_FILTER_H
