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

struct ProcInfo {
    int pid;
    int ppid;
    int uid;
    std::string exe;
    std::string arg1;

    ProcInfo(ProcessInfo* proc);
    static const ProcInfo Empty;

    inline bool operator==(const ProcInfo& x) const;
    inline bool operator!=(const ProcInfo& x) const;
};

struct ProcFilterSpec {
    ProcFilterSpec(const std::string& exe, const std::string& arg1, uint32_t flags, const std::string& user) {
        _exe = exe;
        _arg1 = arg1;
        _flags = flags;
        _user = user;
    }

    std::string _exe;
    std::string _arg1;
    uint32_t _flags;
    std::string _user;
};

class ProcFilter {
public:
    
    ~ProcFilter() = default;
    ProcFilter(const std::shared_ptr<UserDB>& user_db);
    bool IsFilterEnabled();
    void UpdateProcesses(std::vector<ProcInfo>& procs);
    uint32_t GetFilterFlags(int pid, int ppid);
    void AddProcess(int pid, int ppid);

    bool ParseConfig(const Config& config);

private:
    std::unordered_map<int, uint32_t> _filter_pids;
    std::unordered_map<int, uint32_t> _previous_filter_pids;
    std::vector<ProcFilterSpec> _filters;
    std::shared_ptr<UserDB> _user_db;
    struct timeval _last_time_initiated;

    void compile_filter_pids(std::vector<ProcInfo>& allProcs);

    // helper methods
    static int is_dir(std::string path);
    static bool is_number(const std::string& s);
    static std::string do_readlink(std::string const& path);
    uint32_t is_root_filter_proc(const ProcInfo& proc);
};

#endif //AUOMS_PROC_FILTER_H
