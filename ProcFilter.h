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
#include <list>
#include <unordered_map>
#include <queue>
#include "Config.h"
#include "UserDB.h"

struct ProcessInfo {
    int pid;
    int ppid;
    int uid;
    std::string exe;

    ProcessInfo(const std::string& _exe, int processId, int parentProcessId, int _uid);
    static const ProcessInfo Empty;  

    inline bool operator==(const ProcessInfo& x) const;
    inline bool operator!=(const ProcessInfo& x) const;
};

class ProcFilter {
public:
    
    ~ProcFilter() = default;
    ProcFilter(const std::shared_ptr<UserDB>& user_db);
    void Load();
    bool ShouldFilter(int pid, int ppid);
    void AddProcess(int pid, int ppid);

    bool ParseConfig(const Config& config);

private:
    std::set<int> _filter_pids;
    std::unordered_multimap<std::string, std::string> _filters;
    std::shared_ptr<UserDB> _user_db;
    struct timeval _last_time_initiated;

    std::list<ProcessInfo>* get_all_processes();
    void compile_filter_pids(std::list<ProcessInfo>* allProcs);
    bool test_and_recompile();

    // helper methods
    static int is_dir(std::string path);
    static bool is_number(const std::string& s);
    static std::string do_readlink(std::string const& path);
    static ProcessInfo read_proc_data(const std::string& pid_str);
    bool is_root_filter_proc(const ProcessInfo& proc);
};

#endif //AUOMS_PROC_FILTER_H
