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
#include <queue>
#include "UserDB.h"

struct ProcessInfo {
    int pid;
    int ppid;
    std::string name;

    ProcessInfo(std::string description, int processId, int parentProcessId);
    static const ProcessInfo Empty;  

    inline bool operator==(const ProcessInfo& x) const;
    inline bool operator!=(const ProcessInfo& x) const;
};

class ProcFilter {
public:
    
    ~ProcFilter();
    ProcFilter(const std::set<std::string>& blocked_process_names, const std::set<std::string>& blocked_user_names, const std::shared_ptr<UserDB>& user_db); 
    bool ShouldBlock(int pid);
    bool AddProcess(int pid, int ppid);
    bool RemoveProcess(int pid);

private:    
    std::set<int> _proc_list;
    std::queue<int> _delete_queue;
    std::set<std::string> _blocked_process_names;
    std::set<std::string> _blocked_user_names;
    std::shared_ptr<UserDB> _user_db;
    struct timeval _last_time_initiated;
    int _records_processed_since_reinit;
    int _add_proc_counter;
    
    
    void Initialize();
    std::list<ProcessInfo>* get_all_processes();
    void compile_proc_list(std::list<ProcessInfo>* allProcs);
    bool test_and_recompile();
    void cleanup_crawler_step();

    // helper methods
    static int is_dir(std::string path);
    static bool is_number(const std::string& s);
    static bool is_process_running(int pid);
    std::string get_user_of_process(int pid);
    static std::string do_readlink(std::string const& path);
    static ProcessInfo read_proc_data(const std::string& statFileName, const std::string& exeFileName);
};

#endif //AUOMS_PROC_FILTER_H
