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

#include <string>
#include <memory>
#include <set>
#include <list>

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

    static ProcFilter* GetInstance();     
    bool ShouldBlock(int pid);
    bool AddProcess(int pid, int ppid);
    bool RemoveProcess(int pid);

private:    
    static ProcFilter* _instance;
    std::set<int> _proc_list;
    static std::set<std::string> _blocked_process_names;
    

    static void static_init();
    ProcFilter();
    void Initialize();
    std::list<ProcessInfo>* get_all_processes();
    void compile_proc_list(std::list<ProcessInfo>* allProcs);
};

#endif //AUOMS_PROC_FILTER_H
