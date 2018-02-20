/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "ProcFilter.h"

#include <stdexcept>
#include <cassert>
#include <cctype>
#include <cstring>

#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <system_error>
#include <sys/types.h>
#include <sys/stat.h> /* for stat() */
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <algorithm>
#include <cctype>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/filereadstream.h>

// This include file can only be included in ONE translation unit
#include <auparse.h>

#define MAX_ITERATION_DEPTH 10

extern "C" {
#include <dlfcn.h>
}

/*****************************************************************************
 * Dynamicly load needed libaudit symbols
 *
 * There are two version of libaudit (libaudit0, and libaudit1) this makes it
 * impossible to build once then run on all supported distro versions.
 *
 * But, since libauparse is available on all supported distros, and it also
 * links to libaudit, all we need to do is call dlsym to get the function
 * pointer(s) we need.
 *
 *****************************************************************************/



/*****************************************************************************
 ** ProcessInfo
 *****************************************************************************/

ProcessInfo::ProcessInfo(std::string description, int processId, int parentProcessId)
{
    name = description;
    pid = processId;
    ppid = parentProcessId;
}

const ProcessInfo ProcessInfo::Empty("0",0,0);

inline bool ProcessInfo::operator==(const ProcessInfo& x) const
{
    return (pid == x.pid) && (ppid == x.ppid) && (name == x.name);
}

inline bool ProcessInfo::operator!=(const ProcessInfo& x) const
{
    return !(*this==x);
}


/*****************************************************************************
 ** ProcFilter
 *****************************************************************************/

ProcFilter* ProcFilter::_instance = NULL;

std::set<std::string> ProcFilter::_blocked_process_names;

void ProcFilter::static_init()
{
    _blocked_process_names.clear();
    _blocked_process_names.insert("omiagent");
    _blocked_process_names.insert("omsagent");
}

// -------- helper functions -----------------------------
int ProcFilter::is_dir(std::string path)
{
    struct stat stat_buf;
    stat(path.c_str(), &stat_buf);
    int is_directory = S_ISDIR(stat_buf.st_mode);
    return (is_directory ? 1: 0);
}

bool ProcFilter::is_number(const std::string& s)
{
    return !s.empty() &&
           std::find_if(s.begin(), s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
}

bool ProcFilter::is_process_running(int pid)
{
    std::stringstream ss_file;
    ss_file << "/proc/" << pid << "/stat";
    std::string file = ss_file.str();
    struct stat stat_buf;
    return (stat(file.c_str(), &stat_buf) == 0);
}

std::string ProcFilter::get_user_of_process(int pid)
{
    std::stringstream ss_file;
    ss_file << "/proc/" << pid;
    std::string file_name = ss_file.str();

    struct stat stat_buf;
    if(stat(file_name.c_str(), &stat_buf) == -1)
    {
        return std::string::Empty;
    }
    struct passwd *pw = getpwuid(stat_buf.st_uid);
    return pw->pw_name;
}

ProcessInfo ProcFilter::read_proc_data_from_stat(const std::string& fileName)
{
    ProcessInfo procData = ProcessInfo::Empty;
    std::ifstream infile(fileName, std::ifstream::in);

    if(!infile) {
        return ProcessInfo::Empty;
    }

    int pid;
    std::string comm;
    char state;
    int ppid;
    int pgrp;
    int session;
    char c;

    if (infile >> pid >> comm >> state >> ppid >> pgrp >> session)
    {
        procData.pid = pid;
        procData.ppid = ppid;
        procData.name = comm;
        return procData;
    }
    return ProcessInfo::Empty;
}

// --------- end helper functions -------------------------

std::list<ProcessInfo>* ProcFilter::get_all_processes()
{
    std::list<ProcessInfo>* procList = new std::list<ProcessInfo>();
    std::string dir = "/proc/";
 
    DIR *dp;
    struct dirent *dirp, *dirFp ;
    if ((dp = opendir(dir.c_str())) == NULL) {
        return procList;
    }

    while ((dirp = readdir(dp)) != NULL) {
        std::string Tmp = dir.c_str() + std::string(dirp->d_name);
        if (is_number(std::string(dirp->d_name)) && is_dir(Tmp)) {
            ProcessInfo procData = read_proc_data_from_stat(Tmp + std::string("/stat"));
            if (procData != ProcessInfo::Empty) {
                procList->push_front(procData);
            } 
        }
    }
    closedir(dp);

    return procList;
}
void ProcFilter::compile_proc_list(std::list<ProcessInfo>* allProcs)
{
    std::string user_name;
    // add root blocking processes
    for (const ProcessInfo& proc : *allProcs)
    {
        for (const std::string& blockedName : ProcFilter::_blocked_process_names)                                                                                   
        {
            user_name = get_user_of_process(proc.pid);
            if (proc.name.find(blockedName) != std::string::npos && (user_name == std::string("omsagent") || user_name == std::string("root")))
            {
                _proc_list.insert(proc.pid);
                _delete_queue.push(proc.pid);
            }
        }
    }

    // find child blocked processes with limited depth of search
    bool newProcFound;
    int depth = 0;
    do {
        newProcFound = false;
        ++depth;
        for (const ProcessInfo& proc : *allProcs)
        {
            newProcFound = newProcFound | AddProcess(proc.pid, proc.ppid);
        }

    } while (newProcFound && (depth < MAX_ITERATION_DEPTH));
}

ProcFilter* ProcFilter::GetInstance()
{
    if (_instance == NULL)
    {
        static_init();
        _instance = new ProcFilter();
    }

    return _instance;
}

ProcFilter::~ProcFilter()
{
}

void ProcFilter::ResetAndFree()
{
    if(_instance != NULL)
    {
        delete _instance;
        _instance = NULL;
    }
}

void ProcFilter::Initialize()
{
    gettimeofday(&_last_time_initiated, NULL);
    _records_processed_since_reinit = 0;
    _proc_list.clear();
    while(!_delete_queue.empty())
    {
        _delete_queue.pop();
    }
    // TODO: scan existing processes and choose those in the names list and children
    std::list<ProcessInfo>* listOfProcesses = get_all_processes();
    compile_proc_list(listOfProcesses);
    delete listOfProcesses;
}

ProcFilter::ProcFilter()
{
    Initialize();
}

bool ProcFilter::ShouldBlock(int pid)
{
    return (_proc_list.find(pid) != _proc_list.end());
}

bool ProcFilter::test_and_recompile()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if((_last_time_initiated.tv_sec + 3600/*1 hour*/ < tv.tv_sec) || (_records_processed_since_reinit > 30000))
    {
        Initialize();
        return true;
    }
    return false;
}

bool ProcFilter::AddProcess(int pid, int ppid)
{
    bool is_new = false;
    if(!test_and_recompile())
    {
        // dead process which is no longer part of the tree should be removed, this causes revalidation
        is_new = !RemoveProcess(pid);
    }

    ++_records_processed_since_reinit;
    if(_proc_list.find(ppid) != _proc_list.end())
    {        
        _proc_list.insert(pid);
        if (is_new) _delete_queue.push(pid);

        // cleanup crawler iteration:
        int curr_pid = _delete_queue.front();
        _delete_queue.pop();
        if (!is_process_running(curr_pid))
        {
            RemoveProcess(curr_pid);
        }
        else
        {
            _delete_queue.push(curr_pid);
        }
        return true;
    }
    return false;
}

// Shalow delete. The children may remain
bool ProcFilter::RemoveProcess(int pid)
{
    if(_proc_list.find(pid) != _proc_list.end())
    {
        _proc_list.erase(pid);
        return true;
    }
    return false;
}
