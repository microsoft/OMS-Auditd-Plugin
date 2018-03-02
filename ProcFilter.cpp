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

#include "Logger.h"

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
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <limits.h>
#include <rapidjson/document.h>

#define MAX_ITERATION_DEPTH 10
#define PATH_MAX_LEN 4096

const std::string CONFIG_PARAM_NAME = "process_filters";

/*****************************************************************************
 ** ProcessInfo
 *****************************************************************************/

ProcessInfo::ProcessInfo(const std::string& _exe, int processId, int parentProcessId)
{
    exe = _exe;
    pid = processId;
    ppid = parentProcessId;
}

const ProcessInfo ProcessInfo::Empty("0",0,0);

inline bool ProcessInfo::operator==(const ProcessInfo& x) const
{
    return (pid == x.pid) && (ppid == x.ppid) && (exe == x.exe);
}

inline bool ProcessInfo::operator!=(const ProcessInfo& x) const
{
    return !(*this==x);
}


/*****************************************************************************
 ** ProcFilter
 *****************************************************************************/

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
    std::string file = "/proc/" + std::to_string(pid) + "/stat";
    struct stat stat_buf;
    return (stat(file.c_str(), &stat_buf) == 0);
}

std::string ProcFilter::get_user_of_process(int pid)
{
    std::string file_name = "/proc/" + std::to_string(pid);

    struct stat stat_buf;
    if(stat(file_name.c_str(), &stat_buf) == -1)
    {
        return std::string();
    }
    // alternative for retrieving user name:
    // struct passwd *pw = getpwuid(stat_buf.st_uid);
    // return pw->pw_name;
    return  _user_db->GetUserName(stat_buf.st_uid);
}

std::string ProcFilter::do_readlink(std::string const& path) {
    char buff[PATH_MAX_LEN];
    ssize_t len = ::readlink(path.c_str(), buff, sizeof(buff)-1);
    if (len != -1) {
      buff[len] = '\0';
      return std::string(buff);
    }
    Logger::Warn("Failed to read exe link '%s': %s", path.c_str(), std::strerror(errno));
    return std::string();
}

ProcessInfo ProcFilter::read_proc_data(const std::string& pid_str)
{
    ProcessInfo procData = ProcessInfo::Empty;
    std::string statFileName = "/proc/" + pid_str + "/stat";
    std::string exeFileName = "/proc/" + pid_str + "/exe";
    std::ifstream infile(statFileName, std::ifstream::in);

    if(!infile) {
        return ProcessInfo::Empty;
    }

    int pid;
    std::string comm;
    char state;
    int ppid;
    int pgrp;
    int session;

    if (infile >> pid >> comm >> state >> ppid >> pgrp >> session)
    {
        procData.pid = pid;
        procData.ppid = ppid;
        procData.exe = do_readlink(exeFileName);
        if (procData.exe.empty()) {
            return ProcessInfo::Empty;
        }
        return procData;
    }
    return ProcessInfo::Empty;
}

bool ProcFilter::is_root_filter_proc(const ProcessInfo& proc) {
    std::string user_name = get_user_of_process(proc.pid);
    bool is_valid_user = false;
    // validate user name
    for (auto ent : _filters)
    {
        if (user_name == ent.second && proc.exe.length() >= ent.first.length() && proc.exe.compare(0,ent.first.length(), ent.first) == 0)
        {
            return true;
        }
    }
    return false;
}


// --------- end helper functions -------------------------

std::list<ProcessInfo>* ProcFilter::get_all_processes()
{
    std::list<ProcessInfo>* procList = new std::list<ProcessInfo>();
    std::string dir = "/proc/";
 
    DIR *dp;
    struct dirent *dirp;
    if ((dp = opendir(dir.c_str())) == NULL) {
        return procList;
    }

    while ((dirp = readdir(dp)) != NULL) {
        std::string pid_str = std::string(dirp->d_name);
        std::string Tmp = dir + pid_str;
        if (is_number(pid_str) && is_dir(Tmp)) {
            ProcessInfo procData = read_proc_data(pid_str);
            if (procData != ProcessInfo::Empty) {
                procList->push_front(procData);
            } 
        }
    }
    closedir(dp);

    return procList;
}
void ProcFilter::compile_filter_pids(std::list<ProcessInfo>* allProcs)
{
    std::unordered_multimap<int, int> procs;
    std::vector<int> search_pids;
    std::vector<int> tmp_pids;
    // add root blocking processes
    for (const ProcessInfo& proc : *allProcs)
    {
        if (is_root_filter_proc(proc)) {
            _filter_pids.insert(proc.pid);
            search_pids.push_back(proc.pid);
        }
        procs.insert(std::pair<int, int>(proc.ppid, proc.pid));
    }

    // Starting with initial root set of procs to filter
    // Look for children and add them to the filter set
    while(search_pids.size() > 0) {
        for (auto ppid : search_pids) {
            auto it = procs.find(ppid);
            while (it != procs.end() && it->first == ppid) {
                _filter_pids.insert(it->second);
                tmp_pids.push_back(it->second);
            }
        }
        search_pids = tmp_pids;
        tmp_pids.clear();
    }
}

ProcFilter::~ProcFilter()
{
}

bool ProcFilter::ParseConfig(const Config& config) {
    if (config.HasKey(CONFIG_PARAM_NAME)) {
        auto doc = config.GetJSON(CONFIG_PARAM_NAME);
        if (!doc.IsObject()) {
            return false;
        }
        for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
            if (it->value.IsArray()) {
                for (auto it2 = it->value.Begin(); it2 != it->value.End(); ++it) {
                    if (it2->IsString()) {
                        _filters.insert(std::pair<std::string, std::string>(std::string(it->name.GetString(), it->name.GetStringLength()),
                                                                            std::string(it2->GetString(), it2->GetStringLength())));
                    } else {
                        Logger::Error("Invalid entry (%s) in config for '%s'", it->name.GetString(), CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }
            } else {
                Logger::Error("Invalid entry (%s) in config for '%s'", it->name.GetString(), CONFIG_PARAM_NAME.c_str());
                _filters.clear();
                return false;
            }
        }
    }
    return true;
}

void ProcFilter::Load()
{
    if (_filters.empty()) {
        return;
    }
    gettimeofday(&_last_time_initiated, NULL);
    _filter_pids.clear();
    // scan existing processes and choose those in the names list and children
    std::list<ProcessInfo>* listOfProcesses = get_all_processes();
    compile_filter_pids(listOfProcesses);
    delete listOfProcesses;
}

ProcFilter::ProcFilter(const std::shared_ptr<UserDB>& user_db)
{
    _user_db = user_db;
}

bool ProcFilter::ShouldFilter(int pid)
{
    return (_filter_pids.find(pid) != _filter_pids.end());
}

bool ProcFilter::test_and_recompile()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if(tv.tv_sec - _last_time_initiated.tv_sec > 3600/*1 hour*/)
    {
        Load();
        return true;
    }
    return false;
}

void ProcFilter::AddProcess(int pid, int ppid)
{
    // Do nothing if there are no filters
    if (_filters.empty()) {
        return;
    }

    // Check to see if the entire set needs to be re-initialized
    if(test_and_recompile())
    {
        return;
    }

    // Look for the parent pid in set
    if(_filter_pids.find(ppid) != _filter_pids.end())
    {        
        _filter_pids.insert(pid);
        return;
    }

    // Parent wasn't found, check to see if it is a root filter proc
    auto proc = read_proc_data(std::to_string(pid));
    if (proc != ProcessInfo::Empty && is_root_filter_proc(proc)) {
        _filter_pids.insert(pid);
    }
}
