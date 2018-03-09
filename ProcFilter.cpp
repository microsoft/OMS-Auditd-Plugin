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

#include <string>
#include <iostream>
#include <fstream>
#include <sys/stat.h> /* for stat() */
#include <dirent.h>
#include <algorithm>
#include <unistd.h>
#include <limits.h>

#define RELOAD_INTERVAL 300 // 5 minutes

const std::string CONFIG_PARAM_NAME = "process_flags";

/*****************************************************************************
 ** ProcessInfo
 *****************************************************************************/

ProcessInfo::ProcessInfo(const std::string& _exe, int processId, int parentProcessId, int _uid)
{
    exe = _exe;
    pid = processId;
    ppid = parentProcessId;
    uid = _uid;
}

const ProcessInfo ProcessInfo::Empty("0",0,0,0);

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

std::string ProcFilter::do_readlink(std::string const& path) {
    char buff[PATH_MAX];
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

        struct stat stat_buf;
        if(stat(statFileName.c_str(), &stat_buf) == -1)
        {
            return ProcessInfo::Empty;
        }
        procData.uid = stat_buf.st_uid;

        procData.exe = do_readlink(exeFileName);
        if (procData.exe.empty()) {
            return ProcessInfo::Empty;
        }
        return procData;
    }
    return ProcessInfo::Empty;
}

uint32_t ProcFilter::is_root_filter_proc(const ProcessInfo& proc) {
    std::string user_name = _user_db->GetUserName(proc.uid);
    for (auto ent : _filters)
    {
        if (proc.exe.compare(0, ent._exe.length(), ent._exe) == 0) {
            if (!ent._user.empty() && user_name != ent._user) {
                continue;
            }
            if (!ent._arg1.empty() && proc.arg1.compare(0, ent._arg1.length(), ent._arg1) != 0) {
                continue;
            }
            return ent._flags;
        }
    }
    return 0;
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
    std::vector<std::pair<int,uint32_t>> search_pids;
    std::vector<std::pair<int,uint32_t>> tmp_pids;
    // add root blocking processes
    for (const ProcessInfo& proc : *allProcs)
    {
        auto flags = is_root_filter_proc(proc);
        if (flags != 0) {
            _filter_pids.insert(std::pair<int,uint32_t>(proc.pid, flags));
            search_pids.push_back(std::pair<int,uint32_t>(proc.pid, flags));
        }
        procs.insert(std::pair<int, int>(proc.ppid, proc.pid));
    }

    // Starting with initial root set of procs to filter
    // Look for children and add them to the filter set
    while(!search_pids.empty()) {
        for (auto ent : search_pids) {
            for (auto procPair : procs) {
                if (procPair.first == ent.first) {
                    _filter_pids.insert(std::pair<int, uint32_t>(procPair.second, ent.second));
                    tmp_pids.push_back(std::pair<int, uint32_t>(procPair.second, ent.second));
                }

            }
        }
        search_pids = tmp_pids;
        tmp_pids.clear();
    }
}

bool ProcFilter::ParseConfig(const Config& config) {
    if (config.HasKey(CONFIG_PARAM_NAME)) {
        auto doc = config.GetJSON(CONFIG_PARAM_NAME);
        if (!doc.IsArray()) {
            return false;
        }
        int idx = 0;
        for (auto it = doc.Begin(); it != doc.End(); ++it, idx++) {
            if (it->IsObject()) {
                std::string exe;
                std::string arg1;
                uint32_t flags = 0;
                std::string user;
                auto mi = it->FindMember("exe_prefix");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        exe = std::string(mi->value.GetString(), mi->value.GetStringLength());
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                } else {
                    Logger::Error("Invalid entry (exe_prefix) at (%d) in config for '%s' is missing", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                    _filters.clear();
                    return false;
                }
                mi = it->FindMember("arg1_prefix");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        arg1 = std::string(mi->value.GetString(), mi->value.GetStringLength());
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }
                mi = it->FindMember("flags");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsInt()) {
                        int i = mi->value.GetInt();
                        if (i <= 0 || i > 0xFFFF) {
                            Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                            _filters.clear();
                            return false;
                        }
                        flags = static_cast<uint32_t>(i) << 16;
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                } else {
                    Logger::Error("Entry (flags) at (%d) in config for '%s' is missing", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                    _filters.clear();
                    return false;
                }
                mi = it->FindMember("user");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        user = std::string(mi->value.GetString(), mi->value.GetStringLength());
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }
                _filters.emplace(_filters.end(), exe, arg1, flags, user);
            } else {
                Logger::Error("Invalid entry (%d) in config for '%s'", idx, CONFIG_PARAM_NAME.c_str());
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
    _previous_filter_pids.clear();
    _previous_filter_pids = _filter_pids;
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

uint32_t ProcFilter::GetFilterFlags(int pid, int ppid)
{
    auto it = _filter_pids.find(pid);
    if (it != _filter_pids.end()) {
        return it->second;
    }

    it = _filter_pids.find(ppid);
    if (it != _filter_pids.end()) {
        return it->second;
    }

    it = _previous_filter_pids.find(pid);
    if (it != _previous_filter_pids.end()) {
        return it->second;
    }

    it = _previous_filter_pids.find(ppid);
    if (it != _previous_filter_pids.end()) {
        return it->second;
    }

    return 0;
}

bool ProcFilter::test_and_recompile()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    if(tv.tv_sec - _last_time_initiated.tv_sec > RELOAD_INTERVAL)
    {
        Load();
        return true;
    }
    return false;
}

void ProcFilter::AddProcess(int pid, int ppid)
{

    // Do nothing if there are no filters
    if (_filters.empty()) 
    {
        return;
    }  
    
    // Check to see if the entire set needs to be re-initialized
    if(test_and_recompile())
    {
        return;
    }

    // This new processes's pid might still be present in the list if the pid was used by a previous process.
    // So, remove it from the list. If this new process needs to be filtered it will get re-added during the
    // parent pid check, or during the root filter prod check.
    _filter_pids.erase(pid);

    // Look for the parent pid in set
    auto it = _filter_pids.find(ppid);
    if (it != _filter_pids.end()) {
        _filter_pids.insert(std::pair<int, uint32_t>(pid, it->second));
        return;
    } else {
        auto pit = _previous_filter_pids.find(ppid);
        if (pit != _previous_filter_pids.end()) {
            _filter_pids.insert(std::pair<int, uint32_t>(pid, it->second));
            return;
        }
    }

    // Parent wasn't found, check to see if it is a root filter proc
    auto proc = read_proc_data(std::to_string(pid));
    if (proc != ProcessInfo::Empty) {
        auto flags = is_root_filter_proc(proc);
        if (flags != 0) {
            _filter_pids.insert(std::pair<int, uint32_t>(pid, flags));
        }
    }
}
