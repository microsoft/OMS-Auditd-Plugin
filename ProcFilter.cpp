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

ProcInfo::ProcInfo(ProcessInfo* proc)
{
    exe = proc->exe();
    pid = proc->pid();
    ppid = proc->ppid();
    uid = proc->uid();
    proc->get_arg1(arg1);
}

inline bool ProcInfo::operator==(const ProcInfo& x) const
{
    return (pid == x.pid) && (ppid == x.ppid) && (exe == x.exe);
}

inline bool ProcInfo::operator!=(const ProcInfo& x) const
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

uint32_t ProcFilter::is_root_filter_proc(const ProcInfo& proc) {
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

void ProcFilter::compile_filter_pids(std::vector<ProcInfo>& allProcs)
{
    std::unordered_multimap<int, int> procs;
    std::vector<std::pair<int,uint32_t>> search_pids;
    std::vector<std::pair<int,uint32_t>> tmp_pids;
    // add root blocking processes
    for (const ProcInfo& proc : allProcs)
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
                    Logger::Error("Invalid entry (%s) at (%d) in config for '%s' is missing", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
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
                    Logger::Error("Entry (%s) at (%d) in config for '%s' is missing", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
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

void ProcFilter::UpdateProcesses(std::vector<ProcInfo>& procs) {
    if (_filters.empty()) {
        return;
    }
    _previous_filter_pids.clear();
    _previous_filter_pids = _filter_pids;
    _filter_pids.clear();
    compile_filter_pids(procs);
}

ProcFilter::ProcFilter(const std::shared_ptr<UserDB>& user_db)
{
    _user_db = user_db;
}

bool ProcFilter::IsFilterEnabled() {
    return !_filters.empty();
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

void ProcFilter::AddProcess(int pid, int ppid)
{

    // Do nothing if there are no filters
    if (_filters.empty()) 
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
            _filter_pids.insert(std::pair<int, uint32_t>(pid, pit->second));
            return;
        }
    }

    // Parent wasn't found, check to see if it is a root filter proc
    auto pinfo = ProcessInfo::Open(pid);
    if (pinfo) {
        ProcInfo proc(pinfo.get());
        auto flags = is_root_filter_proc(proc);
        if (flags != 0) {
            _filter_pids.insert(std::pair<int, uint32_t>(pid, flags));
        }
    }
}
