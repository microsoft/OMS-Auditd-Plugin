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


const std::string CONFIG_PARAM_NAME = "filter_process_syscalls";

/*****************************************************************************
 ** ProcessInfo
 *****************************************************************************/

ProcInfo::ProcInfo(ProcessInfo* proc)
{
    exe = proc->exe();
    pid = proc->pid();
    ppid = proc->ppid();
    uid = proc->uid();
    proc->get_args(args);
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

ProcFilter::ProcFilter(const std::shared_ptr<UserDB>& user_db)
{
    _user_db = user_db;
}

bool ProcFilter::ParseConfig(std::unique_ptr<Config>& config) {
    if (config->HasKey(CONFIG_PARAM_NAME)) {
        auto doc = config->GetJSON(CONFIG_PARAM_NAME);
        if (!doc.IsArray()) {
            return false;
        }
        int idx = 0;
        for (auto it = doc.Begin(); it != doc.End(); ++it, idx++) {
            if (it->IsObject()) {
                std::string exe;
                std::string args;
                std::string user;
                std::vector<std::string> syscalls;
                int depth = 0;
                auto mi = it->FindMember("exe");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        exe = std::string(mi->value.GetString(), mi->value.GetStringLength());
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                } else {
                    Logger::Error("Invalid entry (exe) at (%d) in config for '%s' is missing", idx, CONFIG_PARAM_NAME.c_str());
                    _filters.clear();
                    return false;
                }
                mi = it->FindMember("args");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        args = std::string(mi->value.GetString(), mi->value.GetStringLength());
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
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
				mi = it->FindMember("syscalls");
				if (mi != it->MemberEnd()) {
					if (mi->value.IsArray()) {
						for (auto it2 = mi->value.Begin(); it2 != mi->value.End(); ++it2) {
							syscalls.emplace_back(std::string(it2->GetString(), it2->GetStringLength()));
						}
					} else {
						Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
						_filters.clear();
						return false;
					}
				}
				for (auto it2 : syscalls) {
					if (it2.substr(0, 1) == "!") {
						syscalls.emplace_back(std::string("*"));
						break;
					}
				}
				mi = it->FindMember("depth");
				if (mi != it->MemberEnd()) {
					if (mi->value.IsInt()) {
						depth = mi->value.GetInt();
					} else {
						Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
						_filters.clear();
						return false;
					}
				}
                _filters.emplace(_filters.end(), exe, args, user, syscalls, depth);
            } else {
                Logger::Error("Invalid entry (%d) in config for '%s'", idx, CONFIG_PARAM_NAME.c_str());
                _filters.clear();
                return false;
            }
        }
    }
    return true;
}


std::vector<procSyscall> ProcFilter::is_root_filter_proc(const std::string exe, const std::string args, const std::string user_name)
{
    std::vector<procSyscall> syscalls;

    for (auto ent : _filters)
    {
        if (std::regex_search(exe, ent._exe)) {
            if (std::regex_search(args, ent._args)) {
                if (ent._user.empty() || (user_name == ent._user)) {
                    if (ent._syscalls.empty()) {
                        procSyscall pSyscall;
                        pSyscall.propagates = ent._depth;
                        pSyscall.syscall = "*";
                        syscalls.emplace_back(pSyscall);
                        return syscalls;
                    } else {
                        for (auto syscallStr : ent._syscalls) {
                            procSyscall pSyscall;
                            pSyscall.propagates = ent._depth;
                            pSyscall.syscall = syscallStr;
                            syscalls.emplace_back(pSyscall);
                        }
                    }
                }
            }
        }
    }

    return syscalls;
}

void ProcFilter::UpdateProcesses(std::multimap<uint64_t, ProcInfo>& procs) {
    if (_filters.empty()) {
        return;
    }
    _previous_filter_pids.clear();
    _previous_filter_pids = _filter_pids;
    _filter_pids.clear();

    for (std::pair<uint64_t, ProcInfo> proc : procs) {
        auto p = proc.second;
        std::string user_name = _user_db->GetUserName(p.uid);
        AddProcess(p.pid, p.ppid, p.exe, p.args, user_name);
    }
}

void ProcFilter::AddProcess(int pid, int ppid, std::string exe, std::string args, std::string user)
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

    std::pair<int, std::vector<procSyscall>> procsys;
    std::vector<procSyscall> syscalls, syscalls_exc, syscalls_inc, syscalls_star;

    // Check if this process is a root filter
    syscalls = is_root_filter_proc(exe, args, user);

    // Now check if this is a child of an existing filtered process
    // and reduce the propagates (depth) value by 1
    auto it = _filter_pids.find(ppid);
    if (it != _filter_pids.end()) {
        for (auto s : it->second) {
            if (s.propagates >= 0) {
                s.propagates--;
            }
            syscalls.push_back(s);
        }

    } else {
        auto pit = _previous_filter_pids.find(ppid);
        if (pit != _previous_filter_pids.end()) {
            for (auto s : pit->second) {
                if (s.propagates >= 0) {
                    s.propagates--;
                }
                syscalls.push_back(s);
            }
        }
    }

    if (syscalls.empty()) {
        return;
    }

    // Sort the syscalls so the excluded ones are first, followed by the included ones, potentially
    // followed by a '*' if exclusions exist
    int max_prop = 0;
    for (auto s : syscalls) {
        if (s.syscall.substr(0,1) == "!") {
            syscalls_exc.push_back(s);
            if (s.propagates > max_prop) {
                max_prop = s.propagates;
            }
        } else if (s.syscall.substr(0,1) == "*") {
            syscalls_star.push_back(s);
        } else {
            syscalls_inc.push_back(s);
        }
    }

    syscalls.clear();
    for (auto s : syscalls_exc) {
        if (s.propagates >= 0) {
            syscalls.push_back(s);
        }
    }
    for (auto s : syscalls_inc) {
        if (s.propagates >= 0) {
            syscalls.push_back(s);
        }
    }
    if (!syscalls_exc.empty()) {
        procSyscall s;
        s.propagates = max_prop;
        s.syscall = "*";
        syscalls.push_back(s);
    }
    for (auto s : syscalls_star) {
        if (s.propagates >= 0) {
            syscalls.push_back(s);
        }
    }

    if (syscalls.empty()) {
        return;
    }

    procsys = std::make_pair(pid, syscalls);
    _filter_pids.insert(procsys);

}

bool ProcFilter::FilterProcessSyscall(int pid, std::string syscall)
{
    std::unordered_map<int, std::vector<procSyscall>>::const_iterator got = _filter_pids.find(pid);
    if (got != _filter_pids.end()) {
        for (auto it : got->second) {
            if (it.propagates >= 0) {
                if (it.syscall == "*") {
                    return true;
                } else if (it.syscall == syscall) {
                    return true;
                } else if (it.syscall == ("!" + syscall)) {
                    return false;
                }
            }
        }
    }

    return false;
}

