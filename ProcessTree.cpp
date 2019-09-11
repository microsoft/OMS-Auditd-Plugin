/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <cstring>
#include "ProcessTree.h"
#include "Logger.h"
#include <stdlib.h>
#include <dirent.h> 
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>



//constexpr int CLEAN_PROCESS_TIMEOUT = 300;
//constexpr int CLEAN_PROCESS_INTERVAL = 300;
constexpr int CLEAN_PROCESS_TIMEOUT = 60;
constexpr int CLEAN_PROCESS_INTERVAL = 60;

void ProcessNotify::InitProcSocket()
{
    struct sockaddr_nl s_addr;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr header;
        struct __attribute__ ((__packed__)) {
            struct cn_msg connector;
            enum proc_cn_mcast_op mode;
        };
    } message;

    Logger::Info("ProcessNotify initialising");

    _proc_socket = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (_proc_socket < 0) {
        Logger::Error("Cannot create netlink socket for proc monitoring");
        exit(1);
    }

    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_groups = CN_IDX_PROC;
    s_addr.nl_pid = getpid();

    if (bind(_proc_socket, (struct sockaddr *) &s_addr, sizeof(struct sockaddr_nl)) < 0) {
        Logger::Error("Cannot bind to netlink socket for proc monitoring");
        close(_proc_socket);
        exit(1);
    }

    memset(&message, 0, sizeof(message));
    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_pid = getpid();
    message.header.nlmsg_type = NLMSG_DONE;

    message.connector.id.idx = CN_IDX_PROC;
    message.connector.id.val = CN_VAL_PROC;
    message.connector.len = sizeof(enum proc_cn_mcast_op);

    message.mode = PROC_CN_MCAST_LISTEN;

    if (send(_proc_socket, &message, sizeof(message), 0) < 0) {
        Logger::Error("Cannot send to netlink socket for proc monitoring");
        exit(1);
    }
}

void ProcessNotify::run()
{
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr header;
        struct __attribute__ ((__packed__)) {
            struct cn_msg connector;
            struct proc_event event;
        };
    } message;

    Logger::Info("ProcessNotify starting");

    while(!IsStopping()) {
        if (recv(_proc_socket, &message, sizeof(message), 0) <= 0) {
            Logger::Error("Error receiving from netlink socket for process monitoring");
        }

        switch (message.event.what) {
            case proc_event::what::PROC_EVENT_FORK:
                _processTree->AddPnForkQueue(message.event.event_data.fork.child_pid, message.event.event_data.fork.parent_pid);
                break;
            case proc_event::what::PROC_EVENT_EXEC:
                _processTree->AddPnExecQueue(message.event.event_data.exec.process_pid);
                break;
            case proc_event::what::PROC_EVENT_EXIT:
                _processTree->AddPnExitQueue(message.event.event_data.exit.process_pid);
                break;
        }
    }
}

void ProcessTree::AddPnForkQueue(int pid, int ppid)
{
    struct ProcessQueueItem p = {ProcessQueueFork, ProcessTreeSource_pnotify, pid, ppid};
    std::unique_lock<std::mutex> queue_push_lock(_queue_push_mutex);
    _PnQueue.push(p);
    queue_push_lock.unlock();
    std::unique_lock<std::mutex> queue_pop_lock(_queue_pop_mutex);
    _queue_data_ready = true;
    _queue_data.notify_one();
}

void ProcessTree::AddPnExecQueue(int pid)
{
    struct ProcessQueueItem p = {ProcessQueueExec, ProcessTreeSource_pnotify, pid};
    std::unique_lock<std::mutex> queue_push_lock(_queue_push_mutex);
    _PnQueue.push(p);
    queue_push_lock.unlock();
    std::unique_lock<std::mutex> queue_pop_lock(_queue_pop_mutex);
    _queue_data_ready = true;
    _queue_data.notify_one();
}

void ProcessTree::AddPnExitQueue(int pid)
{
    struct ProcessQueueItem p = {ProcessQueueExit, ProcessTreeSource_pnotify, pid};
    std::unique_lock<std::mutex> queue_push_lock(_queue_push_mutex);
    _PnQueue.push(p);
    queue_push_lock.unlock();
    std::unique_lock<std::mutex> queue_pop_lock(_queue_pop_mutex);
    _queue_data_ready = true;
    _queue_data.notify_one();
}

void ProcessTree::run()
{
    std::unique_lock<std::mutex> queue_pop_lock(_queue_pop_mutex);
    while (!IsStopping()) {
        _queue_data.wait(queue_pop_lock, [&]{return _queue_data_ready;});
        while (!_PnQueue.empty()) {
            struct ProcessQueueItem p = _PnQueue.front();
            _PnQueue.pop();
            switch (p.type) {
                case ProcessQueueFork:
                    AddPid(p.pid, p.ppid);
                    break;
                case ProcessQueueExec:
                    AddPid(p.pid);
                    break;
                case ProcessQueueExit:
                    RemovePid(p.pid);
                    break;
                default:
                    Logger::Error("Invalid ProcessQueueType");
            }
        }

        // Check if it's time for routine pruning of stale pids
        std::chrono::duration<double> elapsed_seconds = std::chrono::system_clock::now() - _last_clean_time;
        if (elapsed_seconds.count() > CLEAN_PROCESS_INTERVAL) {
            Clean();
            _last_clean_time = std::chrono::system_clock::now();
        }
        _queue_data_ready = false;
    }
}

/* Process event from pnotify (fork)
   If the pid is not in our table then add it.
   If the ppid is in our table, copy the data from that entry.
*/
void ProcessTree::AddPid(int pid, int ppid)
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
    if (_processes.count(pid) == 0) {
        std::shared_ptr<ProcessTreeItem> process = std::make_shared<ProcessTreeItem>(ProcessTreeSource_pnotify, pid, ppid);
        if (ppid && _processes.count(ppid) > 0) {
            process->_uid = _processes[ppid]->_uid;
            process->_gid = _processes[ppid]->_gid;
            process->_exe = _processes[ppid]->_exe;
            process->_cmdline = _processes[ppid]->_cmdline;
            process->_exec_propagation = _processes[ppid]->_exec_propagation;
            _processes[ppid]->_children.emplace_back(pid);
            process->_ancestors = _processes[ppid]->_ancestors;
            struct Ancestor anc = {ppid, _processes[ppid]->_exe};
            process->_ancestors.emplace_back(anc);
            ApplyFlags(process);
        } else {
            struct Ancestor anc = {ppid, ""};
            process->_ancestors.emplace_back(anc);
        }
        _processes[pid] = process;
    } 
}

/* Process event from pnotify (exec)
   If process already exists (as it should) then increase the exec propagation variable in order to
   make sure the next execve audit event fills in this processes' details.
   If the process doesn't exist then add it.
*/
void ProcessTree::AddPid(int pid)
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
    if (_processes.count(pid) > 0) {
        if (_processes[pid]->_source == ProcessTreeSource_pnotify) {
            _processes[pid]->_exec_propagation = _processes[pid]->_exec_propagation + 1;
        }
    } else {
        std::shared_ptr<ProcessTreeItem> process = std::make_shared<ProcessTreeItem>(ProcessTreeSource_pnotify, pid);
        process->_exec_propagation = 1;
        _processes[pid] = process;
    }
}

/* Process event from AuditD (execve)
   Make a new entry (deleting any existing entry).
*/
std::shared_ptr<ProcessTreeItem> ProcessTree::AddProcess(int pid, int ppid, int uid, int gid, std::string exe, const std::string &cmdline)
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
    std::shared_ptr<ProcessTreeItem> process;

    if (exe[0] == '"' && exe.back() == '"') {
        exe = exe.substr(1, exe.length() - 2);
    }

    if (_processes.count(pid) > 0) {
        process = _processes[pid];
        process->_source = ProcessTreeSource_execve;
        process->_uid = uid;
        process->_gid = gid;
        process->_exe = exe;
        if (ppid != process->_ppid) {
            if (_processes.count(process->_ppid) > 0) {
                auto oldparent = _processes[process->_ppid];
                auto e = std::find(oldparent->_children.begin(), oldparent->_children.end(), pid);
                if (e != oldparent->_children.end()) {
                    oldparent->_children.erase(e);
                }
            }
            if (_processes.count(ppid) > 0) {
                _processes[ppid]->_children.emplace_back(pid);
                process->_ancestors = _processes[ppid]->_ancestors;
                struct Ancestor anc = {ppid, _processes[ppid]->_exe};
                process->_ancestors.emplace_back(anc);
            }
            process->_ppid = ppid;
        }
        process->_cmdline = cmdline;
        if (process->_exec_propagation > 0) {
            process->_exec_propagation = process->_exec_propagation - 1;
        }
        for (auto c : process->_children) {
            if (_processes.count(c) > 0) {
                auto p = _processes[c];
                if (p->_exec_propagation > 0) {
                    p->_source = ProcessTreeSource_execve;
                    p->_exe = exe;
                    p->_cmdline = cmdline;
                    p->_uid = uid;
                    p->_gid = gid;
                    p->_ancestors = process->_ancestors;
                    struct Ancestor anc = {pid, exe};
                    p->_ancestors.emplace_back(anc);
                    p->_exec_propagation = p->_exec_propagation - 1;
                    ApplyFlags(p);
                }
            }
        }
        ApplyFlags(process);
    } else {
        process = std::make_shared<ProcessTreeItem>(ProcessTreeSource_execve, pid, ppid, uid, gid, exe, cmdline);
        if (_processes.count(ppid) > 0) {
            _processes[ppid]->_children.emplace_back(pid);
            process->_ancestors = _processes[ppid]->_ancestors;
            struct Ancestor anc = {ppid, _processes[ppid]->_exe};
            process->_ancestors.emplace_back(anc);
        }
        ApplyFlags(process);
        _processes[pid] = process;
    }

    return process;
}

/* Process exit event from pnotify (exit)
*/
void ProcessTree::RemovePid(int pid)
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
    if (_processes.count(pid) > 0) {
        _processes[pid]->_exit_time = std::chrono::system_clock::now();
        _processes[pid]->_exited = true;
    }
}

void ProcessTree::Clean()
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);

    for (auto element = _processes.begin(); element != _processes.end();) {
        if (element->second->_exited) {
            std::chrono::duration<double> elapsed_seconds = std::chrono::system_clock::now() - element->second->_exit_time;
            if (elapsed_seconds.count() > CLEAN_PROCESS_TIMEOUT) {
                // remove this process
                element = _processes.erase(element);
                // back round the loop without iterating (as the erase() gave us the next item)
                continue;
            }
        }
        element++;
    }
}

std::shared_ptr<ProcessTreeItem> ProcessTree::GetInfoForPid(int pid)
{
    if (_processes.count(pid) > 0 && _processes[pid]->_source != ProcessTreeSource_pnotify) {
        return _processes[pid];
    } else {
        // process doesn't currently exist, or we only have rudimentary information for it, so add it
        std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
        auto process = ReadProcEntry(pid);
        if (process != nullptr) {
            if (_processes.count(process->_ppid) > 0) {
                _processes[process->_ppid]->_children.emplace_back(pid);
                process->_ancestors = _processes[process->_ppid]->_ancestors;
                struct Ancestor anc = {process->_ppid, _processes[process->_ppid]->_exe};
                process->_ancestors.emplace_back(anc);
            }
            _processes[pid] = process;
            ApplyFlags(process);
        }
        return process;
    }
}

bool ProcessTree::is_number(char *s)
{
    for (char *t=s; *t != 0; t++) {
        if (!isdigit(*t)) {
            return false;
        }
    }

    return true;
}

void ProcessTree::ApplyFlags(std::shared_ptr<ProcessTreeItem> process)
{
    unsigned int height = 0;
    process->_flags = _filtersEngine->GetFlags(process, height);
    if (process->_flags.none()) {
        std::vector<struct Ancestor>::reverse_iterator rit = process->_ancestors.rbegin();
        for (; rit != process->_ancestors.rend() && process->_flags.none(); ++rit) {
            height++;
            if (_processes.count(rit->pid) > 0) {
                process->_flags = _filtersEngine->GetFlags(_processes[rit->pid], height);
            }
        }
    }
}


void ProcessTree::PopulateTree()
{ 
    struct dirent *de;
    int pid;

    DIR *dr = opendir("/proc"); 
  
    if (dr == NULL)
    { 
        return;
    } 
  
    while ((de = readdir(dr)) != NULL)  {
        if (is_number(de->d_name)) {
            pid = atoi(de->d_name);
            auto process = ReadProcEntry(pid);
            if (process != nullptr) {
                _processes[pid] = process;
            }
        }
    }

    closedir(dr);     

    for (auto p : _processes) {
        auto process = p.second;
        if (_processes.count(process->_ppid) > 0) {
            _processes[process->_ppid]->_children.emplace_back(process->_pid);
        }
    }

    for (auto p : _processes) {
        std::shared_ptr<ProcessTreeItem> process, parent;
        process = p.second;
        if (_processes.count(process->_ppid) > 0) {
            parent = _processes[process->_ppid];
        } else {
            parent = nullptr;
        }
        while (parent) {
            process->_ancestors.insert(process->_ancestors.begin(), {parent->_pid, parent->_exe});
            if (_processes.count(parent->_ppid) > 0) {
                parent = _processes[parent->_ppid];
            } else {
                parent = nullptr;
            }
        }
    }

    for (auto p : _processes) {
        ApplyFlags(p.second);
    }
} 

std::string ProcessTree::ReadFirstLine(const std::string& file)
{
    std::ifstream f;
    std::string line;

    try {
        f.open(file);
        std::getline(f, line);
        f.close();
    } catch (...) {
    }
    return line;
}

std::string ProcessTree::ReadParam(const std::string& file, const std::string& param)
{
    std::ifstream f;
    std::string line;
    std::string value;

    f.open(file);
    while (f.good() && f.is_open() && !f.eof()) {
        std::getline(f, line);
        if (!line.compare(0, param.size() + 1, param + ":")) {
            f.close();
            value = line.substr(param.size() + 1);
            size_t first = value.find_first_not_of(" \t");
            if ( first == std::string::npos) {
                return value;
            } else {
                return value.substr(first);
            }
        }
    }
    f.close();
    return value;
}

std::shared_ptr<ProcessTreeItem> ProcessTree::ReadProcEntry(int pid)
{
    std::shared_ptr<ProcessTreeItem> process = std::make_shared<ProcessTreeItem>(ProcessTreeSource_procfs, pid);
    std::string prefix = std::string("/proc/") + std::to_string(pid) + "/";

    // Check if the pid dir exists
    DIR *dir = opendir(prefix.c_str());
    if (!dir) {
        return nullptr;
    }

    try {
        std::string uidline = ReadParam(prefix + "status", "Uid");
        process->_uid = (int)std::stol(uidline.substr(0, uidline.find('\x09')));
        std::string gidline = ReadParam(prefix + "status", "Gid");
        process->_gid = (int)std::stol(gidline.substr(0, gidline.find('\x09')));
        process->_ppid = std::stoi(ReadParam(prefix + "status", "PPid"));
        char exepath[PATH_MAX];
        std::string exefpath = prefix + "exe";
        if (realpath(exefpath.c_str(), exepath)) {
            process->_exe = std::string(exepath);
        }

        std::string cmdline = ReadFirstLine(prefix + "cmdline");
        std::replace(cmdline.begin(), cmdline.end(), '\x00', ' ');
        while (cmdline.back() == ' ') {
            cmdline = cmdline.substr(0, cmdline.length() - 1);
        }
        process->_cmdline = cmdline;

        return process;
    } catch (...) {
        return nullptr;
    }
}


void ProcessTree::ShowTree()
{
    for (auto p : _processes) {
        ShowProcess(p.second);
        for (auto c : p.second->_children) {
            if (_processes.count(c) > 0) {
                auto p2 = _processes[c];
                printf("    => ");
                ShowProcess(p2);
            }
        }
    }
}

void ProcessTree::ShowProcess(std::shared_ptr<ProcessTreeItem> p)
{
    if (_processes.count(p->_ppid) > 0) {
        printf("%6d (%6d) [%d:%d] exe:'%s' cmdline:'%s' prop:%d (%s)\n", p->_pid, p->_ppid, p->_uid, p->_gid, p->_exe.c_str(), p->_cmdline.c_str(), p->_exec_propagation, _processes[p->_ppid]->_exe.c_str());
    } else {
        printf("%6d (%6d) [%d:%d] exe:'%s' cmdline:'%s' prop:%d\n", p->_pid, p->_ppid, p->_uid, p->_gid, p->_exe.c_str(), p->_cmdline.c_str(), p->_exec_propagation);
    }
    printf("  -> flags = %s\n", p->_flags.to_string().c_str());
    printf("  -> ");
    for (auto i : p->_ancestors) {
        printf("%s(%d), ", i.exe.c_str(), i.pid);
    }
    printf("%s(%d)\n", p->_exe.c_str(), p->_pid);
}


