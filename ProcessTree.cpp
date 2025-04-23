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
#include "StringUtils.h"
#include <stdlib.h>
#include <dirent.h> 
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/filter.h>
#include <sys/stat.h>

#ifndef SOL_NETLINIK
// This isn't defined in older socket.h include files.
#define SOL_NETLINK	270
#endif

//constexpr int CLEAN_PROCESS_TIMEOUT = 300;
//constexpr int CLEAN_PROCESS_INTERVAL = 300;
constexpr int CLEAN_PROCESS_TIMEOUT = 5;
constexpr int CLEAN_PROCESS_INTERVAL = 5;

constexpr int CMDLINE_SIZE_LIMIT = 1024;

bool ProcessNotify::InitProcSocket()
{
    struct sockaddr_nl s_addr;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr header;
        union {
            uint8_t buf[sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op)];
            struct __attribute__ ((__packed__)) {
                struct cn_msg connector;
                union {
                    uint8_t payload[sizeof(enum proc_cn_mcast_op)];
                    enum proc_cn_mcast_op mode;
                };
            };
        };
    } message;

    Logger::Info("ProcessNotify initialising");

    _proc_socket = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (_proc_socket < 0) {
        Logger::Error("Cannot create netlink socket for proc monitoring: %s", std::strerror(errno));
        return false;
    }

    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_groups = CN_IDX_PROC;
    s_addr.nl_pid = getpid();

    if (bind(_proc_socket, (struct sockaddr *) &s_addr, sizeof(struct sockaddr_nl)) < 0) {
        Logger::Error("Cannot bind to netlink socket for proc monitoring: %s", std::strerror(errno));
        close(_proc_socket);
        return false;
    }

    // Add BPF filter to exclude proc connector messages related to threads
    struct sock_filter filter[] = {
        // If netlink message is multi-part, just pass the message
        BPF_STMT (BPF_LD|BPF_H|BPF_ABS, offsetof (struct nlmsghdr, nlmsg_type)),
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K, htons (NLMSG_DONE), 1, 0),
        // Pass the whole message
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff),

        // If the netlink message doesn't contain a proc connector message, just pass the message
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
                    NLMSG_LENGTH (0) + offsetof (struct cn_msg, id)
                            + offsetof (struct cb_id, idx)),
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
                    htonl (CN_IDX_PROC),
                    1, 0),
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff),

        
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
                    NLMSG_LENGTH (0) + offsetof (struct cn_msg, id)
                            + offsetof (struct cb_id, idx)),
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
                    htonl (CN_VAL_PROC),
                    1, 0),
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff),

        // If the proc event is a PROC_EVENT_EXIT, pass it
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
                    NLMSG_LENGTH (0) + offsetof (struct cn_msg, data)
                            + offsetof (struct proc_event, what)),
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
                    htonl (PROC_EVENT_EXIT),
                    0, 1),
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff),

        // If the proc event is a PROC_EVENT_EXEC, pass it
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
                    NLMSG_LENGTH (0) + offsetof (struct cn_msg, data)
                            + offsetof (struct proc_event, what)),
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
                    htonl (PROC_EVENT_EXEC),
                    0, 1),
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff),

        // Drop what's left
        BPF_STMT (BPF_RET|BPF_K, 0),
    };

    struct sock_fprog fprog;
    fprog.filter = filter;
    fprog.len = sizeof filter / sizeof filter[0];

    if (setsockopt (_proc_socket, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof fprog) != 0) {
        Logger::Error("Failed set BPF filter socket for proc monitoring: %s", std::strerror(errno));
        close(_proc_socket);
        return false;
    }

    // Prevent ENOBUFS when messages generated faster then can be received.
    int on = 1;
    if (setsockopt(_proc_socket, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(on)) != 0) {
        Logger::Error("Failed set NETLINK_NO_ENOBUFS option on socket for proc monitoring: %s", std::strerror(errno));
        close(_proc_socket);
        return false;
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
        Logger::Error("Cannot send to netlink socket for proc monitoring: %s", std::strerror(errno));
        close(_proc_socket);
        return false;
    }
    return true;
}

void ProcessNotify::on_stopping() {
    if (_proc_socket > -1) {
        close(_proc_socket);
        _proc_socket = -1;
    }
}

void ProcessNotify::run()
{
    if (!InitProcSocket()) {
        return;
    }

    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr header;
        union {
            uint8_t buf[sizeof(struct cn_msg) + sizeof(struct proc_event)];
            struct __attribute__ ((__packed__)) {
                struct cn_msg connector;
                union {
                    uint8_t payload[sizeof(struct proc_event)];
                    struct proc_event event;
                };
            };
        };
    } message;
    // struct proc_event* pEvent = (struct proc_event*)message.connector.data;

    Logger::Info("ProcessNotify starting");

    while(!IsStopping()) {
        auto ret = recv(_proc_socket, &message, sizeof(message), 0);
        if (ret == 0) {
            if (!IsStopping()) {
                Logger::Error("Unexpected EOF on netlink socket for process monitoring");
            }
            return;
        } else if ( ret < 0) {

            if (errno == EINTR && !IsStopping()) {
                continue;
            }
            Logger::Error("Error receiving from netlink socket for process monitoring: %s", std::strerror(errno));
            return;
        }

        switch (message.event.what) {
            case PROC_EVENT_FORK: // proc_event::what::PROC_EVENT_FORK
                _processTree->AddPnForkQueue(message.event.event_data.fork.child_pid, message.event.event_data.fork.parent_pid);
                break;
            case PROC_EVENT_EXEC: // proc_event::what::PROC_EVENT_EXEC
                _processTree->AddPnExecQueue(message.event.event_data.exec.process_pid);
                break;
            case PROC_EVENT_EXIT: // proc_event::what::PROC_EVENT_EXIT
                _processTree->AddPnExitQueue(message.event.event_data.exit.process_pid);
                break;
        }
    }
}

void ProcessTree::AddPnForkQueue(int pid, int ppid)
{
    struct ProcessQueueItem p = {ProcessQueueFork, ProcessTreeSource_pnotify, pid, ppid};
    std::unique_lock<std::mutex> queue_lock(_queue_mutex);
    _PnQueue.push(p);
    _queue_data.notify_one();
}

void ProcessTree::AddPnExecQueue(int pid)
{
    struct ProcessQueueItem p = {ProcessQueueExec, ProcessTreeSource_pnotify, pid};
    std::unique_lock<std::mutex> queue_lock(_queue_mutex);
    _PnQueue.push(p);
    _queue_data.notify_one();
}

void ProcessTree::AddPnExitQueue(int pid)
{
    struct ProcessQueueItem p = {ProcessQueueExit, ProcessTreeSource_pnotify, pid};
    std::unique_lock<std::mutex> queue_lock(_queue_mutex);
    _PnQueue.push(p);
    _queue_data.notify_one();
}

void ProcessTree::on_stopping() {
    _queue_data.notify_all();
}

void ProcessTree::run()
{
    std::unique_lock<std::mutex> queue_lock(_queue_mutex);
    while (!IsStopping()) {
        _queue_data.wait(queue_lock, [&]{return !_PnQueue.empty() || IsStopping();});
        if (IsStopping()) {
            return;
        }
        while (!_PnQueue.empty()) {
            struct ProcessQueueItem p = _PnQueue.front();
            _PnQueue.pop();
            queue_lock.unlock();
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
            queue_lock.lock();
        }
        queue_lock.unlock();

        // Check if it's time for routine pruning of stale pids
        std::chrono::duration<double> elapsed_seconds = std::chrono::system_clock::now() - _last_clean_time;
        if (elapsed_seconds.count() > CLEAN_PROCESS_INTERVAL) {
            Clean();
            _last_clean_time = std::chrono::system_clock::now();
        }
        queue_lock.lock();
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
            auto parent = _processes[ppid];
            process->_uid = parent->_uid;
            process->_gid = parent->_gid;
            process->_exe = parent->_exe;
            process->_cmdline = parent->_cmdline;
            process->_containerid = parent->_containerid;
            process->_exec_propagation = parent->_exec_propagation;
            parent->_children.emplace_back(pid);
            process->_ancestors = parent->_ancestors;
            struct Ancestor anc = {ppid, parent->_exe};
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
            _processes[pid]->_exec_propagation += 1;
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
std::shared_ptr<ProcessTreeItem> ProcessTree::AddProcess(enum ProcessTreeSource source, int pid, int ppid, int uid, int gid, const std::string& exe, const std::string &cmdline)
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
    std::shared_ptr<ProcessTreeItem> process;

    std::string containerid = ExtractContainerId(exe, cmdline);

    auto it = _processes.find(pid);
    if (it != _processes.end()) {
        process = it->second;
        {
            std::lock_guard<std::mutex> _lock(process->_mutex);
            process->_source = source;
            process->_uid = uid;
            process->_gid = gid;
            process->_exe = exe;
            process->_cmdline = cmdline;
            process->_containeridfromhostprocess = containerid;
        }
        if (ppid != process->_ppid) {
            auto it2 = _processes.find(process->_ppid);
            if (it2 != _processes.end()) {
                auto oldparent = it2->second;
                auto e = std::find(oldparent->_children.begin(), oldparent->_children.end(), pid);
                if (e != oldparent->_children.end()) {
                    oldparent->_children.erase(e);
                }
            }
            it2 = _processes.find(ppid);
            if (it2 != _processes.end()) {
                auto parentproc = it2->second;
                parentproc->_children.emplace_back(pid);
                {
                    std::lock_guard<std::mutex> _lock(process->_mutex);
                    if (!(parentproc->_containeridfromhostprocess).empty()) {
                        process->_containerid = parentproc->_containeridfromhostprocess;
                    } else {
                        process->_containerid = parentproc->_containerid;
                    }
                }
                process->_ancestors = parentproc->_ancestors;
                struct Ancestor anc = {ppid, parentproc->_exe};
                process->_ancestors.emplace_back(anc);
            }
            process->_ppid = ppid;
        }
        if (process->_exec_propagation > 0) {
            process->_exec_propagation = process->_exec_propagation - 1;
        }
        for (auto c : process->_children) {
            auto it2 = _processes.find(c);
            if (it2 != _processes.end()) {
                auto p = it2->second;
                if (p->_exec_propagation > 0) {
                    {
                        std::lock_guard<std::mutex> _lock(process->_mutex);
                        p->_source = source;
                        p->_exe = exe;
                        p->_cmdline = cmdline;
                        p->_uid = uid;
                        p->_gid = gid;
                        if (!(process->_containeridfromhostprocess).empty()) {
                            p->_containerid = process->_containeridfromhostprocess;
                        } else {
                            p->_containerid = process->_containerid;
                        }
                    }
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
        auto it2 = _processes.find(ppid);
        if (it2 != _processes.end()) {
            auto parentproc = it2->second;
            parentproc->_children.emplace_back(pid);
            {
                std::lock_guard<std::mutex> _lock(process->_mutex);
                if (!(parentproc->_containeridfromhostprocess).empty()) {
                    process->_containerid = parentproc->_containeridfromhostprocess;
                } else {
                    process->_containeridfromhostprocess = containerid;
                    process->_containerid = parentproc->_containerid;
                }
            }
            process->_ancestors = parentproc->_ancestors;
            struct Ancestor anc = {ppid, parentproc->_exe};
            process->_ancestors.emplace_back(anc);
        }
        ApplyFlags(process);
        _processes[pid] = process;
    }
    
    // The purpose of extracting the container ID from cgroup is to accurately identify
    // the container in which a process is running. This is particularly important for
    // monitoring and logging purposes in containerized environments, where applications
    // are packaged and run in containers. By testing the extraction logic with various
    // cgroup formats, we aim to ensure that the container ID is correctly identified in
    // all scenarios.
    // This method complements the existing logic that extracts the container ID from the
    // command line arguments by providing an additional, more reliable source of information.
    // This is especially relevant when the container ID is not found through the existing
    // logic, which can happen when there is no parent process or when the parent process
    // does not have the container ID set. This situation can occur in various scenarios,
    // such as when a process is the root process of a container or when the process is
    // started by a web service or another system service that does not pass the container
    // ID through the command line arguments.
    if (process->_containerid.empty()) {
        auto p_temp = ReadProcEntry(pid);
        if (p_temp) {
            process->_containerid = p_temp->_cgroupContainerId;
        }
    }

    return process;
}

/* Process exit event from pnotify (exit)
*/
void ProcessTree::RemovePid(int pid)
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
    auto it = _processes.find(pid);
    if (it != _processes.end()) {
        auto process = it->second;
        process->_exit_time = std::chrono::system_clock::now();
        process->_exited = true;
    }
}

bool proc_is_gone(pid_t pid) {
    struct stat st;
    char buf[128];

    sprintf(buf, "/proc/%d", pid);

    auto ret = stat(buf, &st);
    if (ret == 0) {
        return false;
    }
    return true;
}

void ProcessTree::Clean()
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);

    for (auto element = _processes.begin(); element != _processes.end();) {
        if (element->second->_exited || proc_is_gone(element->second->_pid)) {
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
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);
    auto it = _processes.find(pid);
    if (it != _processes.end() && it->second->_source != ProcessTreeSource_pnotify) {
        return it->second;
    } else {
        // process doesn't currently exist, or we only have rudimentary information for it, so add it
        auto process = ReadProcEntry(pid);
        if (process != nullptr) {
            auto it2 = _processes.find(process->_ppid);
            if (it2 != _processes.end()) {
                auto parentproc = it2->second;
                parentproc->_children.emplace_back(pid);
                if (!(parentproc->_containeridfromhostprocess).empty()) {
                    process->_containerid = parentproc->_containeridfromhostprocess;
                } else {
                    process->_containerid = parentproc->_containerid;
                }
                process->_ancestors = parentproc->_ancestors;
                struct Ancestor anc = {process->_ppid, parentproc->_exe};
                process->_ancestors.emplace_back(anc);
            }

            // If container ID is still empty, set it to be the cgroup container ID
            if (process->_containerid.empty()) {
                process->_containerid = process->_cgroupContainerId;                
            }

            _processes[pid] = process;
            ApplyFlags(process);
        }
        return process;
    }
}

void ProcessTree::ApplyFlags(const std::shared_ptr<ProcessTreeItem>& process)
{
    unsigned int height = 0;
    process->_flags = _filtersEngine->GetFlags(process, height);
    if (process->_flags.none()) {
        std::vector<struct Ancestor>::reverse_iterator rit = process->_ancestors.rbegin();
        for (; rit != process->_ancestors.rend() && process->_flags.none(); ++rit) {
            height++;
            auto it = _processes.find(rit->pid);
            if (it != _processes.end()) {
                process->_flags = _filtersEngine->GetFlags(it->second, height);
            }
        }
    }
}

void ProcessTree::PopulateTree()
{
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);

    int pid;
    int ppid;
    int uid;
    int gid;
    std::string exe;
    std::string cmdline;

    auto pinfo = ProcessInfo::Open(CMDLINE_SIZE_LIMIT);
    if (!pinfo) {
        return;
    }

    while (pinfo->next()) {

        pid = pinfo->pid();
        ppid = pinfo->ppid();
        uid = pinfo->uid();
        gid = pinfo->gid();
        exe = pinfo->exe();
        pinfo->format_cmdline(cmdline);

        auto process = std::make_shared<ProcessTreeItem>(ProcessTreeSource_procfs, pid, ppid, uid, gid, exe, cmdline);
        process->_containeridfromhostprocess = ExtractContainerId(exe, cmdline);
        _processes[pid] = process;
    }

    for (auto& p : _processes) {
        auto process = p.second;
        auto it = _processes.find(process->_ppid);
        if (it != _processes.end()) {
            it->second->_children.emplace_back(process->_pid);
        }
    }

    for (auto& p : _processes) {
        std::shared_ptr<ProcessTreeItem> process, parent;
        process = p.second;
        auto it = _processes.find(process->_ppid);
        if (it != _processes.end()) {
            parent = it->second;
        } else {
            parent = nullptr;
        }
        while (parent) {
            process->_ancestors.insert(process->_ancestors.begin(), {parent->_pid, parent->_exe});
            auto it2 = _processes.find(parent->_ppid);
            if (it2 != _processes.end()) {
                parent = it2->second;
            } else {
                parent = nullptr;
            }
        }
    }
     // Populate containerid
    for (auto& p : _processes) {
        auto process = p.second;
        if( !(process->_containeridfromhostprocess).empty()) {
            SetContainerId(process, process->_containeridfromhostprocess);
        }
    }
}

void ProcessTree::UpdateFlags() {
    std::unique_lock<std::mutex> process_write_lock(_process_write_mutex);

    for (auto& p : _processes) {
        ApplyFlags(p.second);
    }
}

// This utility method gets called only during the initial population of ProcessTree when a containerid shim process is identfied with non-empty value of _containeridfromhostprocess.
// All of its childrens get assigned with the ContainerId value recursively.
// ContainerId is not set for the containerid shim process.
void ProcessTree::SetContainerId(const std::shared_ptr<ProcessTreeItem>& p, const std::string& containerid)
{
    for (auto c : p->_children) {
        auto it2 = _processes.find(c);
        if (it2 != _processes.end()) {
            auto cp = it2->second;
            cp->_containerid = containerid;
            SetContainerId(cp, containerid);
        }
    }
}

std::string ProcessTree::ExtractContainerId(const std::string& exe, const std::string& cmdline)
{
    // cmdline example: 
    //containerd-shim -namespace moby 
    //-workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/ebe83cd204c57dc745ce21b595e6aaabf805dc4046024e8eacb84633d2461ec1 
    //-address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
    // OR ...
    // /usr/bin/containerd-shim-runc-v2 -namespace moby -id 6d8e2e01f3bb36fe420e0515066e1b6e0e44f7198e3fbc563a46396f75939b5e -address /run/containerd/containerd.sock

    std::string containerid = "";   
    if (ends_with(exe, "/containerd-shim") || ends_with(exe, "/docker-containerd-shim")) {
        std::string workdirarg = " -workdir ";
        auto idx = cmdline.find(workdirarg);
        if (idx != std::string::npos) {
            auto argstart = cmdline.find_first_not_of(' ', idx + workdirarg.length());
            auto argend = cmdline.find_first_of(' ', argstart);
            if (argend == std::string::npos) {
                argend = cmdline.length() - 1;
            }
            std::string argvalue = cmdline.substr(argstart, (argend - argstart));
            auto containerididx = argvalue.find_last_of("/");
            if (containerididx != std::string::npos && containerididx+13 < argvalue.length()) {
                containerid = argvalue.substr(containerididx+1, 12);
            }
        }
    } else if (ends_with(exe, "/containerd-shim-runc-v1") || ends_with(exe, "/containerd-shim-runc-v2")) {
        std::string idarg = "-id ";
        auto idx = cmdline.find(idarg);
        if (idx != std::string::npos) {
            auto containerididx = cmdline.find_first_not_of(' ', idx + idarg.length());
            if (containerididx != std::string::npos && containerididx + 13 < cmdline.length()) {
                containerid = cmdline.substr(containerididx, 12);
            }
        }
    }
    return containerid;
}

std::shared_ptr<ProcessTreeItem> ProcessTree::ReadProcEntry(int pid)
{
    std::shared_ptr<ProcessTreeItem> process = std::make_shared<ProcessTreeItem>(ProcessTreeSource_procfs, pid);

    auto pinfo = ProcessInfo::OpenPid(pid, CMDLINE_SIZE_LIMIT);
    if (!pinfo) {
        return nullptr;
    }

    process->_uid = pinfo->uid();
    process->_gid = pinfo->gid();
    process->_ppid = pinfo->ppid();
    process->_exe = pinfo->exe();
    process->_cgroupContainerId = pinfo->container_id();
    pinfo->format_cmdline(process->_cmdline);
    process->_containeridfromhostprocess = ExtractContainerId(process->_exe, process->_cmdline);
    return process;
}


void ProcessTree::ShowTree()
{
    for (auto& p : _processes) {
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


