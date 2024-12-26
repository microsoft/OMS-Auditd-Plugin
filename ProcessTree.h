/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_PROCESSTREE_H
#define AUOMS_PROCESSTREE_H

#include "RunBase.h"
#include "UserDB.h"
#include "ProcessDefines.h"
#include "FiltersEngine.h"

#include <string>
#include <unordered_map>
#include <queue>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <bits/stdc++.h>

/*

    Init
        Read app procs
        Apply filter to each proc
        Propogate filter results to child processes

    Add Pid
        Read proc into
        Apply filter to proc
        Propogate filter results from parent

    ProcInfo
        Trigger (execve, pnotify_fork, pnotify_exec)
        Origin (audit, procfs)
        pid
        ppid
        starttime
        parent_starttime
        containerid
        filterflags

    ProcTree
        std::unordered_map<pid_t, std::shared_ptr<ProcInfo>> proc_tree

    AddForkPid(pid_t pid, pid_t ppid)
        Lock(new_pids_lock)
        Add pid to new_pids
        Notify condition

    AddExecve(pid_t pid, pid_t ppid, exe, cmdline)
        Lock(mutex)

    addForkPid(pid, ppid)
        pp = getProc(ppid, 0)
        p = getProcFromProcFS(pid)
        p->parent = pp
        if p->parent
            copy containerid and filter state from parent
        if p->notfiltered
            filterProc(p)

    addExecPid(pid)
        p = getProc(pid, 0)

    addProc(uid, gid, pid, ppid, exe, cmdline)
        pi = proc_tree.find(pid)
        if pi == null
            pi = new ProcInfo
        pi->Set(uid, gif, pid, ppid, exe, cmdline)

    getProcFromProcFS(pid)
        p = new ProcInfo
        read to p
        filterProc(p)
        return p

    getProc(pid, nestcount)
        if nestcount > 10
            return nullptr
        nestcount++;
        ProcInfo *p
        pi = proc_tree.find(pid)
        if pi == null
            p = getProcFromProcFS(pid)
            proc_tree[pid] = p
        else
            p = pi->second
        if !(p->parent)
            p->parent = getProc(pid, nestcount)
        if p->parent
            copy containerid and filter state from parent
        if p->notfiltered
            filterProc(p)
        return p

    pnotify_run()
        read from sock
            AddForkPid(pid, ppid)
            AddExecPid(pid)
            ExitPid(pid)

    run()


*/

enum ProcessTreeSource { ProcessTreeSource_execve, ProcessTreeSource_pnotify, ProcessTreeSource_procfs };

class FiltersEngine;

struct Ancestor {
    int pid;
    std::string exe;
};

class ProcessTree;

class ProcessTreeItem {
public:
    ProcessTreeItem(enum ProcessTreeSource source, int pid, int ppid=0):
        _source(source), _pid(pid), _ppid(ppid), _uid(-1), _gid(-1), _flags(0), _exec_propagation(0), _exited(false), _containerid("") {}
    ProcessTreeItem(enum ProcessTreeSource source, int pid, int ppid, int uid, int gid, const std::string& exe, const std::string& cmdline):
        _source(source), _pid(pid), _ppid(ppid), _uid(uid), _gid(gid), _exe(exe), _cmdline(cmdline), _containerid(""),
        _flags(0), _exec_propagation(0), _exited(false) {}

    inline int pid() { return _pid; }
    inline int ppid() { return _ppid; }
    inline int uid() { return _uid; }
    inline int gid() { return _gid; }

    inline std::string exe() {
        std::lock_guard<std::mutex> _lock(_mutex);
        return _exe;
    }

    inline std::string cmdline() {
        std::lock_guard<std::mutex> _lock(_mutex);
        return _cmdline;
    }

    inline std::string containerid() {
        std::lock_guard<std::mutex> _lock(_mutex);
        return _containerid;
    }

    inline std::bitset<FILTER_BITSET_SIZE> flags() {
        std::lock_guard<std::mutex> _lock(_mutex);
        return _flags;
    }

protected:
    friend class ProcessTree;
    std::mutex _mutex;
    enum ProcessTreeSource _source;
    int _pid;
    int _ppid;
    int _uid;
    int _gid;
    std::vector<int> _children;
    std::vector<struct Ancestor> _ancestors;
    unsigned int _exec_propagation;
    std::string _exe;
    std::string _containerid;
    std::string _containeridfromhostprocess;
    std::string _cgroupContainerId;
    std::string _cmdline;
    std::bitset<FILTER_BITSET_SIZE> _flags;
    bool _exited;
    std::chrono::system_clock::time_point _exit_time;
};

// Class that monitors pnotify events and writes them to ProcessTree queues
class ProcessNotify: public RunBase {
public:
    ProcessNotify(std::shared_ptr<ProcessTree> processTree): _processTree(processTree), _proc_socket(-1) {}

protected:
    void on_stopping() override;
    void run() override;

private:
    bool InitProcSocket();

    std::shared_ptr<ProcessTree> _processTree;
    int _proc_socket;
};

enum ProcessQueueType { ProcessQueueFork, ProcessQueueExec, ProcessQueueExit };

struct ProcessQueueItem {
    enum ProcessQueueType type;
    enum ProcessTreeSource source;
    int pid;
    int ppid;
};

// Class that manages the process tree
class ProcessTree: public RunBase {
public:
    ProcessTree(const std::shared_ptr<UserDB>& user_db, std::shared_ptr<FiltersEngine> filtersEngine): _user_db(user_db), _filtersEngine(filtersEngine), _queue_data_ready(false)
    {
        _last_clean_time = std::chrono::system_clock::now();
    }

    void AddPnForkQueue(int pid, int ppid);
    void AddPnExecQueue(int pid);
    void AddPnExitQueue(int pid);
    std::shared_ptr<ProcessTreeItem> AddProcess(enum ProcessTreeSource source, int pid, int ppid, int uid, int gid, const std::string& exe, const std::string& cmdline);
    void Clean();
    std::shared_ptr<ProcessTreeItem> GetInfoForPid(int pid);
    void PopulateTree();
    void UpdateFlags();
    void ShowTree();
    void ShowProcess(std::shared_ptr<ProcessTreeItem> p);
    static std::string ExtractContainerId(const std::string& exe, const std::string& cmdline);


protected:
    void on_stopping() override;
    void run() override;

private:
    void AddPid(int pid, int ppid);
    void AddPid(int pid);
    void RemovePid(int pid);
    std::shared_ptr<ProcessTreeItem> ReadProcEntry(int pid);
    void ApplyFlags(const std::shared_ptr<ProcessTreeItem>& process);
    void SetContainerId(const std::shared_ptr<ProcessTreeItem>& p, const std::string& containerid);

    std::shared_ptr<UserDB> _user_db;
    std::shared_ptr<FiltersEngine> _filtersEngine;
    std::unordered_map<int, std::shared_ptr<ProcessTreeItem>> _processes;
    bool _queue_data_ready;
    std::mutex _queue_mutex;
    std::mutex _process_write_mutex;
    std::condition_variable _queue_data;
    std::queue<struct ProcessQueueItem> _PnQueue;
    std::chrono::system_clock::time_point _last_clean_time;
};

#endif //AUOMS_PROCESSTREE_H
