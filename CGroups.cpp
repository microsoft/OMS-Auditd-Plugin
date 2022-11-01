/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdexcept>
#include "CGroups.h"
#include "FileUtils.h"
#include "StringUtils.h"

#include <system_error>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define CGROUP_CPU_ROOT "/sys/fs/cgroup/cpu,cpuacct"

#define CGROUP_PROCS_FILE "/cgroup.procs"
#define CGROUP_TASKS_FILE "/tasks"
#define CGROUP_CPU_SHARES_FILE "/cpu.shares"
#define CGROUP_CPU_QUOTA_US_FILE "/cpu.cfs_quota_us"
#define CGROUP_CPU_PERIOD_US_FILE "/cpu.cfs_period_us"

void AppendUint64(const std::string& path, uint64_t val) {
    AppendFile(path, {{std::to_string(val)}});
}

void WriteUint64(const std::string& path, uint64_t val) {
    WriteFile(path, {{std::to_string(val)}});
}

uint64_t ReadUint64(const std::string& path) {
    auto lines = ReadFile(path);
    if (lines.empty()) {
        throw std::runtime_error("Empty File");
    }
    auto line = trim_whitespace(lines[0]);
    return stoll(line);
}

void CGroupCPU::AddSelf() {
    auto self_pid = getpid();
    auto pids = GetProcs();
    if (pids.count(self_pid) == 0) {
        AppendUint64(_dir + CGROUP_PROCS_FILE, 0);
    }
}

void CGroupCPU::AddSelfThread() {
    auto tid = CGroups::GetSelfThreadId();
    AddThread(tid);
}

void CGroupCPU::AddThread(long tid) {
    auto tids = GetTasks();
    if (tids.count(tid) == 0) {
        AppendUint64(_dir + CGROUP_TASKS_FILE, tid);
    }
}

std::unordered_set<uint64_t> CGroupCPU::GetProcs() {
    auto lines = ReadFile(_dir + CGROUP_PROCS_FILE);
    std::unordered_set<uint64_t> pids;
    pids.reserve(lines.size());
    for (auto& line : lines) {
        pids.emplace(stoll(line));
    }
    return pids;
}

std::unordered_set<uint64_t> CGroupCPU::GetTasks() {
    auto lines = ReadFile(_dir + CGROUP_TASKS_FILE);
    std::unordered_set<uint64_t> tids;
    tids.reserve(lines.size());
    for (auto& line : lines) {
        tids.emplace(stoll(line));
    }
    return tids;
}

uint64_t CGroupCPU::GetShares() {
    return ReadUint64(_dir + CGROUP_CPU_SHARES_FILE);
}

void CGroupCPU::SetShares(uint64_t val) {
    WriteUint64(_dir + CGROUP_CPU_SHARES_FILE, val);
}

bool CGroupCPU::HasCFSQuotaUS() {
    return PathExists(_dir + CGROUP_CPU_PERIOD_US_FILE);
}

uint64_t CGroupCPU::GetCFSPeriodUS() {
    return ReadUint64(_dir + CGROUP_CPU_PERIOD_US_FILE);
}

void CGroupCPU::SetCFSPeriodUS(uint64_t val) {
    WriteUint64(_dir + CGROUP_CPU_PERIOD_US_FILE, val);
}

uint64_t CGroupCPU::GetCFSQuotaUS() {
    return ReadUint64(_dir + CGROUP_CPU_QUOTA_US_FILE);
}

void CGroupCPU::SetCFSQuotaUS(uint64_t val) {
    WriteUint64(_dir + CGROUP_CPU_QUOTA_US_FILE, val);
}

std::shared_ptr<CGroupCPU> CGroups::OpenCPU(const std::string& name) {
    if (!PathExists(CGROUP_CPU_ROOT)) {
        throw std::runtime_error(std::string("Cgroups mount is missing: ") + CGROUP_CPU_ROOT);
    }

    std::string path = CGROUP_CPU_ROOT;

    if (!name.empty() && name != "/") {
        path = std::string(CGROUP_CPU_ROOT) + "/" + name;
    }

    if (!PathExists(path)) {
        if (mkdir(path.c_str(), 0755) != 0) {
            throw std::system_error(errno, std::system_category(), "mkdir("+path+")");
        }
    }

    return std::make_shared<CGroupCPU>(path);
}

long CGroups::GetSelfThreadId() {
    return syscall(SYS_gettid);
}
