/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_CGROUPS_H
#define AUOMS_CGROUPS_H

#include <unordered_set>
#include <memory>

class CGroupCPU {
public:
    CGroupCPU(const std::string& path): _dir(path) {}

    void AddSelf();
    void AddSelfThread();
    void AddThread(long tid);

    std::unordered_set<uint64_t> GetProcs();
    std::unordered_set<uint64_t> GetTasks();

    uint64_t GetShares();
    void SetShares(uint64_t val);

    uint64_t GetCFSPeriodUS();
    void SetCFSPeriodUS(uint64_t val);

    bool HasCFSQuotaUS();
    uint64_t GetCFSQuotaUS();
    void SetCFSQuotaUS(uint64_t val);

private:
    std::string _dir;
};

class CGroups {
public:
    static std::shared_ptr<CGroupCPU> OpenCPU(const std::string& name);
    static long GetSelfThreadId();
};


#endif //AUOMS_CGROUPS_H
