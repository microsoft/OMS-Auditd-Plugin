/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "CPULimits.h"

#define CG_NAME_CONFIG_NAME "cpu_cgroup_name"

std::shared_ptr<CGroupCPU> CPULimits::CGFromConfig(const Config& config, const std::string& default_cg_name) {
    std::string cg_name = default_cg_name;
    double hard_limit = MAX_PCT;
    double soft_limit = MAX_PCT;

    if (config.HasKey(CPU_HARD_LIMIT_NAME)) {
        hard_limit = config.GetDouble(CPU_HARD_LIMIT_NAME);
    }

    if (hard_limit > MAX_PCT) {
        hard_limit = MAX_PCT;
    } else if (hard_limit < MIN_PCT) {
        hard_limit = MIN_PCT;
    }

    if (config.HasKey(CPU_SOFT_LIMIT_NAME)) {
        soft_limit = config.GetDouble(CPU_SOFT_LIMIT_NAME);
    }

    if (soft_limit > MAX_PCT) {
        soft_limit = MAX_PCT;
    } else if (soft_limit < MIN_PCT) {
        soft_limit = MIN_PCT;
    }


    if (config.HasKey(CG_NAME_CONFIG_NAME)) {
        cg_name = config.GetString(CG_NAME_CONFIG_NAME);
    }

    auto cg = CGroups::OpenCPU(cg_name);

    if (hard_limit < MAX_PCT && cg->HasCFSQuotaUS()) {
        uint64_t period = cg->GetCFSPeriodUS();
        uint64_t quota = static_cast<uint64_t>(static_cast<double>(period)*(hard_limit/100));
        cg->SetCFSQuotaUS(quota);
    }

    if (soft_limit < MAX_PCT) {
        uint64_t shares = static_cast<uint64_t>(static_cast<double>(1024)*(soft_limit/100));
        cg->SetShares(shares);
    }

    return cg;
}
