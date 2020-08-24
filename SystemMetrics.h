/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_SYSTEMMETRICS_H
#define AUOMS_SYSTEMMETRICS_H

#include "RunBase.h"
#include "Metrics.h"

class SystemMetrics: public RunBase {
public:
    SystemMetrics(const std::shared_ptr<Metrics> metrics): _metrics(metrics), _cpu_user(0), _cpu_user_nice(0), _cpu_system(0), _cpu_idle(0) {}

protected:
    void run() override;

private:
    bool collect_metrics();


    std::shared_ptr<Metrics> _metrics;

    uint64_t _cpu_user;
    uint64_t _cpu_user_nice;
    uint64_t _cpu_system;
    uint64_t _cpu_idle;

    std::shared_ptr<Metric> _total_mem_metric;
    std::shared_ptr<Metric> _free_mem_metric;
    std::shared_ptr<Metric> _num_cpu_metric;
    std::shared_ptr<Metric> _cpu_pct_metric;
    std::shared_ptr<Metric> _disk_size;
    std::shared_ptr<Metric> _disk_free;
};


#endif //AUOMS_SYSTEMMETRICS_H
