/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_PROCMETRICS_H
#define AUOMS_PROCMETRICS_H

#include "RunBase.h"
#include "Metrics.h"

#include <ctime>

class ProcMetrics: public RunBase {
public:
    ProcMetrics(const std::string& nsname, const std::shared_ptr<Metrics> metrics): _nsname(nsname), _metrics(metrics), _total_system_memory(0), _page_size(0), _clock(0) {}

protected:
    void run() override;

private:
    bool collect_metrics();

    std::string _nsname;
    std::shared_ptr<Metrics> _metrics;
    std::shared_ptr<Metric> _cpu_metric;
    std::shared_ptr<Metric> _mem_metric;
    uint64_t _total_system_memory;
    long _page_size;
    clock_t _clock;
};


#endif //AUOMS_PROCMETRICS_H
