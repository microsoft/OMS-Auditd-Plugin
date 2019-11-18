/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_SYSCALLMETRICS_H
#define AUOMS_SYSCALLMETRICS_H

#include "RunBase.h"
#include "Metrics.h"

#include <regex>

class SyscallMetrics: public RunBase {
public:
    SyscallMetrics(const std::shared_ptr<Metrics> metrics):
        _metrics(metrics), _hist_line_re(_hist_line_match_re, std::regex::ECMAScript|std::regex::optimize) {}

protected:
    void run() override;

private:
    static const std::string _hist_line_match_re;

    bool init();
    int parse_hist_line(const std::string line, uint32_t *id, std::string *name, uint64_t *count);
    bool collect_metrics();
    void cleanup();

    std::shared_ptr<Metrics> _metrics;
    std::regex _hist_line_re;
    std::unordered_map<uint32_t, std::shared_ptr<Metric>> _syscall_metrics;
};


#endif //AUOMS_SYSCALLMETRICS_H
