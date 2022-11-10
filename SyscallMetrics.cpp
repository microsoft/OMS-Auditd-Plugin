/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "SyscallMetrics.h"
#include "Logger.h"
#include "FileUtils.h"
#include "Defer.h"

#include <regex>
#include <unistd.h>
#include <cstring>
#include <sys/stat.h>
#include <iostream>

#define SYSCALL_METRICS_NAMESPACE_NAME "SYSCALL"
#define FTRACE_INSTANCE_DIR "/sys/kernel/debug/tracing/instances/auoms"
#define FTRACE_SYS_ENTER_TRIGGER "/sys/kernel/debug/tracing/instances/auoms/events/raw_syscalls/sys_enter/trigger"
#define FTRACE_SYS_ENTER_HIST "/sys/kernel/debug/tracing/instances/auoms/events/raw_syscalls/sys_enter/hist"
#define SYSCALL_HIST_TRIGGER "hist:key=id.syscall:val=hitcount"
#define SYSCALL_HIST_TRIGGER_CLEAR "hist:key=id.syscall:val=hitcount:clear"

// Lines like: { id: sys_recvmsg                   [ 47] } hitcount:      27076
const std::string SyscallMetrics::_hist_line_match_re = R"REGEX(^\{\s*id:\s*(\S+)\s*\[\s*([0-9]+)\s*\]\s*\}\s*hitcount:\s*([0-9]+))REGEX";

void SyscallMetrics::run() {
    Logger::Warn("SyscallMetrics: starting");

    Defer _cleanup([this](){ cleanup(); });

    if (!init()) {
        Logger::Warn("SyscallMetrics: initialization failed");
        return;
    }

    // Collect syscall metrics once per second without drift
    constexpr long frequency = 1000;
    auto next = std::chrono::steady_clock::now() + std::chrono::milliseconds(frequency);
    long sleep_duration = 0;
    do {
        if (!collect_metrics()) {
            return;
        }

        sleep_duration = std::chrono::duration_cast<std::chrono::milliseconds>(next - std::chrono::steady_clock::now()).count();
        next += std::chrono::milliseconds(frequency);
        if (sleep_duration < 0) {
            sleep_duration = 0;
        }
    } while (!_sleep(sleep_duration));
}

bool SyscallMetrics::init() {
    int ret = mkdir(FTRACE_INSTANCE_DIR, 0750);
    if (ret != 0 && errno != EEXIST) {
        Logger::Warn("SyscallMetrics: Failed to create ftrace instance dir (%s): %s", FTRACE_INSTANCE_DIR, std::strerror(errno));
        return false;
    }

    for (int i = 0; i < 5; ++i) {
        if (!PathExists(FTRACE_INSTANCE_DIR)) {
            Logger::Warn("SyscallMetrics: Waiting for ftrace instance dir (%s) to appear", FTRACE_INSTANCE_DIR);
            _sleep(1000);
        }
    }

    if (!PathExists(FTRACE_INSTANCE_DIR)) {
        Logger::Warn("SyscallMetrics: ftrace instance dir (%s) failed to appear even though mkdir succeeded", FTRACE_INSTANCE_DIR);
        return false;
    }

    if (!PathExists(FTRACE_SYS_ENTER_TRIGGER) || !PathExists(FTRACE_SYS_ENTER_HIST)) {
        Logger::Warn("SyscallMetrics: ftrace doesn't support hist trigger on this system, syscall metrics will not be collected");
        return false;
    }

    try {
        WriteFile(FTRACE_SYS_ENTER_TRIGGER, {{SYSCALL_HIST_TRIGGER}});
    } catch (std::exception &ex) {
        Logger::Warn("SyscallMetrics: Failed to write sys_enter trigger (%s): %s", FTRACE_SYS_ENTER_TRIGGER, ex.what());
        return false;
    }

    return true;
}

void SyscallMetrics::cleanup() {
    int ret = rmdir(FTRACE_INSTANCE_DIR);
    if (ret != 0 && errno != ENOENT) {
        Logger::Warn("SyscallMetrics: Failed to remove ftrace instance dir (%s): %s", FTRACE_INSTANCE_DIR, std::strerror(errno));
    }
}

// Lines like: { id: sys_recvmsg                   [ 47] } hitcount:      27076

// Return 1 if parsed, 0 if not match, -1 if error
int SyscallMetrics::parse_hist_line(const std::string line, uint32_t *id, std::string *name, uint64_t *count) {
    std::smatch m;
    if (!std::regex_search(line, m, _hist_line_re)) {
        return 0;
    } else {
        if (m.size() != 4 || !m[1].matched || !m[2].matched || !m[3].matched) {
            return -1;
        }
        try {
            *name = m[1].str();
            *id = std::stoul(m[2].str());
            *count = std::stoull(m[3].str());
        } catch (std::exception &ex ) {
            return -1;
        }
    }
    return 1;
}

bool SyscallMetrics::collect_metrics() {
    std::vector<std::string> lines;

    // Read hist
    try {
        lines = ReadFile(FTRACE_SYS_ENTER_HIST);
    } catch (std::exception &ex) {
        Logger::Warn("SyscallMetrics: Failed to read sys_enter hist (%s): %s", FTRACE_SYS_ENTER_HIST, ex.what());
        return false;
    }

    // Reset hist
    try {
        AppendFile(FTRACE_SYS_ENTER_TRIGGER, {{SYSCALL_HIST_TRIGGER_CLEAR}});
    } catch (std::exception &ex) {
        Logger::Warn("SyscallMetrics: Failed to write sys_enter trigger (%s): %s", FTRACE_SYS_ENTER_TRIGGER, ex.what());
        return false;
    }

    // Parse hist
    for (auto& line: lines) {
        uint32_t id = 0;
        uint64_t count = 0;
        std::string name;
        auto ret = parse_hist_line(line, &id, &name, &count);
        if (ret == 1) {
            auto it = _syscall_metrics.find(id);
            if (it == _syscall_metrics.end()) {
                auto metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, SYSCALL_METRICS_NAMESPACE_NAME, name, MetricPeriod::SECOND, MetricPeriod::HOUR);
                auto itr = _syscall_metrics.emplace(std::make_pair(id, metric));
                it = itr.first;
            }
            it->second->Update(static_cast<double>(count));
        }
    }

    return true;
}