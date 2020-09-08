/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "SystemMetrics.h"
#include "Logger.h"
#include "FileUtils.h"
#include "StringUtils.h"

void SystemMetrics::run() {
    Logger::Info("SystemMetrics: starting");

    _cpu_pct_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, "SYSTEM", "%cpu", MetricPeriod::SECOND, MetricPeriod::HOUR);
    _num_cpu_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, "SYSTEM", "num_cpu", MetricPeriod::SECOND, MetricPeriod::HOUR);
    _total_mem_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, "SYSTEM", "total_mem", MetricPeriod::SECOND, MetricPeriod::HOUR);
    _free_mem_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, "SYSTEM", "free_mem", MetricPeriod::SECOND, MetricPeriod::HOUR);


    // Collect process metrics once per minute without drift
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
    Logger::Info("SystemMetrics: stopping");
}

bool read_proc_stat(uint64_t *cpu_user, uint64_t *cpu_user_nice, uint64_t *cpu_system, uint64_t *cpu_idle, uint32_t *num_cpu) {
    *cpu_user = 0;
    *cpu_user_nice = 0;
    *cpu_system = 0;
    *cpu_idle = 0;
    *num_cpu = 0;
    try {
        auto lines = ReadFile("/proc/stat");
        if (lines.empty()) {
            return false;
        }
        if (!starts_with(lines[0], "cpu ")) {
            return false;
        }
        if (std::sscanf(lines[0].c_str(), "cpu %ld %ld %ld %ld", cpu_user, cpu_user_nice, cpu_system, cpu_idle) != 4) {
            return false;
        }
        for (auto& line :lines) {
            if (starts_with(line, "cpu") && line[3] >= '0' && line[3] <= '9') {
                *num_cpu += 1;
            }
        }
    } catch (std::exception&) {
        return false;
    }
    return true;
}

bool read_proc_meminfo(uint64_t *total_mem, uint64_t *free_mem) {
    try {
        auto lines = ReadFile("/proc/meminfo");
        if (lines.empty()) {
            return false;
        }
        *total_mem = 0;
        *free_mem = 0;
        bool found_total = false;
        bool found_free = false;
        for (auto& line :lines) {
            if (starts_with(line, "MemTotal:")) {
                *total_mem = std::stoul(line.substr(9));
                *total_mem *= 1024;
                found_total = true;
                break;
            }
        }
        if (!found_total) {
            return false;
        }
        for (auto& line :lines) {
            if (starts_with(line, "MemFree:")) {
                *free_mem = std::stoul(line.substr(8));
                *free_mem *= 1024;
                found_free = true;
                break;
            }
        }
        if (!found_free) {
            return false;
        }
    } catch (std::exception&) {
        return false;
    }
    return true;
}

bool SystemMetrics::collect_metrics() {
    uint64_t cpu_user;
    uint64_t cpu_user_nice;
    uint64_t cpu_system;
    uint64_t cpu_idle;
    uint32_t num_cpu;

    if (read_proc_stat(&cpu_user, &cpu_user_nice, &cpu_system, &cpu_idle, &num_cpu)) {
        if (_cpu_system != 0) {
            auto old_used = _cpu_user + _cpu_user_nice + _cpu_system;
            auto new_used = cpu_user + cpu_user_nice + cpu_system;
            auto old_total = old_used+_cpu_idle;
            auto new_total = new_used+cpu_idle;
            auto pct_cpu = (static_cast<double>(new_used-old_used)/static_cast<double>(new_total-old_total))*100;
            _cpu_pct_metric->Update(pct_cpu);
            _num_cpu_metric->Update(static_cast<double>(num_cpu));
        }
        _cpu_user = cpu_user;
        _cpu_user_nice = cpu_user_nice;
        _cpu_system = cpu_system;
        _cpu_idle = cpu_idle;
    }

    uint64_t total_mem;
    uint64_t free_mem;

    if (read_proc_meminfo(&total_mem, &free_mem)) {
        _total_mem_metric->Update(static_cast<double>(total_mem));
        _free_mem_metric->Update(static_cast<double>(free_mem));
    }

    return true;
}