/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "ProcMetrics.h"
#include "Logger.h"
#include "FileUtils.h"

#include <unistd.h>
#include <sys/sysinfo.h>
#include <cstring>

void ProcMetrics::run() {
    Logger::Warn("ProcMetrics: starting");

    // Collect process metrics once per second without drift
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

bool ProcMetrics::collect_metrics() {
    if (_total_system_memory == 0) {
        struct sysinfo si;
        auto ret = sysinfo(&si);
        if (ret != 0) {
            Logger::Error("ProcMetrics: sysinfo() failed: %s", std::strerror(errno));
            return false;
        }
        _total_system_memory = static_cast<uint64_t>(si.totalram) * si.mem_unit;
    }

    if (_page_size == 0) {
        _page_size = sysconf(_SC_PAGESIZE);
    }

    if (_clock == 0) {
        _clock = std::clock();
        return true;
    }

    auto clock = std::clock();
    auto used = clock-_clock;
    _clock = clock;

    auto cpu_pct = (static_cast<double>(used)/static_cast<double>(CLOCKS_PER_SEC))*100.0;

    if (!_cpu_metric) {
        _cpu_metric = _metrics->AddMetric(_nsname, "%cpu", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

    _cpu_metric->Set(cpu_pct);

    uint64_t total, resident, shared, text, unused1, data, unused2;
    resident = 0;
    try {
        auto lines = ReadFile("/proc/self/statm");
        if (!lines.empty()) {
            if (std::sscanf(lines[0].c_str(), "%lu %lu %lu %lu %lu %lu %lu", &total, &resident, &shared, &text, &unused1, &data, &unused2) != 7) {
                Logger::Error("Failed to parse /proc/self/statm");
                return false;
            }
        }
    } catch (std::exception& ex) {
        Logger::Error("Failed to read /proc/self/statm: %s", ex.what());
        return false;
    }

    if (!_mem_pct_metric) {
        _mem_pct_metric = _metrics->AddMetric(_nsname, "%mem", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

    if (!_rss_metric) {
        _rss_metric = _metrics->AddMetric(_nsname, "rss", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

    if (!_virt_metric) {
        _virt_metric = _metrics->AddMetric(_nsname, "virt", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

    auto mem_pct = (static_cast<double>(resident*_page_size)/static_cast<double>(_total_system_memory))*100.0;
    uint64_t rss = resident*_page_size;
    uint64_t virt = total*_page_size;

    if (rss > _rss_limit) {
        Logger::Error("RSS Limit (%ld) exceeded (%ld)", _rss_limit, rss);
        exit(1);
    }

    if (virt > _virt_limit) {
        Logger::Error("Virt Limit (%ld) exceeded (%ld)", _virt_limit, virt);
        exit(1);
    }

    _mem_pct_metric->Set(mem_pct);
    _rss_metric->Set(static_cast<double>(rss));
    _virt_metric->Set(static_cast<double>(virt));

    return true;
}
