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
#include <functional>

class QueueMetrics {
public:
    QueueMetrics(const std::shared_ptr<Metrics>& metrics, const std::string& nsname, const std::string& name_prefix) {
        _num_items_added_metric = metrics->AddMetric(MetricType::METRIC_FROM_TOTAL, nsname, name_prefix + "num_items_added", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _bytes_fs_metric = metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, name_prefix + "bytes_fs", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _bytes_mem_metric = metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, name_prefix + "bytes_mem", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _bytes_unsaved_metric = metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, name_prefix + "bytes_unsaved", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _bytes_dropped_metric = metrics->AddMetric(MetricType::METRIC_FROM_TOTAL, nsname, name_prefix + "bytes_dropped", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _bytes_written_metric = metrics->AddMetric(MetricType::METRIC_FROM_TOTAL, nsname, name_prefix + "bytes_written", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

    void Update(PriorityQueueStats::Stats& stat) {
        _num_items_added_metric->Update(static_cast<double>(stat._num_items_added));
        _bytes_fs_metric->Update(static_cast<double>(stat._bytes_fs));
        _bytes_mem_metric->Update(static_cast<double>(stat._bytes_mem));
        _bytes_unsaved_metric->Update(static_cast<double>(stat._bytes_unsaved));
        _bytes_dropped_metric->Update(static_cast<double>(stat._bytes_dropped));
        _bytes_written_metric->Update(static_cast<double>(stat._bytes_written));
    }

private:
    std::shared_ptr<Metric> _num_items_added_metric;
    std::shared_ptr<Metric> _bytes_fs_metric;
    std::shared_ptr<Metric> _bytes_mem_metric;
    std::shared_ptr<Metric> _bytes_unsaved_metric;
    std::shared_ptr<Metric> _bytes_dropped_metric;
    std::shared_ptr<Metric> _bytes_written_metric;
};

class ProcMetrics: public RunBase {
public:
    ProcMetrics(const std::string& nsname, const std::shared_ptr<PriorityQueue>& queue, const std::shared_ptr<Metrics>& metrics, uint64_t rss_limit, uint64_t virt_limit, double rss_pct_limit, std::function<void()> limit_fn)
    : _queue(queue), _metrics(metrics), _rss_limit(rss_limit), _virt_limit(virt_limit), _rss_pct_limit(rss_pct_limit), _limit_fn(std::move(limit_fn)), _total_system_memory(0), _page_size(0), _clock(0),
      _queue_total_metrics(metrics, nsname, "queue.total.")
    {
        _cpu_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, "%cpu", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _mem_pct_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, "%mem", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _rss_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, "rss", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _virt_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, "virt", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _read_bytes_metric = _metrics->AddMetric(MetricType::METRIC_FROM_TOTAL, nsname, "io.read_bytes", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _write_bytes_metric = _metrics->AddMetric(MetricType::METRIC_FROM_TOTAL, nsname, "io.write_bytes", MetricPeriod::SECOND, MetricPeriod::HOUR);

        for (int p = 0; p < queue->NumPriorities(); ++p) {
            _queue_priority_metrics.emplace_back(metrics, nsname, "queue." + std::to_string(p) + ".");
        }

        _fs_size_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, "fs_size", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _fs_free_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, "fs_free", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _queue_fs_allowed_bytes_metric = _metrics->AddMetric(MetricType::METRIC_BY_FILL, nsname, "queue.fs_allowed_bytes", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

protected:
    void run() override;

private:
    bool collect_metrics();

    std::shared_ptr<PriorityQueue> _queue;
    std::shared_ptr<Metrics> _metrics;
    uint64_t _rss_limit;
    uint64_t _virt_limit;
    double _rss_pct_limit;
    std::function<void()> _limit_fn;
    uint64_t _total_system_memory;
    long _page_size;
    clock_t _clock;
    std::shared_ptr<Metric> _cpu_metric;
    std::shared_ptr<Metric> _mem_pct_metric;
    std::shared_ptr<Metric> _rss_metric;
    std::shared_ptr<Metric> _virt_metric;
    std::shared_ptr<Metric> _read_bytes_metric;
    std::shared_ptr<Metric> _write_bytes_metric;

    std::vector<QueueMetrics> _queue_priority_metrics;
    QueueMetrics _queue_total_metrics;

    std::shared_ptr<Metric> _fs_size_metric;
    std::shared_ptr<Metric> _fs_free_metric;
    std::shared_ptr<Metric> _queue_fs_allowed_bytes_metric;
};


#endif //AUOMS_PROCMETRICS_H
