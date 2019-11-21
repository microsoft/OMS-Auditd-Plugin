/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_METRICS_H
#define AUOMS_METRICS_H

#include "RunBase.h"
#include "EventQueue.h"
#include "Queue.h"
#include "Logger.h"

#include <atomic>
#include <mutex>
#include <chrono>
#include <list>
#include <limits>
#include <cmath>

enum class MetricPeriod: int {
    SECOND = 1000,
    MINUTE = 60000,
    HOUR = 3600000,
};

struct MetricAggregateSnapshot {
    std::string namespace_name;
    std::string name;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    uint64_t sample_period;
    uint64_t num_samples;
    double min;
    double max;
    double avg;
};

class MetricData {
public:
    MetricData(std::chrono::system_clock::time_point start_time, MetricPeriod sample_period, MetricPeriod agg_period):
        _start_time(start_time), _sample_period(sample_period), _agg_period(agg_period), _counts() {
        if (static_cast<long>(agg_period) < static_cast<long>(sample_period)) {
            _agg_period = _sample_period;
        }
        _counts.resize(static_cast<long>(_agg_period)/static_cast<long>(_sample_period), 0.0);
    }

    std::chrono::system_clock::time_point _start_time;
    MetricPeriod _sample_period;
    MetricPeriod _agg_period;
    std::vector<double> _counts;
};

class Metric {
public:
    Metric(const std::string namespace_name, const std::string name, MetricPeriod sample_period, MetricPeriod agg_period):
        _nsname(namespace_name), _name(name), _sample_period(sample_period), _agg_period(agg_period), _data() {

        // We need the stead_clock for calculating where in the sample period we are
        // but we need the system_clock to report the metrict start/end times.
        // We cannot convert between system_clock and steady_clock
        // so we get both, and keep trying until the delta between the two is small enough
        // most of the time the delta will be very small, but it is possible for the thread
        // to get delayed between s1 and t or between t and s2 due to the scheduler.
        std::chrono::steady_clock::time_point s1, s2;
        std::chrono::system_clock::time_point t;
        do {
            s1 = std::chrono::steady_clock::now();
            t = std::chrono::system_clock::now();
            s2 = std::chrono::steady_clock::now();
        } while (std::chrono::duration_cast<std::chrono::milliseconds>(s2-s1).count() > 2);
        _agg_start_time = t;
        _agg_start_steady = s1;
        _agg_period_size = std::chrono::milliseconds(static_cast<long>(_agg_period));
        _current_data = std::make_shared<MetricData>(_agg_start_time, _sample_period, _agg_period);
    }

    void Add(double count) {
        std::lock_guard<std::mutex> lock(_mutex);
        auto idx = GetCountsIdx();
        _current_data->_counts.at(idx) += count;
    }

    void Set(double count) {
        std::lock_guard<std::mutex> lock(_mutex);
        auto idx = GetCountsIdx();
        _current_data->_counts.at(idx) = count;
    }

    bool GetAggregateSnapshot(MetricAggregateSnapshot *snap) {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_data.empty()) {
            return false;
        } else {
            auto data = _data.front();
            _data.pop_front();
            snap->namespace_name = _nsname;
            snap->name = _name;
            snap->start_time = data->_start_time;
            snap->end_time = data->_start_time + std::chrono::milliseconds(static_cast<long>(data->_agg_period));
            snap->sample_period = static_cast<uint64_t>(data->_sample_period);
            snap->num_samples = data->_counts.size();
            double div = static_cast<double>(snap->num_samples);
            double min = std::numeric_limits<double>::max();
            double max = std::numeric_limits<double>::min();
            double total = 0;
            for (auto c : data->_counts) {
                if (min > c) {
                    min = c;
                }
                if ( max < c) {
                    max = c;
                }
                total += c/div;
            }
            snap->min = min;
            snap->max = max;
            snap->avg = total;
            return total > 0;
        }
    }

private:
    inline long GetCountsIdx() {
        auto now = std::chrono::steady_clock::now();
        auto idx = std::lround(static_cast<double>(std::chrono::duration_cast<std::chrono::milliseconds>(now-_agg_start_steady).count())/static_cast<double>(_sample_period));

        if (idx >= _current_data->_counts.size()) {
            auto nagg = idx / _current_data->_counts.size();
            auto inc = _agg_period_size * nagg;
            _agg_start_time += std::chrono::duration_cast<std::chrono::system_clock::time_point::duration>(inc);
            _agg_start_steady += std::chrono::duration_cast<std::chrono::steady_clock::time_point::duration>(inc);
            idx -= nagg * _current_data->_counts.size();
            _data.emplace_back(_current_data);
            _current_data = std::make_shared<MetricData>(_agg_start_time, _sample_period, _agg_period);
        }

        return idx;
    }

    std::string _nsname;
    std::string _name;
    MetricPeriod _sample_period;
    MetricPeriod _agg_period;
    std::chrono::milliseconds _agg_period_size;

    std::mutex _mutex;
    std::chrono::system_clock::time_point _agg_start_time;
    std::chrono::steady_clock::time_point _agg_start_steady;
    std::shared_ptr<MetricData> _current_data;
    std::list<std::shared_ptr<MetricData>> _data;
};

class Metrics: public RunBase {
public:
    explicit Metrics(std::shared_ptr<EventBuilder> builder): _builder(std::move(builder)) {}
    explicit Metrics(std::shared_ptr<Queue> queue): _builder(std::make_shared<EventBuilder>(std::make_shared<EventQueue>(std::move(queue)))) {}

    std::shared_ptr<Metric> AddMetric(const std::string namespace_name, const std::string name, MetricPeriod sample_period, MetricPeriod agg_period);

protected:
    void run() override;

private:
    bool send_metrics();

    std::shared_ptr<EventBuilder> _builder;
    std::mutex _mutex;
    std::unordered_map<std::string, std::shared_ptr<Metric>> _metrics;
};


#endif //AUOMS_METRICS_H
