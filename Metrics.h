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
#include "PriorityQueue.h"
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

enum class MetricType {
    METRIC_BY_ACCUMULATION,
    METRIC_BY_FILL,
    METRIC_FROM_TOTAL,
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
        _start_time(start_time), _sample_period(sample_period), _agg_period(agg_period), _counts(), _last_index(-1) {
        if (static_cast<long>(agg_period) < static_cast<long>(sample_period)) {
            _agg_period = _sample_period;
        }
        _counts.resize(static_cast<long>(_agg_period)/static_cast<long>(_sample_period), 0.0);
    }

    inline void Add(int idx, double value) {
        _counts.at(idx) += value;
        _last_index = idx;
    }

    inline void Set(int idx, double value) {
        _counts.at(idx) = value;
        _last_index = idx;
    }

    std::chrono::system_clock::time_point _start_time;
    MetricPeriod _sample_period;
    MetricPeriod _agg_period;
    std::vector<double> _counts;
    int _last_index;
};

class Metric {
public:
    Metric(const std::string& namespace_name, const std::string& name, MetricPeriod sample_period, MetricPeriod agg_period):
        _nsname(namespace_name), _name(name), _sample_period(sample_period), _agg_period(agg_period), _data() {

        // We need the stead_clock for calculating where in the sample period we are
        // but we need the system_clock to report the metric start/end times.
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

    virtual void Update(double value) = 0;

    bool GetAggregateSnapshot(MetricAggregateSnapshot *snap) {
        std::lock_guard<std::mutex> lock(_mutex);

        // The side effect of GetCountsIdx is that _current_data is pushed to _data if _current_data has "expired"
        // If _current_data has any values set (_last_index > -1) then call GetCountsIdx() just-in-case it has "expired".
        if (_current_data->_last_index > -1) {
            GetCountsIdx();
        }

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

protected:
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

// The update value is added to any previous value in the sample time slot
class AccumulatorMetric: public Metric {
public:
    AccumulatorMetric(const std::string& namespace_name, const std::string& name, MetricPeriod sample_period, MetricPeriod agg_period):
            Metric(namespace_name, name, sample_period, agg_period) {}

    void Update(double value) override {
        std::lock_guard<std::mutex> lock(_mutex);
        auto idx = GetCountsIdx();
        _current_data->Add(idx, value);
    }

};

// The update value replaces any previous sample time slot value
class FillMetric: public Metric {
public:
    FillMetric(const std::string& namespace_name, const std::string& name, MetricPeriod sample_period, MetricPeriod agg_period):
            Metric(namespace_name, name, sample_period, agg_period) {}

    void Update(double value) override {
        std::lock_guard<std::mutex> lock(_mutex);
        auto idx = GetCountsIdx();
        _current_data->Set(idx, value);
    }

};

/*
 * Some system metrics (e.g. /proc/self/io) only increase for the live of the process
 * Each update calculates the value delta and the value/sample_period.
 */
class MetricFromTotal: public Metric {
public:
    MetricFromTotal(const std::string& namespace_name, const std::string& name, MetricPeriod sample_period, MetricPeriod agg_period):
            Metric(namespace_name, name, sample_period, agg_period), _last_total(0.0), _last_total_index(-1) {}

    void Update(double value) override {
        std::lock_guard<std::mutex> lock(_mutex);
        auto idx = GetCountsIdx();
        if (_last_total_index >= 0 && value < _last_total) {
            auto subtotal = value - _last_total;
            auto sample_time =
                    _agg_start_steady + std::chrono::milliseconds(idx * static_cast<long>(_sample_period));
            auto last_sample_time = _last_total_time_steady + std::chrono::milliseconds(
                    _last_total_index * static_cast<long>(_sample_period));
            auto num_samples =
                    (sample_time - last_sample_time) / std::chrono::milliseconds(static_cast<long>(_sample_period));
            double part = 0.0;
            if (num_samples <= 1) {
                part = subtotal;
            } else {
                part = subtotal / static_cast<double>(num_samples);
            }

            for (auto i = _last_total_index + 1; i <= idx; i++) {
                _current_data->Set(i, part);
            }
        }
        _last_total = value;
        _last_total_index = idx;
        _last_total_time_steady = _agg_start_steady;
    }
private:
    double _last_total;
    long _last_total_index;
    std::chrono::steady_clock::time_point _last_total_time_steady;
};

class Metrics: public RunBase {
public:
    explicit Metrics(const std::string& proc_name, std::shared_ptr<EventBuilder> builder): _proc_name(proc_name), _builder(std::move(builder)) {}
    explicit Metrics(const std::string& proc_name, std::shared_ptr<PriorityQueue> queue): _proc_name(proc_name), _builder(std::make_shared<EventBuilder>(std::make_shared<EventQueue>(std::move(queue)), nullptr)) {}

    std::shared_ptr<Metric> AddMetric(MetricType metric_type, const std::string& namespace_name, const std::string& name, MetricPeriod sample_period, MetricPeriod agg_period);

    void FlushLogMetrics() { send_log_metrics(true); }
protected:
    void run() override;

private:
    bool send_metrics();
    bool send_log_metrics(bool flush_all);

    std::string _proc_name;
    std::shared_ptr<EventBuilder> _builder;
    std::mutex _mutex;
    std::unordered_map<std::string, std::shared_ptr<Metric>> _metrics;
};


#endif //AUOMS_METRICS_H
