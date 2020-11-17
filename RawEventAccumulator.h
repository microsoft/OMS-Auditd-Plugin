/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_EVENTACCUMULATOR_H
#define AUOMS_EVENTACCUMULATOR_H

#include "RawEventRecord.h"
#include "Metrics.h"
#include "Cache.h"

#include <mutex>

class RawEvent {
public:
    static constexpr size_t MAX_EVENT_SIZE = 112*1024; // Prevent runaway accumulation of records for an event
    static constexpr size_t MAX_EXECVE_ACCUM_SIZE = 96*1024; // Prevent runaway accumulation of records for an event
    static constexpr size_t MAX_NUM_EXECVE_RECORDS = 12; // Make sure there will be room in event for PATH/CWD records that follow EXECVE records.
    static constexpr size_t NUM_EXECVE_RH_PRESERVE = 3;

    RawEvent() = delete;
    explicit RawEvent(EventId event_id): _event_id(event_id), _num_execve_records(0), _num_dropped_records(0), _syscall_rec_idx(-1), _size(0), _execve_size(0) {}

    inline EventId GetEventId() { return _event_id; }

    // Returns true if the event is now complete;
    bool AddRecord(std::unique_ptr<RawEventRecord> record);

    int AddEvent(EventBuilder& builder);

private:
    EventId _event_id;
    std::vector<std::unique_ptr<RawEventRecord>> _records;
    std::vector<std::unique_ptr<RawEventRecord>> _execve_records;
    std::unordered_map<RecordType, int> _drop_count;
    int _num_execve_records;
    int _num_dropped_records;
    int _syscall_rec_idx;
    size_t _size;
    size_t _execve_size;
};

class RawEventAccumulator {
public:
    explicit RawEventAccumulator(const std::shared_ptr<EventBuilder>& builder, const std::shared_ptr<Metrics>& metrics): _builder(builder), _metrics(metrics) {
        _bytes_metric = _metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "raw_data", "bytes", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _record_metric = _metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "raw_data", "records", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _event_metric = _metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "raw_data", "events", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _dropped_event_metric = _metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "raw_data", "dropped_events", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

    bool AddRecord(std::unique_ptr<RawEventRecord> record);
    void Flush(long milliseconds);

private:
    static constexpr size_t MAX_CACHE_ENTRY = 256;
    std::mutex _mutex;
    std::shared_ptr<EventBuilder> _builder;
    std::shared_ptr<Metrics> _metrics;
    std::shared_ptr<Metric> _bytes_metric;
    std::shared_ptr<Metric> _record_metric;
    std::shared_ptr<Metric> _event_metric;
    std::shared_ptr<Metric> _dropped_event_metric;
    Cache<EventId, std::shared_ptr<RawEvent>> _events;
};


#endif //AUOMS_EVENTACCUMULATOR_H
