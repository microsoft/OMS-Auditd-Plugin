/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Metrics.h"
#include "Logger.h"
#include "RecordType.h"
#include "Translate.h"
#include "auoms_version.h"

#include <sys/time.h>
#include <sstream>
#include <iomanip>

std::shared_ptr<Metric> Metrics::AddMetric(MetricType metric_type, const std::string& namespace_name, const std::string& name, MetricPeriod sample_period, MetricPeriod agg_period) {
    std::lock_guard<std::mutex> lock(_mutex);

    auto key = namespace_name + name;
    auto it = _metrics.find(key);
    if (it != _metrics.end()) {
        return it->second;
    } else {
        std::shared_ptr<Metric> metric;
        switch(metric_type) {
            case MetricType::METRIC_BY_ACCUMULATION:
                metric = std::shared_ptr<Metric>(new AccumulatorMetric(namespace_name, name, sample_period, agg_period));
                break;
            case MetricType::METRIC_BY_FILL:
                metric = std::shared_ptr<Metric>(new FillMetric(namespace_name, name, sample_period, agg_period));
                break;
            case MetricType::METRIC_FROM_TOTAL:
                metric = std::shared_ptr<Metric>(new MetricFromTotal(namespace_name, name, sample_period, agg_period));
                break;
            default:
                metric = std::shared_ptr<Metric>(new AccumulatorMetric(namespace_name, name, sample_period, agg_period));
                break;
        }
        auto r = _metrics.emplace(std::make_pair(key, metric));
        return r.first->second;
    }
}

void Metrics::run() {
    Logger::Info("Metrics starting");

    // Check for metrics to send once per minute
    while(!_sleep(60000)) {
        if (!send_metrics()) {
            return;
        }
        if (!send_log_metrics(false)) {
            return;
        }
    }
}

void system_time_sec_msec(const std::chrono::system_clock::time_point st, uint64_t& sec, uint32_t& msec) {
    sec = std::chrono::system_clock::to_time_t(st);
    auto sec_st = std::chrono::system_clock::from_time_t(sec);
    msec = std::chrono::duration_cast<std::chrono::milliseconds>(st - sec_st).count();
}

std::string system_time_to_iso3339(const std::chrono::system_clock::time_point st) {
    time_t secs = std::chrono::system_clock::to_time_t(st);
    auto sec_st = std::chrono::system_clock::from_time_t(secs);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(st - sec_st).count();
    std::stringstream str;
    str << std::put_time(gmtime(&secs), "%FT%T") << "." << std::setw(3) << std::setfill('0') << ms << "Z";
    return str.str();
}

bool Metrics::send_metrics() {
    static std::string_view SV_EMPTY;

    MetricAggregateSnapshot snap;

    auto rec_type = RecordType::AUOMS_METRIC;
    auto rec_type_name = RecordTypeToName(RecordType::AUOMS_METRIC);

    for (auto& e : _metrics) {
        while (e.second->GetAggregateSnapshot(&snap)) {
            struct timeval tv;
            gettimeofday(&tv, nullptr);

            uint64_t sec = static_cast<uint64_t>(tv.tv_sec);
            uint32_t msec = static_cast<uint32_t>(tv.tv_usec) / 1000;

            int num_fields = 10;

            if (!_builder->BeginEvent(sec, msec, 0, 1)) {
                return false;
            }
            if (!_builder->BeginRecord(static_cast<uint32_t>(rec_type), rec_type_name, "", num_fields)) {
                return false;
            }
            if (!_builder->AddField("version", AUOMS_VERSION, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("StartTime", system_time_to_iso3339(snap.start_time), SV_EMPTY,
                                  field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("EndTime", system_time_to_iso3339(snap.end_time), SV_EMPTY,
                                  field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("Namespace", snap.namespace_name, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("Name", snap.name, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("SamplePeriod", std::to_string(snap.sample_period), SV_EMPTY,
                                  field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("NumSamples", std::to_string(snap.num_samples), SV_EMPTY,
                                  field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("Min", std::to_string(snap.min), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("Max", std::to_string(snap.max), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->AddField("Avg", std::to_string(snap.avg), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
                return false;
            }
            if (!_builder->EndRecord()) {
                return false;
            }
            if (!_builder->EndEvent() != 0) {
                return false;
            }
        }
    }

    return true;
}

bool Metrics::send_log_metrics(bool flush_all) {
    static std::string_view SV_EMPTY;

    auto rec_type = RecordType::AUOMS_METRIC;
    auto rec_type_name = RecordTypeToName(RecordType::AUOMS_METRIC);

    std::vector<std::shared_ptr<LogMetric>> log_metrics;
    Logger::GetMetrics(log_metrics, flush_all);

    for (auto& lm : log_metrics) {
        uint64_t sec;
        uint32_t msec;
        system_time_sec_msec(lm->_start_time, sec, msec);

        int num_fields = 11;
        bool include_fist_msg = false;
        if (lm->_first_msg.compare(0, lm->_first_msg.size()-1, lm->_fmt) != 0) {
            num_fields = 12;
            include_fist_msg = true;
        }

        if (!_builder->BeginEvent(sec, msec, 0, 1)) {
            return false;
        }
        if (!_builder->BeginRecord(static_cast<uint32_t>(rec_type), rec_type_name, "", num_fields)) {
            return false;
        }
        if (!_builder->AddField("version", AUOMS_VERSION, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("StartTime", system_time_to_iso3339(lm->_start_time), SV_EMPTY,
                                field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("EndTime", system_time_to_iso3339(lm->_end_time), SV_EMPTY,
                                field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("Namespace", _proc_name, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("Name", "log", nullptr, field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("SamplePeriod", std::to_string(static_cast<uint64_t>(MetricPeriod::MINUTE)), SV_EMPTY,
                                field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("NumSamples", std::to_string(1), SV_EMPTY,
                                field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("Min", std::to_string(static_cast<double>(lm->_count)), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("Max", std::to_string(static_cast<double>(lm->_count)), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("Avg", std::to_string(static_cast<double>(lm->_count)), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (!_builder->AddField("Message", lm->_fmt, SV_EMPTY,
                                field_type_t::UNCLASSIFIED)) {
            return false;
        }
        if (include_fist_msg) {
            if (!_builder->AddField("Data", lm->_first_msg, SV_EMPTY,
                                    field_type_t::UNCLASSIFIED)) {
                return false;
            }
        }
        if (!_builder->EndRecord()) {
            return false;
        }
        if (!_builder->EndEvent() != 0) {
            return false;
        }
    }

    return true;
}
