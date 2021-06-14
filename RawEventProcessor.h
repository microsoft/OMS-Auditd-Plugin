/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_RAWEVENTPROCESSOR_H
#define AUOMS_RAWEVENTPROCESSOR_H

#include "Event.h"
#include "UserDB.h"
#include "ProcessTree.h"
#include "ExecveConverter.h"
#include "CmdlineRedactor.h"
#include "Metrics.h"

class RawEventProcessor {
public:
    RawEventProcessor(const std::shared_ptr<EventBuilder>& builder, const std::shared_ptr<UserDB>& user_db, const std::shared_ptr<CmdlineRedactor>& cmdline_redactor, const std::shared_ptr<ProcessTree>& processTree, const std::shared_ptr<FiltersEngine> filtersEngine, const std::shared_ptr<Metrics>& metrics):
    _builder(builder), _user_db(user_db), _cmdline_redactor(cmdline_redactor), _state_ptr(nullptr), _processTree(processTree), _filtersEngine(filtersEngine), _metrics(metrics),
        _event_flags(0), _pid(0), _ppid(0), _uid(-1), _last_proc_event_gen(0), _other_tag(0)
    {
        _bytes_metric = _metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "data", "bytes", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _record_metric = _metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "data", "records", MetricPeriod::SECOND, MetricPeriod::HOUR);
        _event_metric = _metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "data", "events", MetricPeriod::SECOND, MetricPeriod::HOUR);
    }

    void ProcessData(const void* data, size_t data_len);
    void DoProcessInventory();

private:
    void end_event();
    void cancel_event();
    void process_event(const Event& event);
    bool process_syscall_event(const Event& event);
    void process_user_cmd_record(const Event& event, const EventRecord& record);
    bool process_field(const EventRecord& record, const EventRecordField& field, uint32_t rtype_index);
    bool add_int_field(const std::string_view& name, int val, field_type_t ft);
    bool add_uid_field(const std::string_view& name, int uid, field_type_t ft);
    bool add_gid_field(const std::string_view& name, int gid, field_type_t ft);
    bool add_str_field(const std::string_view& name, const std::string_view& val, field_type_t ft);
    bool generate_proc_event(ProcessInfo* pinfo, uint64_t sec, uint32_t nsec);

    std::shared_ptr<EventBuilder> _builder;
    std::shared_ptr<UserDB> _user_db;
    std::shared_ptr<CmdlineRedactor> _cmdline_redactor;
    void* _state_ptr;
    std::shared_ptr<ProcessTree> _processTree;
    std::shared_ptr<FiltersEngine> _filtersEngine;
    std::shared_ptr<Metrics> _metrics;
    std::shared_ptr<Metric> _bytes_metric;
    std::shared_ptr<Metric> _record_metric;
    std::shared_ptr<Metric> _event_metric;
    uint32_t _event_flags;
    pid_t _pid;
    pid_t _ppid;
    int _uid;
    int _gid;
    std::string _exe;
    std::string _args;
    std::string _syscall;
    std::string _field_name;
    std::string _unescaped_val;
    std::string _tmp_val;
    std::string _cmdline;
    std::string _path_name;
    std::string _path_nametype;
    std::string _path_mode;
    std::string _path_ouid;
    std::string _path_ogid;
    uint64_t _last_proc_event_gen;
    ExecveConverter _execve_converter;
    uint64_t _other_tag;
    std::unordered_map<uint32_t, std::pair<uint64_t,uint32_t>> _other_rtype_counts;
};


#endif //AUOMS_RAWEVENTPROCESSOR_H
