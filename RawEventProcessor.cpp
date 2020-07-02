/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "RawEventProcessor.h"

#include "Queue.h"
#include "Logger.h"
#include "Translate.h"
#include "Interpret.h"
#include "StringUtils.h"

#include <climits>
#include <algorithm>
#include <iterator>

// Character that separates key in AUDIT_FILTERKEY field in rules
// This value mirrors what is defined for AUDIT_KEY_SEPARATOR in libaudit.h
#define KEY_SEP 0x01

#define PROCESS_INVENTORY_EVENT_INTERVAL 3600

void RawEventProcessor::ProcessData(const void* data, size_t data_len) {

    Event event(data, data_len);

    _bytes_metric->Add(static_cast<double>(data_len));
    _record_metric->Add(static_cast<double>(event.NumRecords()));
    _event_metric->Add(1.0);

    auto ret = event.Validate();
    if (ret != 0) {
        Logger::Warn("Invalid event encountered: error=%d", ret);
        return;
    }

    auto rec = event.begin();
    auto rtype = static_cast<RecordType>(rec.RecordType());

    if (rtype == RecordType::SYSCALL || rtype == RecordType::EXECVE || rtype == RecordType::CWD || rtype == RecordType::PATH ||
                rtype == RecordType::SOCKADDR || rtype == RecordType::INTEGRITY_RULE) {
        if (!process_syscall_event(event)) {
            process_event(event);
        }
    } else {
        process_event(event);
    }
}

void RawEventProcessor::process_event(const Event& event) {

    using namespace std::string_literals;

    static auto S_PID = "pid"s;
    static auto S_PPID = "ppid"s;

    auto ret = _builder->BeginEvent(event.Seconds(), event.Milliseconds(), event.Serial(), event.NumRecords());
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return;
    }

    for (auto& rec: event) {
        if (rec.NumFields() == 0) {
            Logger::Warn("Encountered event record with NumFields == 0: type=%s msg=audit(%ld.%03d:%ld)", rec.RecordTypeNamePtr(), event.Seconds(), event.Milliseconds(), event.Serial());
            return;
        }
        ret = _builder->BeginRecord(rec.RecordType(), rec.RecordTypeName(), rec.RecordText(), rec.NumFields());
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return;
        }

        auto pid_field = rec.FieldByName(S_PID);
        if (pid_field) {
            _pid = atoi(pid_field.RawValuePtr());
            _builder->SetEventPid(_pid);
        }
        auto ppid_field = rec.FieldByName(S_PPID);
        if (ppid_field) {
            _ppid = atoi(ppid_field.RawValuePtr());
        }

        for (auto& field: rec) {
            if (!process_field(rec, field, false)) {
                cancel_event();
                return;
            }
        }

        ret = _builder->EndRecord();
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return;
        }
    }

    end_event();
}

bool RawEventProcessor::process_syscall_event(const Event& event) {

    using namespace std::string_view_literals;

    static auto SV_ZERO = "0"sv;
    static auto SV_TYPE = "type"sv;
    static auto SV_ITEMS = "items"sv;
    static auto SV_ITEM = "item"sv;
    static auto SV_NODE = "node"sv;
    static auto SV_ARGC = "argc"sv;
    static auto SV_CWD = "cwd"sv;
    static auto SV_SADDR = "saddr"sv;
    static auto SV_INTEGRITY_HASH = "hash"sv;
    static auto SV_NAME = "name"sv;
    static auto SV_NAMETYPE = "nametype"sv;
    static auto SV_OBJTYPE = "objtype"sv;
    static auto SV_MODE = "mode"sv;
    static auto SV_OUID = "ouid"sv;
    static auto SV_OGID = "ogid"sv;
    static auto SV_PATH_NAME = "path_name"sv;
    static auto SV_PATH_NAMETYPE = "path_nametype"sv;
    static auto SV_PATH_MODE = "path_mode"sv;
    static auto SV_PATH_OUID = "path_ouid"sv;
    static auto SV_PATH_OGID = "path_ogid"sv;
    static auto SV_EMPTY = ""sv;
    static auto SV_CMDLINE = "cmdline"sv;
    static auto SV_CONTAINERID = "containerid"sv;
    static auto SV_DROPPED = "dropped_"sv;
    static auto SV_PID = "pid"sv;
    static auto SV_PPID = "ppid"sv;
    static auto SV_SYSCALL = "syscall"sv;
    static auto SV_PROCTITLE = "proctitle"sv;
    static auto S_EXECVE = std::string("execve");
    static auto SV_JSON_ARRAY_START = "[\""sv;
    static auto SV_JSON_ARRAY_SEP = "\",\""sv;
    static auto SV_JSON_ARRAY_END = "\"]"sv;
    static auto auoms_syscall_name = RecordTypeToName(RecordType::AUOMS_SYSCALL);
    static auto auoms_syscall_fragment_name = RecordTypeToName(RecordType::AUOMS_SYSCALL_FRAGMENT);
    static auto auoms_execve_name = RecordTypeToName(RecordType::AUOMS_EXECVE);

    int num_fields = 0;
    int num_path = 0;
    int num_execve = 0;
    int uid;
    int gid;
    std::string exe;
    std::string syscall;

    auto rec_type = RecordType::AUOMS_SYSCALL_FRAGMENT;
    auto rec_type_name = auoms_syscall_fragment_name;

    EventRecord syscall_rec;
    EventRecordField syscall_field;
    EventRecord cwd_rec;
    EventRecordField cwd_field;
    EventRecord path_rec;
    std::vector<EventRecord> path_recs;
    std::vector<EventRecord> execve_recs;
    EventRecord argc_rec;
    EventRecordField argc_field;
    EventRecord sockaddr_rec;
    EventRecordField sockaddr_field;
    EventRecord integrity_rec;
    EventRecordField integrity_field;
    EventRecord proctitle_rec;
    EventRecordField proctitle_field;
    EventRecord dropped_rec;
    std::vector<EventRecord> other_recs;

    for (auto& rec: event) {
        switch(static_cast<RecordType>(rec.RecordType())) {
            case RecordType::SYSCALL:
                if (!syscall_rec) {
                    rec_type = RecordType::AUOMS_SYSCALL;
                    rec_type_name = auoms_syscall_name;
                    for (auto &f : rec) {
                        auto fname = f.FieldName();
                        switch (fname[0]) {
                            case 't': {
                                if (fname != SV_TYPE) {
                                    num_fields += 1;
                                }
                                break;
                            }
                            case 'i': {
                                if (fname != SV_ITEMS) {
                                    num_fields += 1;
                                }
                                break;
                            }
                            case 's': {
                                if (fname == SV_SYSCALL) {
                                    syscall_field = f;
                                }
                                num_fields += 1;
                                break;
                            }
                            default:
                                num_fields += 1;
                                break;
                        }
                    }
                    syscall_rec = rec;
                }
                break;
            case RecordType::EXECVE: {
                if (rec.NumFields() > 0) {
                    if (num_execve == 0) {
                        num_fields += 1;
                        if (!argc_rec) {
                            // the argc field should be the first (or second if node field is present) field in the record but check the first four just in case
                            for(uint16_t i = 0; i < rec.NumFields() && i < 4 ; i++) {
                                auto field = rec.FieldAt(i);
                                if (field.FieldName() == SV_ARGC) {
                                    num_fields += 1;
                                    argc_rec = rec;
                                    argc_field = field;
                                    break;
                                }
                            }
                        }
                    }
                    num_execve += 1;
                    execve_recs.emplace_back(rec);
                }
                break;
            }
            case RecordType::CWD:
                if (!cwd_rec) {
                    for (int i = 0; i < rec.NumFields(); ++i) {
                        auto field = rec.FieldAt(i);
                        if (field.FieldName() == SV_CWD) {
                            num_fields += 1;
                            cwd_rec = rec;
                            cwd_field = field;
                            break;
                        }
                    }
                }
                break;
            case RecordType::PATH:
                if (rec.NumFields() > 0) {
                    if (num_path == 0) {
                        // This assumes there will only be a nametype field or an objtype field but never both
                        num_fields += 5; // name, mode, ouid, ogid, (nametype or objtype)
                    }
                    num_path += 1;
                    path_recs.emplace_back(rec);
                    if (!path_rec) {
                        bool isItemZero = false;
                        unsigned int numNodeFields = 0;
                        for (auto& f: rec) {
                            if (f.FieldName() == SV_ITEM && f.RawValue() == SV_ZERO) {
//                                num_fields += rec.NumFields()-1; // exclude item
                                isItemZero = true;
                                path_rec = rec;
                            } else if (f.FieldName() == SV_NODE) {
                                numNodeFields++;
                            }
                        }
                        if (isItemZero) {
                            num_fields += rec.NumFields() - 1 - numNodeFields; // exclude item and node fields
                        }
                    }
                }
                break;
            case RecordType::SOCKADDR:
                if (!sockaddr_rec) {
                    for (int i = 0; i < rec.NumFields(); ++i) {
                        auto field = rec.FieldAt(i);
                        if (field.FieldName() == SV_SADDR) {
                            sockaddr_rec = rec;
                            sockaddr_field = field;
                            num_fields += 1;
                            break;
                        }
                    }
                }
                break;
            case RecordType::INTEGRITY_RULE:
                if (!integrity_rec) {
                    for (int i = 0; i < rec.NumFields(); ++i) {
                        auto field = rec.FieldAt(i);
                        if (field.FieldName() == SV_INTEGRITY_HASH) {
                            integrity_rec = rec;
                            integrity_field = field;
                            num_fields += 1;
                        }
                    }
                }
                break;
            case RecordType::PROCTITLE:
                if (!proctitle_rec) {
                    for (int i = 0; i < rec.NumFields(); ++i) {
                        auto field = rec.FieldAt(i);
                        if (field.FieldName() == SV_PROCTITLE) {
                            num_fields += 1;
                            proctitle_rec = rec;
                            proctitle_field = field;
                            break;
                        }
                    }
                }
                break;
            case RecordType::AUOMS_DROPPED_RECORDS:
                dropped_rec = rec;
                break;
            default:
                if (rec.NumFields() > 0) {
                    num_fields += rec.NumFields();
                    other_recs.emplace_back(rec);
                }
                break;
        }
    }

    // Sort PATH records by item field
    std::sort(path_recs.begin(), path_recs.end(), [](const EventRecord& a, const EventRecord& b) -> int {
        auto fa = a.FieldByName(SV_ITEM);
        auto fb = b.FieldByName(SV_ITEM);
        int a_num = INT32_MAX; // PATH records with a missing or invalid item value should be sorted to the end;
        int b_num = INT32_MAX;

        if (fa) {
            try {
                a_num = std::stoi(std::string(fa.FieldName()));
            } catch (std::logic_error&) {
                // Ignore
            }
        }

        if (fb) {
            try {
                b_num = std::stoi(std::string(fb.FieldName()));
            } catch (std::logic_error&) {
                // Ignore
            }
        }

        return a_num > b_num;
    });

    if (syscall_rec && syscall_field) {
        if (InterpretField(_tmp_val, syscall_rec, syscall_field, field_type_t::SYSCALL)) {
            if (starts_with(_tmp_val, S_EXECVE)) {
                rec_type = RecordType::AUOMS_EXECVE;
                rec_type_name = auoms_execve_name;
            }
        }
        _syscall = _tmp_val;
    }

    // Exclude proctitle if EXECVE is present
    if (execve_recs.size() > 0 && proctitle_rec && proctitle_field) {
        num_fields -= 1;
    }

    if (num_fields == 0) {
        return false;
    }

    // For containerid
    num_fields += 1;

    auto ret = _builder->BeginEvent(event.Seconds(), event.Milliseconds(), event.Serial(), 1);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }
    _event_flags = EVENT_FLAG_IS_AUOMS_EVENT;

    ret = _builder->BeginRecord(static_cast<uint32_t>(rec_type), rec_type_name, SV_EMPTY, num_fields);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    if (syscall_rec) {
        for (auto &f : syscall_rec) {
            auto fname = f.FieldName();
            bool add_field = false;
            switch (fname[0]) {
                case 't': {
                    if (fname != SV_TYPE) {
                        add_field = true;
                    }
                    break;
                }
                case 'i': {
                    if (fname != SV_ITEMS) {
                        add_field = true;
                    }
                    break;
                }
                case 'p':
                    if (fname == SV_PID) {
                        _pid = atoi(f.RawValuePtr());
                        _builder->SetEventPid(_pid);
                    }
                    if (fname == SV_PPID) {
                        _ppid = atoi(f.RawValuePtr());
                    }
                    add_field = true;
                    break;
                case 'u':
                    if (fname == "uid") {
                        uid = atoi(f.RawValuePtr());
                    }
                    add_field = true;
                    break;
                case 'g':
                    if (fname == "gid") {
                        gid = atoi(f.RawValuePtr());
                    }
                    add_field = true;
                    break;
                case 'e':
                    if (fname == "exe") {
                        exe = std::string(f.RawValuePtr());
                    }
                    add_field = true;
                    break;
                default:
                    add_field = true;
                    break;
            }
            if (add_field) {
                if (!process_field(syscall_rec, f, false)) {
                    cancel_event();
                    return false;
                }
            }
        }
    }

    if (cwd_rec && cwd_field) {
        if (!process_field(cwd_rec, cwd_field, false)) {
            cancel_event();
            return false;
        }
    }

    if (path_rec) {
        for (auto &f : path_rec) {
            auto fname = f.FieldName();
            if ((fname != SV_ITEM) && (fname != SV_NODE)) {
                if (!process_field(path_rec, f, false)) {
                    cancel_event();
                    return false;
                }
            }
        }
    }

    _path_name.resize(0);
    _path_nametype.resize(0);
    _path_mode.resize(0);
    _path_ouid.resize(0);
    _path_ogid.resize(0);

    if (path_recs.size() > 0) {
        _path_name = SV_JSON_ARRAY_START;
        _path_nametype = SV_JSON_ARRAY_START;
        _path_mode = SV_JSON_ARRAY_START;
        _path_ouid = SV_JSON_ARRAY_START;
        _path_ogid = SV_JSON_ARRAY_START;

        int path_num = 0;

        for (auto& rec: path_recs) {
            bool found_nametype = false;
            for (auto &f : rec) {
                auto fname = f.FieldName();
                if (fname.size() >= 2) {
                    switch (fname[0]) {
                        case 'm': {
                            if (fname == SV_MODE) {
                                if (path_num != 0) {
                                    _path_mode.append(SV_JSON_ARRAY_SEP);
                                }
                                _path_mode.append(f.RawValuePtr(), f.RawValueSize());
                            }
                            break;
                        }
                        case 'n': {
                            if (fname == SV_NAME) {
                                if (path_num != 0) {
                                    _path_name.append(SV_JSON_ARRAY_SEP);
                                }
                                // name might be escaped
                                unescape_raw_field(_unescaped_val, f.RawValuePtr(), f.RawValueSize());
                                // Path names might have non-ASCII/non-printable chars, escape the name before adding it.
                                json_escape_string(_tmp_val, _unescaped_val.data(), _unescaped_val.size());
                                _path_name.append(_tmp_val);
                            } else if (fname == SV_NAMETYPE && !found_nametype) {
                                if (path_num != 0) {
                                    _path_nametype.append(SV_JSON_ARRAY_SEP);
                                }
                                _path_nametype.append(f.RawValuePtr(), f.RawValueSize());
                                found_nametype = true;
                            }
                            break;
                        }
                        case 'o': {
                            switch (fname[1]) {
                                case 'b':
                                    if (fname == SV_OBJTYPE && !found_nametype) {
                                        if (path_num != 0) {
                                            _path_nametype.append(SV_JSON_ARRAY_SEP);
                                        }
                                        _path_nametype.append(f.RawValuePtr(), f.RawValueSize());
                                        found_nametype = true;
                                    }
                                    break;
                                case 'g':
                                    if (fname == SV_OGID) {
                                        if (path_num != 0) {
                                            _path_ogid.append(SV_JSON_ARRAY_SEP);
                                        }
                                        _path_ogid.append(f.RawValuePtr(), f.RawValueSize());
                                    }
                                    break;
                                case 'u':
                                    if (fname == SV_OUID) {
                                        if (path_num != 0) {
                                            _path_ouid.append(SV_JSON_ARRAY_SEP);
                                        }
                                        _path_ouid.append(f.RawValuePtr(), f.RawValueSize());
                                    }
                                    break;
                            }
                            break;
                        }
                    }
                }
            }
            path_num += 1;
        }

        _path_name.append(SV_JSON_ARRAY_END);
        _path_nametype.append(SV_JSON_ARRAY_END);
        _path_mode.append(SV_JSON_ARRAY_END);
        _path_ouid.append(SV_JSON_ARRAY_END);
        _path_ogid.append(SV_JSON_ARRAY_END);

        auto ret = _builder->AddField(SV_PATH_NAME, _path_name, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return false;
        }

        ret = _builder->AddField(SV_PATH_NAMETYPE, _path_nametype, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return false;
        }

        ret = _builder->AddField(SV_PATH_MODE, _path_mode, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return false;
        }

        ret = _builder->AddField(SV_PATH_OUID, _path_ouid, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return false;
        }

        ret = _builder->AddField(SV_PATH_OGID, _path_ogid, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return false;
        }
    }

    if (argc_rec && argc_field) {
        if (!process_field(argc_rec, argc_field, false)) {
            cancel_event();
            return false;
        }
    }

    if (execve_recs.size() > 0) {
        // Exclude proctitle since we have EXECVE
        proctitle_rec = EventRecord();
        proctitle_field = EventRecordField();

        _execve_converter.Convert(execve_recs, _cmdline);
        ret = _builder->AddField(SV_CMDLINE, _cmdline, nullptr, field_type_t::UNESCAPED);

        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return false;
        }
    } else {
        _cmdline.resize(0);
    }

    if (sockaddr_rec && sockaddr_field) {
        if (!process_field(sockaddr_rec, sockaddr_field, false)) {
            cancel_event();
            return false;
        }
    }

    if (integrity_rec && integrity_field) {
        if (!process_field(integrity_rec, integrity_field, false)) {
            cancel_event();
            return false;
        }
    }

    if (proctitle_rec && proctitle_field) {
        unescape_raw_field(_unescaped_val, proctitle_field.RawValuePtr(), proctitle_field.RawValueSize());
        ExecveConverter::ConvertRawCmdline(_unescaped_val, _cmdline);

        ret = _builder->AddField(SV_PROCTITLE, _cmdline, nullptr, field_type_t::PROCTITLE);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return false;
        }
    }

    if (other_recs.size() > 0) {
        for (auto& rec : other_recs) {
            for (auto &field: rec) {
                if (!process_field(rec, field, true)) {
                    cancel_event();
                    return false;
                }
            }
        }
    }

    if (dropped_rec) {
        for (auto& field: dropped_rec) {
            _field_name.assign(SV_DROPPED);
            _field_name.append(field.FieldName());
            ret = _builder->AddField(_field_name, field.RawValue(), nullptr, field_type_t::UNCLASSIFIED);
            if (ret != 1) {
                if (ret == Queue::CLOSED) {
                    throw std::runtime_error("Queue closed");
                }
                cancel_event();
                return false;
            }
        }
    }

    std::shared_ptr<ProcessTreeItem> p;
    std::string cmdline;

    if (!_syscall.empty() && starts_with(_syscall, "execve")) {
        p = _processTree->AddProcess(ProcessTreeSource_execve, _pid, _ppid, uid, gid, exe, _cmdline);
    } else if (!_syscall.empty()) {
        p = _processTree->GetInfoForPid(_pid);
    }

    std::string containerid = "";
    if (p) {
        containerid = p->_containerid;
    }

    ret = _builder->AddField(SV_CONTAINERID, containerid, nullptr, field_type_t::UNCLASSIFIED);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    ret = _builder->EndRecord();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    bool filtered = false;
    if (_filtersEngine->IsEventFiltered(_syscall, p, _filtersEngine->GetCommonFlagsMask())) {
        filtered = true;
    }

    if (!filtered) {
        end_event();
    } else {
        cancel_event();
    }

    return true;
}

void RawEventProcessor::end_event()
{
    _builder->SetEventFlags(_event_flags);
    _event_flags = 0;
    auto ret = _builder->EndEvent();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
    }
}

void RawEventProcessor::cancel_event()
{
    _event_flags = 0;
    if (_builder->CancelEvent() != 1) {
        throw std::runtime_error("Queue Closed");
    }
}

bool RawEventProcessor::process_field(const EventRecord& record, const EventRecordField& field, bool prepend_rec_type)
{
    using namespace std::string_literals;

    static auto S_UNSET = "unset"s;

    auto val = field.RawValue();
    auto val_ptr = field.RawValuePtr();

    auto field_type = FieldNameToType(static_cast<RecordType>(field.RecordType()), field.FieldName(), field.RawValue());
    if (field_type == field_type_t::UNCLASSIFIED && field.FieldType() == field_type_t::UNESCAPED) {
        field_type = field_type_t::UNESCAPED;
    }

    _field_name.resize(0);
    if (prepend_rec_type) {
        _field_name.append(record.RecordTypeName());
        _field_name.push_back('_');
    }

    _field_name.append(field.FieldName());

    _tmp_val.resize(0);

    switch (field_type) {
        case field_type_t::UID: {
            int uid = static_cast<int>(strtoul(val_ptr, NULL, 10));
            if (uid < 0) {
                _tmp_val = S_UNSET;
            } else {
                _tmp_val = _user_db->GetUserName(uid);
            }
            if (_tmp_val.size() == 0) {
                _tmp_val = "unknown-uid(" + std::to_string(uid) + ")";
            }
            break;
        }
        case field_type_t::GID: {
            int gid = static_cast<int>(strtoul(val_ptr, NULL, 10));
            if (gid < 0) {
                _tmp_val = S_UNSET;
            } else {
                _tmp_val = _user_db->GetGroupName(gid);
            }
            if (_tmp_val.size() == 0) {
                _tmp_val = "unknown-gid(" + std::to_string(gid) + ")";
            }
            break;
        }
        case field_type_t::ESCAPED_KEY:
            if (unescape_raw_field(_tmp_val, val_ptr, field.RawValueSize()) > 0) {
                std::replace(_tmp_val.begin(), _tmp_val.end(), static_cast<char>(KEY_SEP), ',');
            } else {
                _tmp_val.resize(0);
            }
            break;
        case field_type_t::ESCAPED:
            break;
        case field_type_t::PROCTITLE:
            break;
        default:
            if (!InterpretField(_tmp_val, record, field, field_type)) {
                _tmp_val.resize(0);
            }
            break;
    }

    auto ret = _builder->AddField(_field_name, val, _tmp_val, field_type);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }
    return true;
}

bool RawEventProcessor::add_int_field(const std::string_view& name, int val, field_type_t ft) {
    _tmp_val.assign(std::to_string(val));
    return add_str_field(name, _tmp_val, ft);
}

bool RawEventProcessor::add_str_field(const std::string_view& name, const std::string_view& val, field_type_t ft) {
    int ret = _builder->AddField(name, val, nullptr, ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
}

bool RawEventProcessor::add_uid_field(const std::string_view& name, int uid, field_type_t ft) {
    _tmp_val.assign(std::to_string(uid));
    std::string user = _user_db->GetUserName(uid);
    int ret = _builder->AddField(name, _tmp_val, user.c_str(), ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
}

bool RawEventProcessor::add_gid_field(const std::string_view& name, int gid, field_type_t ft) {
    _tmp_val.assign(std::to_string(gid));
    std::string user = _user_db->GetGroupName(gid);
    int ret = _builder->AddField(name, _tmp_val, user.c_str(), ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
}

bool RawEventProcessor::generate_proc_event(ProcessInfo* pinfo, uint64_t sec, uint32_t msec) {
    using namespace std::literals::string_view_literals;

    auto ret = _builder->BeginEvent(sec, msec, 0, 1);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }

    _builder->SetEventFlags(EVENT_FLAG_IS_AUOMS_EVENT);

    uint16_t num_fields = 16;

    static auto auoms_proc_inv_str = RecordTypeToName(RecordType::AUOMS_PROCESS_INVENTORY);
    ret = _builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_PROCESS_INVENTORY), auoms_proc_inv_str, ""sv, num_fields);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    if (!add_int_field("pid"sv, pinfo->pid(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_int_field("ppid"sv, pinfo->ppid(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_int_field("ses"sv, pinfo->ses(), field_type_t::SESSION)) {
        return false;
    }

    if (!add_str_field("starttime"sv, pinfo->starttime(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_uid_field("uid"sv, pinfo->uid(), field_type_t::UID)) {
        return false;
    }

    if (!add_uid_field("euid"sv, pinfo->euid(), field_type_t::UID)) {
        return false;
    }

    if (!add_uid_field("suid"sv, pinfo->suid(), field_type_t::UID)) {
        return false;
    }

    if (!add_uid_field("fsuid"sv, pinfo->fsuid(), field_type_t::UID)) {
        return false;
    }

    if (!add_gid_field("gid"sv, pinfo->gid(), field_type_t::GID)) {
        return false;
    }

    if (!add_gid_field("egid"sv, pinfo->egid(), field_type_t::GID)) {
        return false;
    }

    if (!add_gid_field("sgid"sv, pinfo->sgid(), field_type_t::GID)) {
        return false;
    }

    if (!add_gid_field("fsgid"sv, pinfo->fsgid(), field_type_t::GID)) {
        return false;
    }

    if (!add_str_field("comm"sv, pinfo->comm(), field_type_t::UNESCAPED)) {
        return false;
    }

    if (!add_str_field("exe"sv, pinfo->exe(), field_type_t::UNESCAPED)) {
        return false;
    }

    pinfo->format_cmdline(_tmp_val);

    bool cmdline_truncated = false;
    if (_tmp_val.size() > UINT16_MAX-1) {
        _tmp_val.resize(UINT16_MAX-1);
        cmdline_truncated = true;
    }

    if (!add_str_field("cmdline"sv, _tmp_val, field_type_t::UNESCAPED)) {
        return false;
    }

    if (!add_str_field("cmdline_truncated"sv, cmdline_truncated ? "true"sv : "false"sv, field_type_t::UNCLASSIFIED)) {
        return false;
    }

    ret = _builder->EndRecord();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    ret = _builder->EndEvent();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }
    return true;
}

void RawEventProcessor::DoProcessInventory() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);

    uint64_t sec = static_cast<uint64_t>(tv.tv_sec);
    uint32_t msec = static_cast<uint32_t>(tv.tv_usec)/1000;

    if (_last_proc_event_gen+PROCESS_INVENTORY_EVENT_INTERVAL > sec) {
        return;
    }

    auto pinfo = ProcessInfo::Open();
    if (!pinfo) {
        Logger::Error("Failed to open '/proc': %s", strerror(errno));
        return;
    }

    while(pinfo->next()) {
        generate_proc_event(pinfo.get(), sec, msec);
    }

    _last_proc_event_gen = sec;
}
