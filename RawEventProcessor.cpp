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
#include "LookupTables.h"
#include "Interpret.h"
#include "StringUtils.h"

/*****************************************************************************
* New record types are in 10000 range to avoid collision with existing codes.
*
* 14688 was chosen for aggregate process creation records, given similarity
* to windows 4688 events.
*
* 11309 was chosen for fragmented EXECVE records, following use of 1309 for
* native AUDIT_EXECVE.
*
******************************************************************************/


#define PROCESS_INVENTORY_FETCH_INTERVAL 300
#define PROCESS_INVENTORY_EVENT_INTERVAL 3600

void RawEventProcessor::ProcessData(const char* data, size_t data_len) {
    Event event(data, data_len);

    auto rec = event.begin();
    if (event.NumRecords() > 1 && rec.RecordType() == static_cast<uint32_t>(RecordType::SYSCALL)) {
        if (!process_syscall_event(event)) {
            process_event(event);
        }
    } else {
        process_event(event);
    }
}

void RawEventProcessor::process_event(const Event& event) {
    auto ret = _builder->BeginEvent(event.Seconds(), event.Milliseconds(), event.Serial(), event.NumRecords());
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return;
    }

    for (auto& rec: event) {
        ret = _builder->BeginRecord(rec.RecordType(), rec.RecordTypeName(), rec.RecordText(), rec.NumFields());
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return;
        }

        auto pid_field = rec.FieldByName("pid");
        if (pid_field) {
            _pid = atoi(pid_field.RawValuePtr());
        }
        auto ppid_field = rec.FieldByName("ppid");
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

int parse_execve_argnum(const std::string_view& fname) {
    if (fname[0] == 'a' && fname[1] >= '0' && fname[1] <= '9') {
        try {
            return std::stoi(std::string(fname.substr(1)));
        } catch (std::logic_error&) {
            // This is highly unlikely, but, if it happend, resutn INT_MAX so that the record gets sorted to the end.
            return INT32_MAX;
        }
    }
    return 0;
}

// Return 0 if "a%d"
// Return 1 if "a%d_len=%d"
// Return 2 if "a%d[%d]"
// Return -1 if error
int parse_execve_fieldname(const std::string_view& fname, const std::string_view& val, int& arg_num, int& arg_len, int& arg_idx) {
    try {
        if (fname[0] == 'a' && fname[1] >= '0' && fname[1] <= '9') {
            auto name = fname.substr(1);
            size_t pos = 0;
            arg_num = std::stoi(std::string(name), &pos, 10);
            if (pos == name.length()) {
                arg_len = 0;
                arg_idx = 0;
                return 0;
            } else if (name[pos] == '_') {
                if (name.substr(pos) == "_len" && val[0] >= '0' && val[0] <= '9') {
                    arg_idx = 0;
                    arg_len = std::stoi(std::string(val), &pos, 10);
                    if (pos == val.size()) {
                        return 1;
                    }
                }
            } else if (name[pos] == '[' && pos < name.size()) {
                name = name.substr(pos + 1);
                arg_len = 0;
                if (name[0] >= '0' && name[0] <= '9') {
                    arg_idx = std::stoi(std::string(name), &pos, 10);
                    if (name[pos] == ']') {
                        return 2;
                    }
                }
            }
        }
    } catch (std::logic_error&) {
        return -1;
    }
    return -1;
}

bool RawEventProcessor::process_syscall_event(const Event& event) {

    int num_fields = 0;
    int num_path = 0;
    int num_execve = 0;

    EventRecord syscall_rec;
    EventRecord cwd_rec;
    std::vector<EventRecord> path_recs;
    std::vector<EventRecord> execve_recs;
    EventRecord argc_rec;
    EventRecord sockaddr_rec;
    std::vector<EventRecord> other_recs;

    for (auto& rec: event) {
        switch(static_cast<RecordType>(rec.RecordType())) {
            case RecordType::SYSCALL:
                for (auto &f : rec) {
                    auto fname = f.FieldName();
                    switch (fname[0]) {
                        case 't': {
                            if (fname != "type") {
                                num_fields += 1;
                            }
                            break;
                        }
                        case 'i': {
                            if (fname != "items") {
                                num_fields += 1;
                            }
                            break;
                        }
                        case 'a': {
                            if (fname.length() != 2 || fname[1] < '0' || fname[1] > '3') {
                                num_fields += 1;
                            }
                            break;
                        }
                        default:
                            num_fields += 1;
                            break;
                    }
                }
                syscall_rec = rec;
                break;
            case RecordType::EXECVE: {
                if (rec.NumFields() > 0) {
                    if (num_execve == 0) {
                        num_fields += 1;
                        if (!argc_rec) {
                            // the argc field should be the first field in the record but check the first three just in case
                            for(uint16_t i = 0; i < rec.NumFields() && i < 3 ; i++) {
                                if (rec.FieldAt(i).FieldName() == "argc") {
                                    num_fields += 1;
                                    argc_rec = rec;
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
                if (!cwd_rec && rec.NumFields() > 0 && rec.FieldAt(0).FieldName() == "cwd") {
                    num_fields += 1;
                    cwd_rec = rec;
                }
                break;
            case RecordType::PATH:
                if (rec.NumFields() > 0) {
                    if (num_path == 0) {
                        num_fields += 5; // name, mode, ouid, ogid, nametype
                    }
                    num_path += 1;
                    path_recs.emplace_back(rec);
                }
                break;
            case RecordType::SOCKADDR:
                if (!sockaddr_rec && rec.NumFields() > 0 && rec.FieldAt(0).FieldName() == "saddr") {
                    num_fields += 1;
                    sockaddr_rec = rec;
                }
                break;
            default:
                if (rec.NumFields() > 0) {
                    num_fields += rec.NumFields();
                    other_recs.emplace_back(rec);
                }
                break;
        }
    }

    // Sort EXECVE records so that args (e.g. a0, a1, a2 ...) will be in order.
    std::sort(execve_recs.begin(), execve_recs.end(), [](const EventRecord& a, const EventRecord& b) -> int {
        auto fa = a.FieldAt(0);
        auto fb = b.FieldAt(0);
        int a_num = parse_execve_argnum(fa.FieldName());
        int b_num = parse_execve_argnum(fb.FieldName());

        return a_num > b_num;
    });

    // Sort PATH records by item field
    std::sort(execve_recs.begin(), execve_recs.end(), [](const EventRecord& a, const EventRecord& b) -> int {
        auto fa = a.FieldByName("item");
        auto fb = b.FieldByName("item");
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

    auto ret = _builder->BeginEvent(event.Seconds(), event.Milliseconds(), event.Serial(), 1);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }

    ret = _builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_SYSCALL), LookupTables::RecordTypeCodeToString(RecordType::AUOMS_SYSCALL), "", num_fields);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }

    if (syscall_rec) {
        for (auto &f : syscall_rec) {
            auto fname = f.FieldName();
            bool add_field = false;
            switch (fname[0]) {
                case 't': {
                    if (fname != "type") {
                        add_field = true;
                    }
                    break;
                }
                case 'i': {
                    if (fname != "items") {
                        add_field = true;
                    }
                    break;
                }
                case 'a': {
                    if (fname.length() != 2 || fname[1] < '0' || fname[1] > '3') {
                        add_field = true;
                    }
                    break;
                }
                default:
                    add_field = true;
                    break;
            }
            if (add_field) {
                if (!process_field(syscall_rec, f, false)) {
                    cancel_event();
                    return true;
                }
            }
        }
    }

    if (cwd_rec) {
        for (auto &f : cwd_rec) {
            auto fname = f.FieldName();
            if (fname[0] == 'c' && fname == "cwd") {
                if (!process_field(cwd_rec, f, false)) {
                    cancel_event();
                    return true;
                }
                break;
            }
        }
    }

    _path_name.resize(0);
    _path_nametype.resize(0);
    _path_mode.resize(0);
    _path_ouid.resize(0);
    _path_ogid.resize(0);

    if (path_recs.size() > 0) {
        _path_name = "[\"";
        _path_nametype = "[\"";
        _path_mode = "[\"";
        _path_ouid = "[\"";
        _path_ogid = "[\"";

        int path_num = 0;

        for (auto& rec: path_recs) {
            for (auto &f : rec) {
                if (path_num != 0) {
                    _path_name.append("\",\"");
                    _path_nametype.append("\",\"");
                    _path_mode.append("\",\"");
                    _path_ouid.append("\",\"");
                    _path_ogid.append("\",\"");
                }

                auto fname = f.FieldName();
                switch (fname[0]) {
                    case 'n': {
                        if (fname == "name") {
                            _path_name.append(f.RawValue());
                        } else if (fname == "nametype") {
                            _path_nametype.append(f.RawValue());
                        }
                        break;
                    }
                    case 'm': {
                        if (fname == "mode") {
                            _path_mode.append(f.RawValue());
                        }
                        break;
                    }
                    case 'o': {
                        if (fname == "ouid") {
                            _path_ouid.append(f.RawValue());
                        } else if (fname == "ogid") {
                            _path_ogid.append(f.RawValue());
                        }
                        break;
                    }
                }
                path_num += 1;
            }
        }

        _path_name = "\"]";
        _path_nametype = "\"]";
        _path_mode = "\"]";
        _path_ouid = "\"]";
        _path_ogid = "\"]";

        auto ret = _builder->AddField("path_name", _path_name, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            return false;
        }

        ret = _builder->AddField("path_nametype", _path_nametype, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            return false;
        }

        ret = _builder->AddField("path_mode", _path_mode, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            return false;
        }

        ret = _builder->AddField("path_ouid", _path_ouid, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            return false;
        }

        ret = _builder->AddField("path_ogid", _path_ogid, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            return false;
        }
    }

    if (argc_rec) {
        auto f = argc_rec.FieldByName("argc");
        if (!process_field(argc_rec, f, false)) {
            cancel_event();
            return true;
        }
    }

    if (execve_recs.size() > 0) {
        _cmdline.resize(0);
        for (auto& rec : execve_recs) {
            int curr_arg_num = 0;
            int curr_arg_len = 0;
            int curr_arg_idx = 0;
            for (auto &f : rec) {
                auto fname = f.FieldName();
                auto val = f.RawValue();
                int arg_num = 0;
                int arg_len = 0;
                int arg_idx = 0;

                auto atype = parse_execve_fieldname(fname, val, arg_num, arg_len, arg_idx);
                if (atype < 0) {
                    continue;
                }

                // Fill in arg gaps with place holder
                if (curr_arg_num < arg_num) {
                    while (curr_arg_num < arg_num) {
                        if (!_cmdline.empty()) {
                            _cmdline.append(" ");
                        }
                        _cmdline.append("<MISSING_ARG>");
                        curr_arg_num += 1;
                    }
                    continue;
                }

                switch (atype) {
                    case 0:
                        if (curr_arg_len > 0) {
                            unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
                            bash_escape_string(_cmdline, _unescaped_val.data(), _unescaped_val.length());
                            // Fill in the missing parts with the place holder
                            while(curr_arg_idx < curr_arg_len) {
                                _cmdline.append("<MISSING_PART>");
                                curr_arg_idx += 1;
                            }
                            curr_arg_len = 0;
                            curr_arg_idx = 0;
                        }

                        curr_arg_num += 1;
                        _unescaped_val.resize(0);
                        if (!_cmdline.empty()) {
                            _cmdline.append(" ");
                        }
                        unescape_raw_field(_unescaped_val, val.data(), val.size());
                        bash_escape_string(_cmdline, _unescaped_val.data(), _unescaped_val.length());
                        break;
                    case 1:
                        curr_arg_len = arg_len;
                        curr_arg_idx = 0;
                        _tmp_val.resize(0);
                        _unescaped_val.resize(0);
                        break;
                    case 2: {
                        if (curr_arg_idx == 0 && !_cmdline.empty()) {
                            _cmdline.append(" ");
                        }
                        if (curr_arg_idx != arg_idx) {
                            // There's a gap in the parts, so unescape and bash escape the part we have
                            // then fill in the missing parts with the place holder
                            unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
                            bash_escape_string(_cmdline, _unescaped_val.data(), _unescaped_val.length());
                            while(curr_arg_idx < arg_idx) {
                                _cmdline.append("<MISSING_PART>");
                                curr_arg_idx += 1;
                            }
                            _tmp_val.resize(0);
                            _unescaped_val.resize(0);
                        }
                        _tmp_val.append(val);
                        curr_arg_idx += 1;
                        if (curr_arg_idx >= curr_arg_len) {
                            unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
                            bash_escape_string(_cmdline, _unescaped_val.data(), _unescaped_val.length());
                            curr_arg_len = 0;
                            curr_arg_idx = 0;
                        }
                        break;
                    }
                }
            }
        }
        ret = _builder->AddField("cmdline", _cmdline, nullptr, field_type_t::UNCLASSIFIED);
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            return false;
        }
    }

    if (sockaddr_rec) {
        for (auto &f : sockaddr_rec) {
            auto fname = f.FieldName();
            if (fname[0] == 'c' && fname == "saddr") {
                if (!process_field(sockaddr_rec, f, false)) {
                    cancel_event();
                    return true;
                }
                break;
            }
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

    ret = _builder->EndRecord();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return true;
    }

    end_event();

    return true;
}

void RawEventProcessor::end_event()
{
    _builder->SetEventFlags(_event_flags);
    auto ret = _builder->EndEvent();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
    }
}

void RawEventProcessor::cancel_event()
{
    if (_builder->CancelEvent() != 1) {
        throw std::runtime_error("Queue Closed");
    }
}

bool RawEventProcessor::process_field(const EventRecord& record, const EventRecordField& field, bool prepend_rec_type)
{
    auto val = field.RawValue();
    auto val_ptr = field.RawValuePtr();

    auto field_type = LookupTables::FieldNameToType(static_cast<RecordType>(field.RecordType()), field.FieldName(), field.RawValue());

    _field_name.resize(0);
    if (prepend_rec_type) {
        _field_name.append(record.RecordTypeName());
        _field_name.append("_");
    }

    _field_name.append(field.FieldName());

    _tmp_val.resize(0);

    switch (field_type) {
        case field_type_t::UID: {
            int uid = static_cast<int>(strtoul(val_ptr, NULL, 10));
            if (uid < 0) {
                _tmp_val = "unset";
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
                _tmp_val = "unset";
            } else {
                _tmp_val = _user_db->GetGroupName(gid);
            }
            if (_tmp_val.size() == 0) {
                _tmp_val = "unknown-gid(" + std::to_string(gid) + ")";
            }
            break;
        }
        case field_type_t::ESCAPED:
            // Remove double quotes from raw field.
            if (val.front() == '"' && val.back() == '"') {
                val = val.substr(1, val.size()-2);
            }
            break;
        case field_type_t::PROCTITLE:
            // interp_ptr remains NULL
            break;
        default:
            if (!InterpretField(_tmp_val, record, field)) {
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

bool RawEventProcessor::add_int_field(const char* name, int val, field_type_t ft) {
    _tmp_val.assign(std::to_string(val));
    return add_str_field(name, _tmp_val.c_str(), ft);
}

bool RawEventProcessor::add_str_field(const char* name, const char* val, field_type_t ft) {
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

bool RawEventProcessor::add_uid_field(const char* name, int uid, field_type_t ft) {
    _tmp_val.assign(std::to_string(uid));
    std::string user = _user_db->GetUserName(uid);
    int ret = _builder->AddField(name, _tmp_val.c_str(), user.c_str(), ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
}

bool RawEventProcessor::add_gid_field(const char* name, int gid, field_type_t ft) {
    _tmp_val.assign(std::to_string(gid));
    std::string user = _user_db->GetGroupName(gid);
    int ret = _builder->AddField(name, _tmp_val.c_str(), user.c_str(), ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
}

bool RawEventProcessor::generate_proc_event(ProcessInfo* pinfo, uint64_t sec, uint32_t nsec) {
    auto ret = _builder->BeginEvent(sec, nsec, 0, 1);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }

    _builder->SetEventFlags(EVENT_FLAG_IS_AUOMS_EVENT);

    uint16_t num_fields = 16;

    ret = _builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_PROCESS_INVENTORY), LookupTables::RecordTypeCodeToString(RecordType::AUOMS_PROCESS_INVENTORY), "", num_fields);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    if (!add_int_field("pid", pinfo->pid(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_int_field("ppid", pinfo->ppid(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_int_field("ses", pinfo->ses(), field_type_t::SESSION)) {
        return false;
    }

    if (!add_str_field("starttime", pinfo->starttime().c_str(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_uid_field("uid", pinfo->uid(), field_type_t::UID)) {
        return false;
    }

    if (!add_uid_field("euid", pinfo->euid(), field_type_t::UID)) {
        return false;
    }

    if (!add_uid_field("suid", pinfo->suid(), field_type_t::UID)) {
        return false;
    }

    if (!add_uid_field("fsuid", pinfo->fsuid(), field_type_t::UID)) {
        return false;
    }

    if (!add_gid_field("gid", pinfo->gid(), field_type_t::GID)) {
        return false;
    }

    if (!add_gid_field("egid", pinfo->egid(), field_type_t::GID)) {
        return false;
    }

    if (!add_gid_field("sgid", pinfo->sgid(), field_type_t::GID)) {
        return false;
    }

    if (!add_gid_field("fsgid", pinfo->fsgid(), field_type_t::GID)) {
        return false;
    }

    if (!add_str_field("comm", pinfo->comm().c_str(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_str_field("exe", pinfo->exe().c_str(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    pinfo->format_cmdline(_cmdline);

    bool cmdline_truncated = false;
    if (_cmdline.size() > UINT16_MAX-1) {
        _cmdline.resize(UINT16_MAX-1);
        cmdline_truncated = true;
    }

    if (!add_str_field("cmdline", _cmdline.c_str(), field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!add_str_field("cmdline_truncated", cmdline_truncated ? "true" : "false", field_type_t::UNCLASSIFIED)) {
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
}

void RawEventProcessor::DoProcessInventory() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);

    uint64_t sec = static_cast<uint64_t>(tv.tv_sec);
    uint32_t nsec = static_cast<uint32_t>(tv.tv_usec)*1000;

    if (_last_proc_fetch+PROCESS_INVENTORY_FETCH_INTERVAL > sec) {
        return;
    }

    bool gen_events = false;
    if (_last_proc_event_gen+PROCESS_INVENTORY_EVENT_INTERVAL <= sec) {
        gen_events = true;
    }

    bool update_filter = _procFilter->IsFilterEnabled();

    if (!update_filter && !gen_events) {
        return;
    }

    auto pinfo = ProcessInfo::Open();
    if (!pinfo) {
        Logger::Error("Failed to open '/proc': %s", strerror(errno));
        return;
    }

    std::vector<ProcInfo> procs;
    procs.reserve(16*1024);

    while(pinfo->next()) {
        if (update_filter) {
            procs.emplace(procs.end(), pinfo.get());
        }
        if (gen_events) {
            generate_proc_event(pinfo.get(), sec, nsec);
        }
    }

    if (update_filter) {
        _procFilter->UpdateProcesses(procs);
    }

    _last_proc_fetch = sec;
    if (gen_events) {
        _last_proc_event_gen = sec;
    }
}
