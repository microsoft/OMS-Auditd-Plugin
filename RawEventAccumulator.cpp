/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "RawEventAccumulator.h"
#include "Logger.h"

bool RawEvent::AddRecord(std::unique_ptr<RawEventRecord> record) {
    auto rtype = record->GetRecordType();

    if (rtype == RecordType::EOE) {
        return true;
    }

    if (rtype == RecordType::EXECVE) {
        _num_execve_records++;
    }

    if (record->GetSize()+_size > MAX_EVENT_SIZE || _num_execve_records > MAX_NUM_EXECVE_RECORDS) {
        _num_dropped_records++;
        _drop_count[rtype]++;
    } else {
        _size += record->GetSize();
        _records.emplace_back(std::move(record));
    }

    if (rtype == RecordType::PROCTITLE ||
        rtype < RecordType::FIRST_EVENT ||
        rtype >= RecordType::FIRST_ANOM_MSG ||
        rtype == RecordType::KERNEL) {
        return true;
    }

    return false;
}

int RawEvent::AddEvent(EventBuilder& builder) {
    auto ret = builder.BeginEvent(_event_id.Seconds(), _event_id.Milliseconds(), _event_id.Seconds(), static_cast<uint16_t>(_records.size()));
    if (ret != 1) {
        return ret;
    }
    for (std::unique_ptr<RawEventRecord>& rec: _records) {
        ret = rec->AddRecord(builder);
        if (ret != 1) {
            builder.CancelEvent();
            return ret;
        }
    }
    if (_num_dropped_records > 0) {
        ret = builder.BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_DROPPED_RECORDS), std::string_view(LookupTables::RecordTypeCodeToString(RecordType::AUOMS_DROPPED_RECORDS)), std::string_view(""), static_cast<uint16_t>(_drop_count.size()));
        if (ret != 1) {
            builder.CancelEvent();
            return ret;
        }
        for (auto& e: _drop_count) {
            ret = builder.AddField(LookupTables::RecordTypeCodeToString(e.first), std::to_string(e.second), "", field_type_t::UNCLASSIFIED);
            if (ret != 1) {
                builder.CancelEvent();
                return ret;
            }
        }
        ret = builder.EndRecord();
        if (ret != 1) {
            builder.CancelEvent();
            return ret;
        }
    }
    return builder.EndEvent();
}

int RawEventAccumulator::AddRecord(std::unique_ptr<RawEventRecord> record) {
    auto event_id = record->GetEventId();
    auto itr = _events.find(event_id);
    if (itr != _events.end()) {
        if (itr->second->AddRecord(std::move(record))) {
            auto ret = itr->second->AddEvent(*_builder);
            _events.erase(itr);
            return ret;
        }
    } else {
        auto event = std::make_unique<RawEvent>(record->GetEventId());
        if (event->AddRecord(std::move(record))) {
            return event->AddEvent(*_builder);
        } else {
            _events.emplace(std::make_pair(event_id, std::move(event)));
        }
    }
    return 1;
}

int RawEventAccumulator::Flush() {
    for (auto& e : _events) {
        e.second->AddEvent(*_builder);
    }
    _events.clear();
}
