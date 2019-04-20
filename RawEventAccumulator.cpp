/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <sys/time.h>
#include "RawEventAccumulator.h"
#include "Translate.h"
#include "Logger.h"

bool RawEvent::AddRecord(std::unique_ptr<RawEventRecord> record) {
    auto rtype = record->GetRecordType();

    if (rtype == RecordType::EOE) {
        return true;
    }

    // Ignore the PROCTITLE record because we convert the EXECVE records into cmdline field.
    if (rtype == RecordType::PROCTITLE) {
        return false;
    }

    if (rtype == RecordType::EXECVE) {
        _num_execve_records++;
        if (_num_execve_records == 1) {
            _size += record->GetSize();
            _execve_size += record->GetSize();
            _records.emplace_back(std::move(record));
        } else {
            if (record->GetSize()+_size > MAX_EVENT_SIZE || record->GetSize()+_execve_size > MAX_EXECVE_ACCUM_SIZE || _num_execve_records > MAX_NUM_EXECVE_RECORDS) {
                _num_dropped_records++;
                _drop_count[rtype]++;
                size_t idx = 0;
                if (_execve_records.size() > NUM_EXECVE_RH_PRESERVE) {
                    idx = _execve_records.size() - NUM_EXECVE_RH_PRESERVE - 1;
                }
                _size-=_execve_records[idx]->GetSize();
                _execve_size-=_execve_records[idx]->GetSize();
                _execve_records.erase(_execve_records.begin()+idx);
            }
            _size += record->GetSize();
            _execve_size += record->GetSize();
            _execve_records.emplace_back(std::move(record));
        }
        return false;
    }

    if (record->GetSize()+_size > MAX_EVENT_SIZE || _num_execve_records > MAX_NUM_EXECVE_RECORDS) {
        _num_dropped_records++;
        _drop_count[rtype]++;
    } else {
        _size += record->GetSize();
        _records.emplace_back(std::move(record));
    }

    if (rtype < RecordType::FIRST_EVENT ||
        rtype >= RecordType::FIRST_ANOM_MSG ||
        rtype == RecordType::KERNEL) {
        return true;
    }

    return false;
}

int RawEvent::AddEvent(EventBuilder& builder) {
    if (_records.empty() && _num_dropped_records == 0) {
        return 1;
    }
    auto ret = builder.BeginEvent(_event_id.Seconds(), _event_id.Milliseconds(), _event_id.Serial(), static_cast<uint16_t>(_records.size()+_execve_records.size()));
    if (ret != 1) {
        return ret;
    }
    for (std::unique_ptr<RawEventRecord>& rec: _records) {
        ret = rec->AddRecord(builder);
        if (ret != 1) {
            builder.CancelEvent();
            return ret;
        }
        if (rec->GetRecordType() == RecordType::EXECVE) {
            for (std::unique_ptr<RawEventRecord>& rec: _execve_records) {
                ret = rec->AddRecord(builder);
                if (ret != 1) {
                    builder.CancelEvent();
                    return ret;
                }
            }
        }
    }
    if (_num_dropped_records > 0 && _drop_count.size() > 0) {
        ret = builder.BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_DROPPED_RECORDS), std::string_view(RecordTypeToName(RecordType::AUOMS_DROPPED_RECORDS)), std::string_view(""), static_cast<uint16_t>(_drop_count.size()));
        if (ret != 1) {
            builder.CancelEvent();
            return ret;
        }
        for (auto& e: _drop_count) {
            ret = builder.AddField(RecordTypeToName(e.first), std::to_string(e.second), "", field_type_t::UNCLASSIFIED);
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
    std::lock_guard<std::mutex> lock(_mutex);

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

void RawEventAccumulator::Flush(long milliseconds) {
    if (milliseconds > 0) {
        struct timeval tv;
        gettimeofday(&tv, nullptr);

        auto sec = static_cast<uint64_t>(tv.tv_sec);
        uint32_t msec = static_cast<uint32_t>(tv.tv_usec) / 1000;

        if (msec < milliseconds) {
        } else {
            sec -= 1;
            msec += 1000;
        }
        msec -= milliseconds;

        EventId oldest(sec, msec, 0);

        std::lock_guard<std::mutex> lock(_mutex);

        // Flush any events older than oldest;
        while (!_events.empty()) {
            auto itr = _events.begin();
            if (itr->first > oldest) {
                return;
            }
            itr->second->AddEvent(*_builder);
            _events.erase(itr);
        }
    } else {
        for (auto& e: _events) {
            e.second->AddEvent(*_builder);
        }
        _events.clear();
    }
}
