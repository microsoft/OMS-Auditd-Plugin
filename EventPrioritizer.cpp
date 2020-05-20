/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "EventPrioritizer.h"

#include "Logger.h"
#include "Translate.h"

bool EventPrioritizer::LoadFromConfig(Config& config) {

    if (config.HasKey("default_event_priority")) {
        _default_priority = config.GetUint64("default_event_priority");
    }

    if (config.HasKey("event_priority_by_record_type")) {
        auto doc = config.GetJSON("event_priority_by_record_type");
        if (!doc.IsObject()) {
            return false;
        }
        for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
            if (!it->name.IsString() || !it->value.IsInt()) {
                Logger::Warn("Invalid value in 'event_priority_by_record_type' in config");
                return false;
            }
            auto rt_name = std::string(it->name.GetString(), it->name.GetStringLength());
            auto rt = RecordNameToType(rt_name);
            if (rt == RecordType::UNKNOWN) {
                Logger::Warn("Invalid Record Type Name in 'event_priority_by_record_type' in config: %s", rt_name.c_str());
                return false;
            }
            _record_type_priorities.emplace(std::make_pair(rt, it->value.GetUint()));
        }
    }

    if (config.HasKey("event_priority_by_syscall")) {
        auto doc = config.GetJSON("event_priority_by_syscall");
        if (!doc.IsObject()) {
            return false;
        }
        for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
            if (!it->name.IsString() || !it->value.IsInt()) {
                Logger::Warn("Invalid value in 'event_priority_by_syscall' in config");
                return false;
            }
            auto sc = std::string(it->name.GetString(), it->name.GetStringLength());
            auto sc_num = SyscallNameToNumber(DetectMachine(), sc);
            if (sc_num < 0) {
                errno = 0;
                sc_num = static_cast<int>(strtol(sc.c_str(), nullptr, 10));
                if (errno != 0) {
                    Logger::Warn("Invalid Syscall in 'event_priority_by_syscall' in config: %s", sc.c_str());
                    return false;
                }
            }
            _syscall_priorities.emplace(std::make_pair(sc_num, it->value.GetUint()));
        }
    }

    return true;
}

uint16_t EventPrioritizer::Prioritize(const Event& event) {
    static std::string_view SV_SYSCALL = "syscall";

    auto rec1 = event.begin();

    if (static_cast<RecordType>(rec1.RecordType()) == RecordType::SYSCALL) {
        auto syscall_field = rec1.FieldByName(SV_SYSCALL);
        if (syscall_field) {
            errno = 0;
            int syscall = static_cast<int>(strtol(syscall_field.RawValuePtr(), nullptr, 10));
            if (errno == 0) {
                auto itr = _syscall_priorities.find(syscall);
                if (itr != _syscall_priorities.end()) {
                    return itr->second;
                }
            }
        }
    } else {
        auto itr = _record_type_priorities.find(static_cast<RecordType>(rec1.RecordType()));
        if (itr != _record_type_priorities.end()) {
            return itr->second;
        }
    }

    return _default_priority;
}
