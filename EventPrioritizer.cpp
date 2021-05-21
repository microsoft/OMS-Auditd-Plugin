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
#include "StringUtils.h"

template <typename T>
inline bool field_to_int(const EventRecordField& field, T& val, int base) {
    errno = 0;
    val = static_cast<T>(strtol(field.RawValuePtr(), nullptr, base));
    return errno == 0;
}

template <typename T>
inline bool field_to_uint(const EventRecordField& field, T& val, int base) {
    errno = 0;
    val = static_cast<T>(strtoul(field.RawValuePtr(), nullptr, base));
    return errno == 0;
}

void interpret_syscall_field(std::string& syscall_name, const EventRecord& record) {
    static std::string_view SV_SYSCALL = "syscall";
    static std::string_view SV_ARCH = "arch";

    auto syscall_field = record.FieldByName(SV_SYSCALL);
    if (!syscall_field) {
        syscall_name = "unknown-syscall()";
        return;
    }
    auto arch_field = record.FieldByName(SV_ARCH);
    if (!arch_field) {
        syscall_name = "unknown-syscall(" + std::string(syscall_field.RawValue()) + ")";
        return;
    }
    uint32_t arch;
    if (!field_to_uint(arch_field, arch, 16)) {
        arch = 0;
    }
    auto mt = ArchToMachine(arch);
    if (mt == MachineType::UNKNOWN) {
        syscall_name = "unknown-syscall(" + std::string(syscall_field.RawValue()) + ")";
        return;
    }

    int syscall;
    if (field_to_int(syscall_field, syscall, 10)) {
        SyscallToName(mt, syscall, syscall_name);
    } else {
        syscall_name = "unknown-syscall(" + std::string(syscall_field.RawValue()) + ")";
    }
}


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
                Logger::Warn("Invalid Record Type Name in 'event_priority_by_record_type' in config: %s",
                             rt_name.c_str());
                return false;
            }
            _record_type_priorities.emplace(std::make_pair(rt, it->value.GetUint()));
        }
    }

    if (config.HasKey("event_priority_by_record_type_category")) {
        auto doc = config.GetJSON("event_priority_by_record_type_category");
        if (!doc.IsObject()) {
            return false;
        }
        for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
            if (!it->name.IsString() || !it->value.IsInt()) {
                Logger::Warn("Invalid value in 'event_priority_by_record_type' in config");
                return false;
            }
            auto rt_name = std::string(it->name.GetString(), it->name.GetStringLength());
            auto rt = RecordTypeCategoryNameToCategory(rt_name);
            if (rt == RecordTypeCategory::UNKNOWN) {
                Logger::Warn("Invalid Record Type Category Name in 'event_priority_by_record_type_category' in config: %s",
                             rt_name.c_str());
                return false;
            }
            _record_type_category_priorities.emplace(std::make_pair(rt, it->value.GetUint()));
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
            auto sc_name = std::string(it->name.GetString(), it->name.GetStringLength());
            _syscall_priorities.emplace(std::make_pair(sc_name, it->value.GetUint()));
        }
    }

    return true;
}

uint16_t EventPrioritizer::Prioritize(const Event& event) {
    static std::string S_EXECVE = "execve";
    static std::string S_STAR = "*";

    auto rec1 = event.begin();

    if (static_cast<RecordType>(rec1.RecordType()) == RecordType::AUOMS_EXECVE) {
        auto itr = _syscall_priorities.find(S_EXECVE);
        if (itr != _syscall_priorities.end()) {
            return itr->second;
        }
        itr = _syscall_priorities.find(S_STAR);
        if (itr != _syscall_priorities.end()) {
            return itr->second;
        }
    } else if (static_cast<RecordType>(rec1.RecordType()) == RecordType::SYSCALL ||
        static_cast<RecordType>(rec1.RecordType()) == RecordType::AUOMS_SYSCALL) {
        _syscall_name.resize(0);
        interpret_syscall_field(_syscall_name, rec1);
        auto itr = _syscall_priorities.find(_syscall_name);
        if (itr != _syscall_priorities.end()) {
            return itr->second;
        }
        itr = _syscall_priorities.find(S_STAR);
        if (itr != _syscall_priorities.end()) {
            return itr->second;
        }
    } else {
        auto itr = _record_type_priorities.find(static_cast<RecordType>(rec1.RecordType()));
        if (itr != _record_type_priorities.end()) {
            return itr->second;
        }
        auto rtc = RecordTypeToCategory(static_cast<RecordType>(rec1.RecordType()));
        auto itr2 = _record_type_category_priorities.find(rtc);
        if (itr2 != _record_type_category_priorities.end()) {
            return itr2->second;
        }
    }

    return _default_priority;
}
