/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_TESTEVENTDATA_H
#define AUOMS_TESTEVENTDATA_H

#include "TestEventQueue.h"
#include "EventWriterConfig.h"

struct TestEventField {
    TestEventField(const char* name, const char* raw, const char* interp, field_type_t field_type) {
        _name = name;
        _raw = raw;
        _interp = interp;
        _field_type = field_type;
    }
    const char* _name;
    const char* _raw;
    const char* _interp;
    field_type_t _field_type;

    void Write(const std::shared_ptr<EventBuilder>& builder) {
        builder->AddField(_name, _raw, _interp, _field_type);
    }
};

struct TestEventRecord {
    TestEventRecord(uint32_t type, const char* name, const char* text, const std::vector<TestEventField>& fields): _fields(fields) {
        _type = type;
        _name = name;
        _text = text;
    }
    uint32_t _type;
    const char* _name;
    const char* _text;
    std::vector<TestEventField> _fields;

    void Write(const std::shared_ptr<EventBuilder>& builder) {
        builder->BeginRecord(_type, _name, _text, static_cast<uint16_t>(_fields.size()));
        for (auto field : _fields) {
            field.Write(builder);
        }
        builder->EndRecord();
    }
};

struct TestEvent {
    TestEvent(uint64_t seconds,
              uint32_t milliseconds,
              uint64_t serial,
              uint32_t flags,
              int32_t pid,
              const std::vector<TestEventRecord>& records): _records(records)
    {
        _seconds = seconds;
        _milliseconds = milliseconds;
        _serial = serial;
        _flags = flags;
        _pid = pid;
    }

    uint64_t _seconds;
    uint32_t _milliseconds;
    uint64_t _serial;

    uint32_t _flags;
    int32_t _pid;
    std::vector<TestEventRecord> _records;

    void Write(const std::shared_ptr<EventBuilder>& builder) {
        builder->BeginEvent(_seconds, _milliseconds, _serial, _records.size());
        builder->AddEventFlags(_flags);
        builder->SetEventPid(_pid);
        for (auto rec : _records) {
            rec.Write(builder);
        }
        builder->EndEvent();
    }
};

extern const std::string passwd_file_text;
extern const std::string group_file_text;

extern const std::string test_redaction_rule_filename;
extern const std::string test_redaction_rule_name;
extern const std::string test_redaction_rule_regex;
extern std::vector<const char*> raw_test_events;
extern const std::vector<bool> raw_events_do_flush;
extern const std::string oversized_event_text;
extern const std::vector<TestEvent> test_events;
extern const std::vector<const char*> oms_test_events;
extern const std::vector<const char*> fluent_test_events;
extern const std::vector<const char*> fluent_other_field_test_events;
extern const std::unordered_map<std::string, std::string> TestConfigFieldNameOverrideMap;
extern const std::unordered_map<std::string, std::string> TestConfigInterpFieldNameMap;
extern const std::unordered_set<std::string> TestConfigFilterRecordTypeSet;
extern const std::unordered_set<std::string> TestConfigFilterFieldNameSet;
extern const std::unordered_set<std::string> TestConfigInclusiveFieldNameSet;
extern const std::unordered_map<std::string, std::string> TestConfigAdditionalFieldsMap;
extern const std::string TestConfigHostnameValue;

#endif //AUOMS_TESTEVENTDATA_H
