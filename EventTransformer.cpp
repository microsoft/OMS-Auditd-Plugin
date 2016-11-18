/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "EventTransformer.h"

#include "Logger.h"

#include <vector>
#include <sstream>

void EventTransformer::ProcessEvent(const Event& event)
{
    auto num_records = event.NumRecords();

    std::vector<int> record_types;
    std::vector<std::string> record_names;
    std::unordered_map<std::string, int> record_type_counts;
    std::unordered_map<std::string, int> record_type_indexes;

    record_types.reserve(num_records);
    record_names.reserve(num_records);

    int idx = 0;
    for (auto rec : event) {
        int record_type = rec.RecordType();
        std::string record_name = std::string(rec.RecordTypeName(), rec.RecordTypeNameSize());
        if (!_config.RecordTypeNameOverrideMap.empty()) {
            auto it = _config.RecordTypeNameOverrideMap.find(record_type);
            if (it != _config.RecordTypeNameOverrideMap.end()) {
                record_name = it->second;
            }
        }
        record_types.push_back(record_type);
        record_names.push_back(record_name);
        record_type_counts[record_name]++;
        idx++;
    }

    if (!_config.MsgPerRecord) {
        begin_message(event);

        _sink->AddInt32Field(_config.RecordCountFieldName, num_records);
        {
            std::ostringstream out;
            bool first = true;
            for (auto record_type : record_types) {
                if (!first) { out << ","; }
                first = false;
                out << record_type;
            }
            _sink->AddStringField(_config.RecordTypeFieldName, out.str());
        }
        {
            std::ostringstream out;
            bool first = true;
            for (auto record_name : record_names) {
                if (!first) { out << ","; }
                first = false;
                out << record_name;
            }
            _sink->AddStringField(_config.RecordNameFieldName, out.str());
        }
    }

    idx = 0;
    try {
        for (auto rec : event) {
            auto record_type = record_types[idx];
            auto record_name = record_names[idx];
            auto record_type_idx = record_type_indexes[record_name];
            record_type_indexes[record_name]++;

            if (_config.MsgPerRecord) {
                begin_message(event);
            }

            process_record(rec, idx, record_type, record_name, record_type_idx, record_type_counts[record_name]);
            idx++;

            if (_config.MsgPerRecord) {
                end_message(event);
            }
        }
    } catch (const std::exception& ex) {
        Logger::Warn("Unexpected exception while processing event: %s", ex.what());
        cancel_message();
        return;
    }

    if (!_config.MsgPerRecord) {
        end_message(event);
    }
}

void EventTransformer::ProcessEventsGap(const EventGapReport& gap)
{
    _sink->BeginMessage(_tag, gap.sec, gap.msec);
    _sink->AddTimestampField(_config.TimestampFieldName, gap.sec, gap.msec);
    _sink->AddStringField(_config.MsgTypeFieldName, "AUDIT_EVENT_GAP");
    _sink->AddTimeField("START" + _config.FieldNameSeparator + _config.TimestampFieldName, gap.start_sec, gap.start_msec);
    _sink->AddInt64Field("START" + _config.FieldNameSeparator + _config.SerialFieldName, gap.start_serial);
    _sink->AddTimeField("END" + _config.FieldNameSeparator + _config.TimestampFieldName, gap.end_sec, gap.end_msec);
    _sink->AddInt64Field("END" + _config.FieldNameSeparator + _config.SerialFieldName, gap.end_serial);
    _sink->EndMessage();
}

void decode_hex(std::string& out, const std::string& hex, const std::string null_replacement)
{
    if (out.capacity() < hex.length()) {
        out.reserve(hex.length());
    }

    char c = 0;
    int i = 0;
    for (auto hex_c : hex) {
        char x;
        if (hex_c >= '0' && hex_c <= '9') {
            x = hex_c - '0';
        } else if (hex_c >= 'A' && hex_c <= 'F') {
            x = hex_c - 'A' + (char)10;
        } else if (hex_c >= 'f' && hex_c <= 'f') {
            x = hex_c - 'a' + (char)10;
        } else {
            // This isn't HEX, just return the original input
            out = hex;
            return;
        }
        if (i % 2 == 0) {
            c = x << 4;
        } else {
            c |= x;
            if (c != 0) {
                out += c;
            } else {
                out.append(null_replacement);
            }
        }
        ++i;
    }
    return;
}

void unescape(std::string& out, const std::string& in, const std::string null_replacement)
{
    if (in.front() == '"' && in.back() == '"') {
        out = in.substr(1, in.size() - 2);
    } else if (in == "(null)") {
        out = in;
    } else if (in.size() % 2 == 0) {
        decode_hex(out, in, null_replacement);
    } else {
        out = in;
    }
}

void EventTransformer::begin_message(const Event& event)
{
    _sink->BeginMessage(_tag, event.Seconds(), event.Milliseconds());
    _sink->AddTimestampField(_config.TimestampFieldName, event.Seconds(), event.Milliseconds());
    _sink->AddInt64Field(_config.SerialFieldName, event.Serial());
    if (_config.MsgPerRecord) {
        _sink->AddStringField(_config.MsgTypeFieldName, "AUDIT_EVENT_RECORD");
    } else {
        _sink->AddStringField(_config.MsgTypeFieldName, "AUDIT_EVENT");
    }
}

void EventTransformer::end_message(const Event& event)
{
    _sink->EndMessage();
}

void EventTransformer::cancel_message()
{
    _sink->CancelMessage();
}

void EventTransformer::process_record(const EventRecord& rec, int record_idx, int record_type, const std::string& record_name, int record_type_idx, int record_type_count)
{
    _field_name.clear();
    if (_config.MsgPerRecord) {
        _sink->AddInt32Field(_config.RecordTypeFieldName, static_cast<int32_t>(record_type));
        _sink->AddStringField(_config.RecordNameFieldName, record_name);
    } else {
        switch (_config.FieldPrefixMode) {
            case EventTransformerConfig::PREFIX_RECORD_INDEX:
                _field_name.append(std::to_string(record_idx));
                _field_name.append(_config.FieldNameSeparator);
                break;
            case EventTransformerConfig::PREFIX_RECORD_TYPE_NUMBER:
                _field_name.append(std::to_string(record_type));
                _field_name.append(_config.FieldNameSeparator);
                break;
            case EventTransformerConfig::PREFIX_RECORD_TYPE_NAME:
                _field_name.append(record_name);
                _field_name.append(_config.FieldNameSeparator);
                break;
        }
        if (_config.FieldPrefixMode != EventTransformerConfig::PREFIX_RECORD_INDEX && record_type_count > 1) {
            int idx;
            if (_config.FieldNameDedupIndexGlobal) {
                idx = record_idx;
            } else {
                idx = record_type_idx;
            }
            if (_config.FieldNameDedupIndexOneBased) {
                idx++;
            }
            _field_name.append(std::to_string(idx));
            _field_name.append(_config.FieldNameSeparator);
        }
    }

    if (_config.IncludeFullRawText) {
        auto fsize = _field_name.size();
        _field_name.append(_config.RawTextFieldName);
        _sink->AddStringField(_field_name, std::string(rec.RecordText(), rec.RecordTextSize()));
        _field_name.resize(fsize);
    }

    for (auto field : rec) {
        auto fsize = _field_name.size();
        process_field(field);
        _field_name.resize(fsize);
    }
}

void EventTransformer::process_field(const EventRecordField& field)
{
    auto psize = _field_name.size();
    if (_config.FieldNameOverrideMap.empty()) {
        _field_name.append(field.FieldName(), field.FieldNameSize());
    } else {
        _field_name_temp.assign(field.FieldName(), field.FieldNameSize());
        auto it = _config.FieldNameOverrideMap.find(_field_name_temp);
        if (it != _config.FieldNameOverrideMap.end()) {
            _field_name.append(it->second);
        }
    }
    auto fsize = _field_name.size();

    _raw_value.assign(field.RawValue(), field.RawValueSize());

    if ((_config.FieldEmitMode & EventTransformerConfig::EMIT_RAW) != 0) {
        if (_config.FieldEmitMode == EventTransformerConfig::EMIT_BOTH && _config.FieldNameDedupSuffixRawField) {
            _field_name.append(_config.FieldSuffix);
        }

        if (field.FieldType() == FIELD_TYPE_ESCAPED && _config.DecodeEscapedFieldValues) {
            unescape(_value1, _raw_value, _config.NullReplacement);
            _sink->AddStringField(_field_name, _value1);
        } else {
            _sink->AddStringField(_field_name, _raw_value);
        }

        _field_name.resize(fsize);
    }

    // If the field type is FIELD_TYPE_ESCAPED, then there is no interp value.
    if ((_config.FieldEmitMode & EventTransformerConfig::EMIT_INTERP) != 0 && field.InterpValueSize() > 0) {
        if (_config.InterpFieldNameMap.empty()) {
            if (_config.FieldEmitMode == EventTransformerConfig::EMIT_BOTH && !_config.FieldNameDedupSuffixRawField) {
                _field_name.append(_config.FieldSuffix);
            }
        } else {
            _field_name.resize(psize);
            _field_name_temp.assign(field.FieldName(), field.FieldNameSize());
            auto it = _config.InterpFieldNameMap.find(_field_name_temp);
            if (it != _config.InterpFieldNameMap.end()) {
                _field_name.append(it->second);
            }
        }

        _value2.assign(field.InterpValue(), field.InterpValueSize());
        if (_value2 == _raw_value) {
            // Don't emit the interpreted field if it matches the raw field.
            return;
        }
        _sink->AddStringField(_field_name, _value2);
    }
}
