/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "OMSEventTransformer.h"

#include "Logger.h"

#include <string>
#include <vector>
#include <sstream>

void OMSEventTransformer::ProcessEvent(const Event& event)
{
    auto num_records = event.NumRecords();

    _sink->BeginMessage(_tag, event.Seconds(), event.Milliseconds());
    _sink->AddStringField(_config.MsgTypeFieldName, "AUDIT_EVENT");
    _sink->AddTimestampField(_config.TimestampFieldName, event.Seconds(), event.Milliseconds());
    _sink->AddInt64Field(_config.SerialFieldName, event.Serial());
    _sink->AddInt32Field(_config.RecordCountFieldName, num_records);

    int idx = 0;
    try {
        for (auto rec : event) {
            int record_type = rec.RecordType();
            std::string record_name = std::string(rec.RecordTypeName(), rec.RecordTypeNameSize());
            if (!_config.RecordTypeNameOverrideMap.empty()) {
                auto it = _config.RecordTypeNameOverrideMap.find(record_type);
                if (it != _config.RecordTypeNameOverrideMap.end()) {
                    record_name = it->second;
                }
            }

            process_record(rec, idx, record_type, record_name);
            idx++;
        }
    } catch (const std::exception& ex) {
        Logger::Warn("Unexpected exception while processing event: %s", ex.what());
        _sink->CancelMessage();
        return;
    }

    _sink->EndMessage();
}

void OMSEventTransformer::ProcessEventsGap(const EventGapReport& gap)
{
    _sink->BeginMessage(_tag, gap.sec, gap.msec);
    _sink->AddTimestampField(_config.TimestampFieldName, gap.sec, gap.msec);
    _sink->AddStringField(_config.MsgTypeFieldName, "AUDIT_EVENT_GAP");
    _sink->AddTimeField("Start" + _config.TimestampFieldName, gap.start_sec, gap.start_msec);
    _sink->AddInt64Field("Start" + _config.SerialFieldName, gap.start_serial);
    _sink->AddTimeField("End" + _config.TimestampFieldName, gap.end_sec, gap.end_msec);
    _sink->AddInt64Field("End" + _config.SerialFieldName, gap.end_serial);
    _sink->EndMessage();
}

static void decode_hex(std::string& out, const std::string& hex, const std::string null_replacement)
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

static void unescape(std::string& out, const std::string& in, const std::string null_replacement)
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

void OMSEventTransformer::process_record(const EventRecord& rec, int record_idx, int record_type, const std::string& record_name)
{
    _field_name.clear();

    _json_buffer.BeginMessage();
    _json_buffer.AddInt32Field(_config.RecordTypeFieldName, static_cast<int32_t>(record_type));
    _json_buffer.AddStringField(_config.RecordTypeNameFieldName, record_name);

    for (auto field : rec) {
        process_field(field);
    }

    if (_config.IncludeFullRawText) {
        _json_buffer.AddStringField(_config.RawTextFieldName, std::string(rec.RecordText(), rec.RecordTextSize()));
    }

    _json_buffer.EndMessage();

    _sink->AddStringField(_config.RecordDataFieldNamePrefix + std::to_string(record_idx), _json_buffer.GetString(), _json_buffer.GetSize());
}

void OMSEventTransformer::process_field(const EventRecordField& field)
{
    _field_name.assign(field.FieldName(), field.FieldNameSize());

    if (!_config.FieldNameOverrideMap.empty()) {
        auto it = _config.FieldNameOverrideMap.find(_field_name);
        if (it != _config.FieldNameOverrideMap.end()) {
            _raw_name.assign(it->second);
        } else {
            _raw_name.assign(_field_name);
        }
    } else {
        _raw_name.assign(_field_name);
    }

    if (!_config.InterpFieldNameMap.empty()) {
        auto it = _config.InterpFieldNameMap.find(_field_name);
        if (it != _config.InterpFieldNameMap.end()) {
            _interp_name.assign(it->second);
        } else {
            _interp_name.assign(_raw_name);
        }
    } else {
        _interp_name.assign(_raw_name);
    }

    _raw_value.assign(field.RawValue(), field.RawValueSize());

    if (field.FieldType() == FIELD_TYPE_ESCAPED) {
        // If the field type is FIELD_TYPE_ESCAPED, then there is no interp value.
        unescape(_value1, _raw_value, _config.NullReplacement);
        _json_buffer.AddStringField(_raw_name, _value1);
        if (_raw_name == _interp_name) {
            _raw_name.append(_config.FieldSuffix);
        }
        _json_buffer.AddStringField(_raw_name, _raw_value);
    } else {
        if (field.InterpValueSize() > 0) {
            _value2.assign(field.InterpValue(), field.InterpValueSize());
            _json_buffer.AddStringField(_interp_name, _value2);
            if (_value2 != _raw_value) {
                if (_raw_name == _interp_name) {
                    _raw_name.append(_config.FieldSuffix);
                }
                _json_buffer.AddStringField(_raw_name, _raw_value);
            }
        } else {
            _json_buffer.AddStringField(_raw_name, _raw_value);
        }
    }

}
