/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "OMSEventWriter.h"

#include "Logger.h"
#include "StringUtils.h"

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

ssize_t OMSEventWriter::write_event(IWriter* writer) {
    return writer->WriteAll(_buffer.GetString(), _buffer.GetSize());
}

void OMSEventWriter::reset()
{
    _buffer.Clear();
    _writer.Reset(_buffer);
}

void OMSEventWriter::begin_array() {
    _writer.StartArray();
}

void OMSEventWriter::end_array() {
    _writer.EndArray();
}

void OMSEventWriter::begin_object() {
    _writer.StartObject();
}

void OMSEventWriter::end_object() {
    _writer.EndObject();
}

void OMSEventWriter::add_int32_field(const std::string& name, int32_t value)
{
    if (_config.FilterFieldNameSet.count(name) == 0) {
        _writer.Key(name.c_str(), name.size(), true);
        _writer.Int(value);
    }
}

void OMSEventWriter::add_int64_field(const std::string& name, int64_t value)
{
    if (_config.FilterFieldNameSet.count(name) == 0) {
        _writer.Key(name.c_str(), name.size(), true);
        _writer.Int64(value);
    }
}

void OMSEventWriter::add_double(double value)
{
    _writer.Double(value);
}

void OMSEventWriter::add_string(const std::string& value)
{
    _writer.String(value.c_str(), value.size(), true);
}

void OMSEventWriter::add_string_field(const std::string& name, const std::string& value)
{
    if (_config.FilterFieldNameSet.count(name) == 0) {
        _writer.Key(name.c_str(), name.size(), true);
        _writer.String(value.c_str(), value.size(), true);
    }
}

void OMSEventWriter::add_string_field(const std::string& name, const char* value_data, size_t value_size)
{
    if (_config.FilterFieldNameSet.count(name) == 0) {
        _writer.Key(name.c_str(), name.size(), true);
        _writer.String(value_data, value_size, true);
    }
}

ssize_t OMSEventWriter::WriteEvent(const Event& event, IWriter* writer)
{
    std::ostringstream timestamp_str;

    if ((event.Flags() & _config.FilterFlagsMask) != 0) {
        return IWriter::OK;
    }

    double time = static_cast<double>(event.Seconds());
    time += static_cast<double>(event.Milliseconds())/1000;
    reset();
    begin_array(); // Message
    add_double(time);
    begin_object(); // Event

    if ((event.Flags() & EVENT_FLAG_IS_AUOMS_EVENT) != 0) {
        add_string_field(_config.MsgTypeFieldName, "AUOMS_EVENT");
    } else {
        add_string_field(_config.MsgTypeFieldName, "AUDIT_EVENT");
    }

    timestamp_str << event.Seconds() << "."
                 << std::setw(3) << std::setfill('0')
                 << event.Milliseconds();

    add_string_field(_config.TimestampFieldName, timestamp_str.str());
    add_int64_field(_config.SerialFieldName, event.Serial());
    add_int64_field(_config.ProcessFlagsFieldName, event.Flags()>>16);
    add_string(_config.RecordsFieldName);

    int records = 0;

    try {
        begin_array(); // Records
        for (auto rec : event) {
            int record_type = rec.RecordType();
            std::string record_type_name = std::string(rec.RecordTypeNamePtr(), rec.RecordTypeNameSize());
            // Exclude the EOE (end-of-event) record
            if (!_config.RecordTypeNameOverrideMap.empty()) {
                auto it = _config.RecordTypeNameOverrideMap.find(record_type);
                if (it != _config.RecordTypeNameOverrideMap.end()) {
                    record_type_name = it->second;
                }
            }

            if (_config.FilterRecordTypeSet.count(record_type_name) == 0) {
                process_record(rec, record_type, record_type_name);
                records++;
            }
        }
        end_array(); // Records
    } catch (const std::exception& ex) {
        Logger::Warn("Unexpected exception while processing event: %s", ex.what());
        return IWriter::FAILED;
    }

    end_object(); // Event
    end_array(); // Message

    if (records == 0) {
        return IWriter::OK;
    }
    return write_event(writer);
}

void OMSEventWriter::process_record(const EventRecord& rec, int record_type, const std::string& record_type_name)
{
    _field_name.clear();

    begin_object();
    add_int32_field(_config.RecordTypeFieldName, static_cast<int32_t>(record_type));
    add_string_field(_config.RecordTypeNameFieldName, record_type_name);

    for (auto field : rec) {
        process_field(field);
    }

    end_object();
}

void OMSEventWriter::process_field(const EventRecordField& field)
{
    _field_name.assign(field.FieldNamePtr(), field.FieldNameSize());

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

    if (_raw_name == _interp_name) {
        _raw_name.append(_config.FieldSuffix);
    }

    if (field.FieldType() == field_type_t::ESCAPED || field.FieldType() == field_type_t::PROCTITLE) {
        // If the field type is FIELD_TYPE_ESCAPED, then there is no interp value in the event.
        switch (unescape_raw_field(_interp_value, field.RawValuePtr(), field.RawValueSize())) {
            case -1: // _interp_value is identical to _raw_value
            case 0: // _raw_value was "(null)"
            default:
                add_string_field(_interp_name, field.RawValuePtr(), field.RawValueSize());
                break;
            case 1: // _raw_value was double quoted
            case 2: // _raw_value was hex encoded
                add_string_field(_interp_name, _interp_value);
                break;
            case 3: // _raw_value was hex encoded and decoded string needs escaping
                tty_escape_string(_escaped_value, _interp_value.data(), _interp_value.size());
                add_string_field(_interp_name, _escaped_value);
                break;
        }
    } else {
        if (field.InterpValueSize() > 0) {
            switch (field.FieldType()) {
                case field_type_t::SESSION:
                    // Since the interpreted value for SES is also (normally) an int
                    // Replace "unset" and "4294967295" with "-1"
                    if ((field.InterpValueSize() == 5 && std::strncmp("unset", field.InterpValuePtr(), field.InterpValueSize()) == 0) ||
                            (field.InterpValueSize() == 10 && strncmp("4294967295", field.InterpValuePtr(), field.InterpValueSize()) == 0)) {
                        add_string_field(_interp_name, "-1");
                    } else {
                        add_string_field(_interp_name, field.InterpValuePtr(), field.InterpValueSize());
                    }
                    break;
                default:
                    add_string_field(_interp_name, field.InterpValuePtr(), field.InterpValueSize());
            }
            add_string_field(_raw_name, field.RawValuePtr(), field.RawValueSize());
        } else {
            // Use interp name for raw value because there is no interp value
            add_string_field(_interp_name, field.RawValuePtr(), field.RawValueSize());
        }
    }
}
