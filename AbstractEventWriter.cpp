/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "AbstractEventWriter.h"
#include "Logger.h"
#include "StringUtils.h"

ssize_t AbstractEventWriter::WriteEvent(const Event& event, IWriter* writer)
{
    try {
        if (!format_event(event)) {
            return IEventWriter::NOOP;
        }
        return write_event(writer);
    }
    catch (const std::exception& ex) {
        Logger::Warn("Unexpected exception while processing event: %s", ex.what());
        return IWriter::FAILED;
    }
}

bool AbstractEventWriter::format_event(const Event& event)
{
    if (!begin_event(event))
        return false;

    int records = 0;

    for (auto record : event) {
        if (format_record(record)) {
            records++;
        }
    }

    if (records > 0) {
        end_event(event);
        return true;
    }

    return false;
}

bool AbstractEventWriter::format_record(const EventRecord& record)
{
    int record_type = record.RecordType();
    std::string record_type_name = std::string(record.RecordTypeNamePtr(), record.RecordTypeNameSize());

    // apply record type name overrides
    if (!_config.RecordTypeNameOverrideMap.empty()) {
        auto it = _config.RecordTypeNameOverrideMap.find(record_type);
        if (it != _config.RecordTypeNameOverrideMap.end()) {
            record_type_name = it->second;
        }
    }

    // apply record type filters
    if (_config.IsRecordFiltered(record_type_name)) {
        return false;
    }

    _other_fields_initialized = false;

    if (!begin_record(record, record_type_name)) {
        return false;
    }

    format_string_field(_config.SchemaVersionFieldName, _config.SchemaVersion);

    for (auto& f : _config.AdditionalFieldsMap) {
        format_string_field(f.first, f.second);
    }

    for (auto field : record) {
        format_field(field);
    }

    if (_config.OtherFieldsMode && _other_fields_initialized) {
        _other_fields_writer.EndObject();
        _other_fields_initialized = false;
        format_raw_field(_config.OtherFieldsFieldName, _other_fields_buffer.GetString(), _other_fields_buffer.GetSize());
    }

    end_record(record);
    return true;
}

bool AbstractEventWriter::format_field(const EventRecordField& field)
{
    bool ret = false;

    static std::string S_NEG_ONE = "-1";

    std::string interp_name;
    std::string field_name;
    std::string raw_name;
    std::string escaped_value;
    std::string interp_value;

    field_name.assign(field.FieldNamePtr(), field.FieldNameSize());

    if (!_config.FieldNameOverrideMap.empty()) {
        auto it = _config.FieldNameOverrideMap.find(field_name);
        if (it != _config.FieldNameOverrideMap.end()) {
            raw_name.assign(it->second);
        } else {
            raw_name.assign(field_name);
        }
    } else {
        raw_name.assign(field_name);
    }

    if (!_config.InterpFieldNameMap.empty()) {
        auto it = _config.InterpFieldNameMap.find(field_name);
        if (it != _config.InterpFieldNameMap.end()) {
            interp_name.assign(it->second);
        } else {
            interp_name.assign(raw_name);
        }
    } else {
        interp_name.assign(raw_name);
    }

    if (raw_name == interp_name) {
        raw_name.append(_config.FieldSuffix);
    }

    if (field.FieldType() == field_type_t::ESCAPED || field.FieldType() == field_type_t::PROCTITLE) {
        // If the field type is FIELD_TYPE_ESCAPED, then there is no interp value in the event.
        switch (unescape_raw_field(interp_value, field.RawValuePtr(), field.RawValueSize())) {
            case -1: // _interp_value is identical to _raw_value
            case 0: // _raw_value was "(null)"
            default:
                maybe_format_raw_field(interp_name, field.RawValuePtr(), field.RawValueSize());
                break;
            case 1: // _raw_value was double quoted
            case 2: // _raw_value was hex encoded
                maybe_format_string_field(interp_name, interp_value);
                break;
            case 3: // _raw_value was hex encoded and decoded string needs escaping
                tty_escape_string(escaped_value, interp_value.data(), interp_value.size());
                maybe_format_string_field(interp_name, escaped_value);
                break;
        }
        ret = true;
    } else {
        if (field.InterpValueSize() > 0) {
            if (field.FieldType() == field_type_t::SESSION) {
                // Since the interpreted value for SES is also (normally) an int
                // Replace "unset" and "4294967295" with "-1"
                if ((field.InterpValueSize() == 5 && std::strncmp("unset", field.InterpValuePtr(), field.InterpValueSize()) == 0) ||
                (field.InterpValueSize() == 10 && strncmp("4294967295", field.InterpValuePtr(), field.InterpValueSize()) == 0)) {
                    maybe_format_string_field(interp_name, S_NEG_ONE);
                } else {
                    maybe_format_raw_field(interp_name, field.InterpValuePtr(), field.InterpValueSize());
                }
            } else {
                maybe_format_raw_field(interp_name, field.InterpValuePtr(), field.InterpValueSize());
            }
            // write additional raw field
            maybe_format_raw_field(raw_name, field.RawValuePtr(), field.RawValueSize());
            ret = true;
        } else {
            if (field.FieldType() == field_type_t::UNESCAPED) {
                // fields we have created that potentially need escaping
                tty_escape_string(escaped_value, field.RawValuePtr(), field.RawValueSize());
                maybe_format_string_field(interp_name, escaped_value);
            }
            else {
                // Use interp name for raw value because there is no interp value
                maybe_format_raw_field(interp_name, field.RawValuePtr(), field.RawValueSize());
            }
            ret = true;
        }
    }
    return ret;
}

void AbstractEventWriter::format_other_field(const std::string& name, const char* value_data, size_t value_size)
{
    if (!_other_fields_initialized) {
        _other_fields_buffer.Clear();
        _other_fields_writer.Reset(_other_fields_buffer);
        _other_fields_writer.StartObject();
        _other_fields_initialized = true;
    }

    _other_fields_writer.Key(name.data(), name.length(), true);
    _other_fields_writer.String(value_data, value_size, true);
}
