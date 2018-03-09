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

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

void OMSEventWriter::decode_hex(std::string& out, const std::string& hex)
{
    static const char int2hex[16] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    static const int hex2int[256] {
            // 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 1F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 2F
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 3F
            -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 4F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 5F
            -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 6F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 7F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 8F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 9F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // AF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // BF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // CF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // DF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // EF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // FF
    };

    if (hex.length() % 2 != 0) {
        // Not hex like we expected, just output the raw value
        out = hex;
        return;
    }
    if (out.capacity() < hex.length()*2) {
        out.reserve(hex.length()*2);
    }
    out.resize(0);

    auto p = hex.begin();
    auto endp = hex.end();
    while (p != endp) {
        int i1 = hex2int[static_cast<uint8_t>(*p)];
        ++p;
        int i2 = hex2int[static_cast<uint8_t>(*p)];
        ++p;
        if (i1 < 0 || i2 < 0) {
            // Not hex like we expected, just output the raw value
            out = hex;
            return;
        }
        char c = static_cast<char>(i1 << 4 | i2);
        if (c != 0 && static_cast<unsigned char>(c) < 0x80) {
            out += c;
        } else {
            out += '\\';
            out += 'x';
            out += int2hex[i1];
            out += int2hex[i2];
        }
    }
    return;
}

bool OMSEventWriter::unescape(std::string& out, const std::string& in)
{
    if (in.front() == '"' && in.back() == '"') {
        out = in.substr(1, in.size() - 2);
        return false;
    } else if (in == "(null)") {
        out = in;
        return false;
    } else if (in.size() % 2 == 0) {
        decode_hex(out, in);
        return true;
    } else {
        out = in;
        return false;
    }
}

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
    if (!_config.FilterFieldNameSet.count(name)) {
        _writer.Key(name.c_str(), name.size(), true);
        _writer.Int(value);
    }
}

void OMSEventWriter::add_int64_field(const std::string& name, int64_t value)
{
    if (!_config.FilterFieldNameSet.count(name)) {
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
    if (!_config.FilterFieldNameSet.count(name)) {
        _writer.Key(name.c_str(), name.size(), true);
        _writer.String(value.c_str(), value.size(), true);
    }
}

void OMSEventWriter::add_string_field(const std::string& name, const char* value_data, size_t value_size)
{
    if (!_config.FilterFieldNameSet.count(name)) {
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
    add_string(_config.RecordsFieldName);
    add_int64_field(_config.ProcessFlagsFieldName, event.Flags()>>16);

    int records = 0;

    try {
        begin_array(); // Records
        for (auto rec : event) {
            int record_type = rec.RecordType();
            std::string record_type_name = std::string(rec.RecordTypeName(), rec.RecordTypeNameSize());
            // Exclude the EOE (end-of-event) record
            if (!_config.RecordTypeNameOverrideMap.empty()) {
                auto it = _config.RecordTypeNameOverrideMap.find(record_type);
                if (it != _config.RecordTypeNameOverrideMap.end()) {
                    record_type_name = it->second;
                }
            }

            if (!_config.FilterRecordTypeSet.count(record_type_name)) {
                process_record(rec, record_type, record_type_name);
                records++;
            }
        }
        end_array(); // Records
    } catch (const std::exception& ex) {
        Logger::Warn("Unexpected exception while processing event: %s", ex.what());
        return false;
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

    if (_config.IncludeFullRawText) {
        add_string_field(_config.RawTextFieldName, std::string(rec.RecordText(), rec.RecordTextSize()));
    }

    end_object();
}

void OMSEventWriter::process_field(const EventRecordField& field)
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

    if (_raw_name == _interp_name) {
        _raw_name.append(_config.FieldSuffix);
    }

    if (field.FieldType() == FIELD_TYPE_ESCAPED || field.FieldType() == FIELD_TYPE_PROCTITLE) {
        // If the field type is FIELD_TYPE_ESCAPED, then there is no interp value in the event.
        _raw_value.assign(field.RawValue(), field.RawValueSize());
        if (unescape(_interp_value, _raw_value)) {
            // Only include raw value if it was HEX encoded
            add_string_field(_raw_name, field.RawValue(), field.RawValueSize());
        }
        add_string_field(_interp_name, _interp_value);
    } else {
        if (field.InterpValueSize() > 0) {
            switch (field.FieldType()) {
                case FIELD_TYPE_SESSION:
                    // Since the interpreted value for SES is also (normally) an int
                    // Replace "unset" and "4294967295" with "-1"
                    if ((field.InterpValueSize() == 5 && std::strncmp("unset", field.InterpValue(), field.InterpValueSize()) == 0) ||
                            (field.InterpValueSize() == 10 && strncmp("4294967295", field.InterpValue(), field.InterpValueSize()) == 0)) {
                        add_string_field(_interp_name, "-1");
                    } else {
                        add_string_field(_interp_name, field.InterpValue(), field.InterpValueSize());
                    }
                    break;
                default:
                    add_string_field(_interp_name, field.InterpValue(), field.InterpValueSize());
            }
            add_string_field(_raw_name, field.RawValue(), field.RawValueSize());
        } else {
            // Use interp name for raw value because there is no interp value
            add_string_field(_interp_name, field.RawValue(), field.RawValueSize());
        }
    }
}
