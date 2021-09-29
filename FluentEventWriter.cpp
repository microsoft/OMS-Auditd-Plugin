/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "FluentEventWriter.h"

void FluentEventWriter::format_int32_field(const std::string& name, int32_t value)
{
    _currentMessage->add_field(name, std::move(std::to_string(value)));
}

void FluentEventWriter::format_int64_field(const std::string& name, int64_t value)
{
    _currentMessage->add_field(name, std::move(std::to_string(value)));
}

void FluentEventWriter::format_raw_field(const std::string& name, const char* value_data, size_t value_size)
{
    _currentMessage->add_field(name, std::move(std::string(value_data, value_size)));
}


bool FluentEventWriter::begin_event(const Event& event)
{
    _fluentEvent = std::make_unique<FluentEvent>(_tag);
    _eventCommonFields.clear();

    std::stringstream str;
    time_t seconds = event.Seconds();
    time_t milliseconds = event.Milliseconds();
    str << std::put_time(gmtime(&seconds), "%FT%T") << "." << std::setw(3) << std::setfill('0') << milliseconds << "Z";
    _eventCommonFields[_config.TimestampFieldName] = str.str();

    std::ostringstream timestamp_str;
    timestamp_str << event.Seconds() << "."
                << std::setw(3) << std::setfill('0')
                << event.Milliseconds();

    _eventCommonFields[_config.AuditIDFieldName] = timestamp_str.str() + ":" + std::to_string(event.Serial());
    _eventCommonFields[_config.ComputerFieldName] = _config.HostnameValue;
    _eventCommonFields[_config.SerialFieldName] = std::to_string(event.Serial());

    return true;
}

ssize_t FluentEventWriter::write_event(IWriter* writer)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, *_fluentEvent);

    return writer->WriteAll(sbuf.data(), sbuf.size());
}

bool FluentEventWriter::begin_record(const EventRecord& record, const std::string& record_type_name)
{
    _currentMessage = std::make_unique<FluentMessage>();
    format_int32_field(_config.RecordTypeFieldName, static_cast<int32_t>(record.RecordType()));
    format_string_field(_config.RecordTypeNameFieldName, record_type_name);

    if (_config.IncludeRecordTextField) {
        format_raw_field(_config.RecordTextFieldName, record.RecordTextPtr(), record.RecordTextSize());
    }

    for (auto itr = _eventCommonFields.begin(); itr != _eventCommonFields.end(); ++itr) {
        format_string_field(itr->first, itr->second);
    }

    return true;
}

void FluentEventWriter::end_record(const EventRecord& record)
{
    _fluentEvent->Add(std::move(*_currentMessage));
    _currentMessage.reset();
}
