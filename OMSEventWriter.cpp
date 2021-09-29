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

void OMSEventWriter::format_int32_field(const std::string& name, int32_t value)
{
    _writer.Key(name.data(), name.length(), true);
    _writer.Int(value);
}

void OMSEventWriter::format_int64_field(const std::string& name, int64_t value)
{
    _writer.Key(name.data(), name.length(), true);
    _writer.Int64(value);
}

void OMSEventWriter::format_raw_field(const std::string& name, const char* value_data, size_t value_size)
{
    _writer.Key(name.data(), name.length(), true);
    _writer.String(value_data, value_size, true);
}

bool OMSEventWriter::begin_event(const Event& event)
{
    std::ostringstream timestamp_str;

    double time = static_cast<double>(event.Seconds());
    time += static_cast<double>(event.Milliseconds())/1000;

    _buffer.Clear();
    _writer.Reset(_buffer);

    _writer.StartArray();
    _writer.Double(time);
    _writer.StartObject();

    timestamp_str << event.Seconds() << "."
                 << std::setw(3) << std::setfill('0')
                 << event.Milliseconds();

    AbstractEventWriter::format_string_field(_config.TimestampFieldName, timestamp_str.str());
    format_int64_field(_config.SerialFieldName, event.Serial());
    _writer.String(_config.RecordsFieldName.data(), _config.RecordsFieldName.length(), true);

    _writer.StartArray();
    return true;
}

void OMSEventWriter::end_event(const Event& event)
{
    _writer.EndArray();
    _writer.EndObject();
    _writer.EndArray();
}

// ACK format: Sec:Msec:Serial\n all in fixed size HEX
ssize_t OMSEventWriter::ReadAck(EventId& event_id, IReader* reader) {
    std::array<char, ((8+8+4)*2)+3> data;
    auto ret = reader->ReadAll(data.data(), data.size());
    if (ret != IO::OK) {
        return ret;
    }

    if (data[8*2] != ':' || data[(12*2)+1] != ':' || data[data.size()-1] != '\n') {
        return IO::FAILED;
    }

    data[8*2] = 0;
    data[(12*2)+1] = 0;
    data[data.size()-1] = 0;

    uint64_t sec;
    uint32_t msec;
    uint64_t serial;

    sec = strtoull(data.data(), nullptr, 16);
    msec = static_cast<uint32_t>(strtoul(&data[(8*2)+1], nullptr, 16));
    serial = strtoull(&data[(12*2)+2], nullptr, 16);

    if (sec == 0 || sec == ULLONG_MAX || msec == ULONG_MAX || serial == ULLONG_MAX) {
        return IO::FAILED;
    }

    event_id = EventId(sec, msec, serial);

    return IO::OK;
}

ssize_t OMSEventWriter::write_event(IWriter* writer)
{
    return writer->WriteAll(_buffer.GetString(), _buffer.GetSize());
}

bool OMSEventWriter::begin_record(const EventRecord& record, const std::string& record_type_name)
{
    _writer.StartObject();
    format_int32_field(_config.RecordTypeFieldName, static_cast<int32_t>(record.RecordType()));
    format_string_field(_config.RecordTypeNameFieldName, record_type_name);

    return true;
}

void OMSEventWriter::end_record(const EventRecord& record)
{
    _writer.EndObject();
}
