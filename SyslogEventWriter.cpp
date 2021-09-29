/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "SyslogEventWriter.h"

#include "Logger.h"
#include "StringUtils.h"

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

void SyslogEventWriter::format_int32_field(const std::string& name, int32_t value)
{
    char buf[32];
    int len = snprintf(buf, sizeof(buf) - 1, "%d", value);
    format_raw_field(name, buf, len);
}

void SyslogEventWriter::format_int64_field(const std::string& name, int64_t value)
{
    char buf[32];
    int len = snprintf(buf, sizeof(buf) - 1, "%ld", value);
    format_raw_field(name, buf, len);
}

void SyslogEventWriter::format_string_field(const std::string& name, const std::string& value)
{
    _buffer << ' ' << name << '=' << '"' << value << '"';
}

void SyslogEventWriter::format_raw_field(const std::string& name, const char* value_data, size_t value_size)
{
    _buffer << ' ' << name << '=';
    _buffer.write(value_data, value_size);
}

bool SyslogEventWriter::begin_event(const Event& event) {
    _event = &event;
    return true;
}

bool SyslogEventWriter::begin_record(const EventRecord& record, const std::string& record_type_name) {
    _buffer.str(std::string());
    _buffer << "type=" << record_type_name;
    _buffer << " audit(" << _event->Seconds() << '.' << std::setw(3) << std::setfill('0') <<_event->Milliseconds() << std::setw(0) << ':' << _event->Serial() << "):";
    return true;
}

void SyslogEventWriter::end_record(const EventRecord& record) {
    syslog(LOG_USER | LOG_INFO, "%s", _buffer.str().c_str());
}
