/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "JSONMessageSinkBase.h"

void JSONMessageSinkBase::reset()
{
    _buffer.Clear();
    _writer.Reset(_buffer);
}

void JSONMessageSinkBase::AddBoolField(const std::string& name, bool value)
{
    _writer.Key(name.c_str(), name.size(), true);
    _writer.Bool(value);
}

void JSONMessageSinkBase::AddInt32Field(const std::string& name, int32_t value)
{
    _writer.Key(name.c_str(), name.size(), true);
    _writer.Int(value);
}

void JSONMessageSinkBase::AddInt64Field(const std::string& name, int64_t value)
{
    _writer.Key(name.c_str(), name.size(), true);
    _writer.Int64(value);
}

void JSONMessageSinkBase::AddDoubleField(const std::string& name, double value)
{
    _writer.Key(name.c_str(), name.size(), true);
    _writer.Double(value);
}

void JSONMessageSinkBase::AddTimeField(const std::string& name, uint64_t sec, uint32_t msec)
{
    _writer.Key(name.c_str(), name.size(), true);
    std::string time = formatTime(sec, msec);
    _writer.Key(time.c_str(), time.size(), true);
}

void JSONMessageSinkBase::AddTimestampField(const std::string& name, uint64_t sec, uint32_t msec)
{
    _writer.Key(name.c_str(), name.size(), true);
    std::string time = formatTime(sec, msec);
    _writer.Key(time.c_str(), time.size(), true);
}

void JSONMessageSinkBase::AddStringField(const std::string& name, const std::string& value)
{
    _writer.Key(name.c_str(), name.size(), true);
    _writer.Key(value.c_str(), value.size(), true);
}

void JSONMessageSinkBase::AddStringField(const std::string& name, const char* value_data, size_t value_size)
{
    _writer.Key(name.c_str(), name.size(), true);
    _writer.Key(value_data, value_size, true);
}
