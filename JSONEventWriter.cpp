/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "JSONEventWriter.h"

#include <cstdlib>
#include <climits>

ssize_t JSONEventWriter::WriteEvent(const Event& event, IWriter* writer) {
    _buffer.Clear();
    _writer.Reset(_buffer);

    // Start message
    _writer.StartObject(); // Event
    _writer.Key("sec");
    _writer.Int64(event.Seconds());
    _writer.Key("msec");
    _writer.Int64(event.Milliseconds());
    _writer.Key("serial");
    _writer.Int64(event.Serial());
    _writer.Key("pid");
    _writer.Int64(event.Pid());
    _writer.Key("records");
    _writer.StartArray(); // Records
    for (auto rec: event) {
        _writer.Key("type-code");
        _writer.Int64(rec.RecordType());
        _writer.Key("type-name");
        _writer.String(rec.RecordTypeName(), rec.RecordTypeNameSize(), true);
        _writer.Key("raw-text");
        _writer.String(rec.RecordText(), rec.RecordTextSize(), true);
        _writer.Key("field-names");
        _writer.StartArray(); // Field Names
        for (auto f: rec) {
            _writer.String(f.FieldName(), f.FieldNameSize(), true);
        }
        _writer.EndArray(); // Field Names
        _writer.Key("field-types");
        _writer.StartArray(); // Field Types
        for (auto f: rec) {
            _writer.Int64(f.FieldType());
        }
        _writer.EndArray(); // Field Types
        _writer.Key("raw-values");
        _writer.StartArray(); // Field Raw Values
        for (auto f: rec) {
            _writer.Key(f.RawValue(), f.RawValueSize(), true);
        }
        _writer.EndArray(); // Field Raw Values
        _writer.Key("interp-values");
        _writer.StartArray(); // Field Interp Values
        for (auto f: rec) {
            if (f.InterpValueSize() > 0) {
                _writer.Key("i");
                _writer.Key(f.InterpValue(), f.InterpValueSize(), true);
            } else {
                _writer.Null();
            }
        }
        _writer.EndArray(); // Field Interp Values
    }
    _writer.EndArray(); // Records
    _writer.EndObject(); // Event

    auto len = snprintf(_header.data(), _header.size(), "%ld\n", _buffer.GetSize());
    auto ret = writer->WriteAll(_header.data(), len);
    if (ret != IWriter::OK) {
        return ret;
    }
    return writer->WriteAll(_buffer.GetString(), _buffer.GetSize());
}

