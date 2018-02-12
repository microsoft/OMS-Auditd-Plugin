/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "MsgPackEventWriter.h"

ssize_t MsgPackEventWriter::WriteEvent(const Event& event, IWriter* writer) {
    _buffer.clear();

    // Added event
    _packer.pack_map(6);
    _packer.pack("sec");
    _packer.pack(event.Seconds());
    _packer.pack("msec");
    _packer.pack(event.Milliseconds());
    _packer.pack("serial");
    _packer.pack(event.Serial());
    _packer.pack("flags");
    _packer.pack(event.Flags());
    _packer.pack("pid");
    _packer.pack(event.Pid());
    _packer.pack("records");
    _packer.pack_array(event.NumRecords());
    for (auto rec: event) {
        _packer.pack_map(7);
        _packer.pack("type-code");
        _packer.pack(rec.RecordType());
        _packer.pack("type-name");
        _packer.pack_str(rec.RecordTypeNameSize());
        _packer.pack_str_body(rec.RecordTypeName(), rec.RecordTypeNameSize());
        _packer.pack("raw-text");
        _packer.pack_str(rec.RecordTextSize());
        _packer.pack_str_body(rec.RecordText(), rec.RecordTextSize());
        _packer.pack("field-names");
        _packer.pack_array(rec.NumFields());
        for (auto f: rec) {
            _packer.pack_str(f.FieldNameSize());
            _packer.pack_str_body(f.FieldName(), f.FieldNameSize());
        }
        _packer.pack("field-types");
        _packer.pack_array(rec.NumFields());
        for (auto f: rec) {
            _packer.pack(static_cast<uint16_t>(f.FieldType()));
        }
        _packer.pack("raw-values");
        _packer.pack_array(rec.NumFields());
        for (auto f: rec) {
            _packer.pack_str(f.RawValueSize());
            _packer.pack_str_body(f.RawValue(), f.RawValueSize());
        }
        _packer.pack("interp-values");
        _packer.pack_array(rec.NumFields());
        for (auto f: rec) {
            if (f.InterpValueSize() > 0) {
                _packer.pack_str(f.InterpValueSize());
                _packer.pack_str_body(f.InterpValue(), f.InterpValueSize());
            } else {
                _packer.pack_nil();
            }
        }
    }

    return writer->WriteAll(_buffer.data(), _buffer.size());
}

ssize_t MsgPackEventWriter::ReadAck(EventId& event_id, IReader* reader) {
    std::array<uint8_t, 8+4+8> data;
    auto ret = reader->ReadAll(data.data(), data.size());
    if (ret != IO::OK) {
        return ret;
    }
    event_id = EventId(*reinterpret_cast<uint64_t*>(data.data()),
                       *reinterpret_cast<uint32_t*>(data.data()+8),
                       *reinterpret_cast<uint64_t*>(data.data()+12));
    return IO::OK;
}
