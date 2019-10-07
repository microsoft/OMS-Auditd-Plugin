/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_TEXTEVENTWRITER_H
#define AUOMS_TEXTEVENTWRITER_H

#include "IEventWriter.h"
#include "TextEventWriterConfig.h"

#include <string>

class TextEventWriter: public IEventWriter {
public:
    TextEventWriter(TextEventWriterConfig config) : _config(config)
    {}
    ssize_t ReadAck(EventId& event_id, IReader* reader);
    ssize_t WriteEvent(const Event& event, IWriter* writer);

protected:

    TextEventWriterConfig _config;

    virtual void write_raw_field(const std::string& name, const char* value_data, size_t value_size) = 0;
    virtual void write_int32_field(const std::string& name, int32_t value);
    virtual void write_int64_field(const std::string& name, int64_t value);
    virtual void write_string_field(const std::string& name, const std::string& value);

    virtual bool begin_event(const Event& event) {return true;}
    virtual void end_event(const Event& event) {}

    virtual bool begin_record(const EventRecord &record, const std::string& record_name) {return true;}
    virtual void end_record(const EventRecord &record) {}

    virtual bool write_field(const EventRecordField& field);
    virtual bool write_record(const EventRecord& rec);
    virtual bool write_event(const Event& event);
};


#endif //AUOMS_TEXTEVENTWRITER_H
