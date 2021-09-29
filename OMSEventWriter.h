/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_OMSEVENTTRANSFORMER_H
#define AUOMS_OMSEVENTTRANSFORMER_H

#include "AbstractEventWriter.h"

#include <string>
#include <memory>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>


class OMSEventWriter: public AbstractEventWriter {
public:
    explicit OMSEventWriter(EventWriterConfig config): AbstractEventWriter(std::move(config)),
    _buffer(0, 1024*1024), _writer(_buffer)
    {}

    bool SupportsAckMode() override { return true; }
    ssize_t ReadAck(EventId& event_id, IReader* reader) override;

protected:

    ssize_t write_event(IWriter* writer) override;

    bool begin_event(const Event& event) override;
    void end_event(const Event& event) override;

    bool begin_record(const EventRecord& record, const std::string& record_type_name) override;
    void end_record(const EventRecord& record) override;

    void format_int32_field(const std::string& name, int32_t value) override;
    void format_int64_field(const std::string& name, int64_t value) override;
    void format_raw_field(const std::string& name, const char* value_data, size_t value_size) override;

private:
    rapidjson::StringBuffer _buffer;
    rapidjson::Writer<rapidjson::StringBuffer> _writer;
};


#endif //AUOMS_OMSEVENTTRANSFORMER_H
