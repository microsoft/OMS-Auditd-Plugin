/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_ABSTRACTEVENTWRITER_H
#define AUOMS_ABSTRACTEVENTWRITER_H

#include "IEventWriter.h"
#include "EventWriterConfig.h"

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

class AbstractEventWriter: public IEventWriter {
public:
    explicit AbstractEventWriter(EventWriterConfig config) : _config(std::move(config)), _other_fields_initialized(false), _other_fields_buffer(0, 256*1024), _other_fields_writer(_other_fields_buffer)
    {}
    bool SupportsAckMode() override { return false; }
    ssize_t ReadAck(EventId& event_id, IReader* reader) override { return IO::FAILED; }
    ssize_t WriteEvent(const Event& event, IWriter* writer) override;

protected:

    EventWriterConfig _config;

    virtual ssize_t write_event(IWriter* writer) = 0;

    virtual bool format_event(const Event& event);
    virtual bool format_record(const EventRecord& rec);
    virtual bool format_field(const EventRecordField& field);

    virtual bool begin_event(const Event& event) { return true; }
    virtual void end_event(const Event& event) {}

    virtual bool begin_record(const EventRecord &record, const std::string& record_name) { return true; }
    virtual void end_record(const EventRecord &record) {}

    virtual void format_int32_field(const std::string& name, int32_t value) = 0;
    virtual void format_int64_field(const std::string& name, int64_t value) = 0;
    virtual void format_string_field(const std::string& name, const std::string& value) {
        format_raw_field(name, value.data(), value.length());
    }
    virtual void format_raw_field(const std::string& name, const char* value_data, size_t value_size) = 0;

    virtual void format_other_field(const std::string& name, const char* value_data, size_t value_size);

private:

    inline void maybe_format_string_field(const std::string& name, const std::string& value) {
        if (!_config.IsFieldAlwaysFiltered(name)) {
            if (!_config.IsFieldFiltered(name)) {
                format_string_field(name, value);
            } else if (_config.OtherFieldsMode) {
                format_other_field(name, value.data(), value.size());
            }
        }
    }

    inline void maybe_format_raw_field(const std::string& name, const char* value_data, size_t value_size) {
        if (!_config.IsFieldAlwaysFiltered(name)) {
            if (!_config.IsFieldFiltered(name)) {
                format_raw_field(name, value_data, value_size);
            } else if (_config.OtherFieldsMode) {
                format_other_field(name, value_data, value_size);
            }
        }
    }

    bool _other_fields_initialized;
    rapidjson::StringBuffer _other_fields_buffer;
    rapidjson::Writer<rapidjson::StringBuffer> _other_fields_writer;
};


#endif //AUOMS_ABSTRACTEVENTWRITER_H
