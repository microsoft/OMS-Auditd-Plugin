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

#include "OMSEventWriterConfig.h"
#include "TextEventWriter.h"

#include <string>
#include <memory>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>


class OMSEventWriter: public TextEventWriter {
public:
    OMSEventWriter(OMSEventWriterConfig config):
    _config(config), _buffer(0, 1024*1024), _writer(_buffer)
    {}

    virtual ssize_t WriteEvent(const Event& event, IWriter* writer);

private:
    ssize_t write_event(IWriter* writer);
    void reset();
    void begin_array();
    void end_array();
    void begin_object();
    void end_object();
    void add_int32_field(const std::string& name, int32_t value);
    void add_int64_field(const std::string& name, int64_t value);
    void add_double(double value);
    void add_string(const std::string& value);
    void add_string_field(const std::string& name, const std::string& value);
    void add_string_field(const std::string& name, const char* value_data, size_t value_size);

    void process_record(const EventRecord& rec, int record_type, const std::string& record_name);
    void process_field(const EventRecordField& field);

    OMSEventWriterConfig _config;
    std::string _field_name;
    std::string _raw_name;
    std::string _interp_name;
    std::string _escaped_value;
    std::string _interp_value;

    rapidjson::StringBuffer _buffer;
    rapidjson::Writer<rapidjson::StringBuffer> _writer;
};


#endif //AUOMS_OMSEVENTTRANSFORMER_H
