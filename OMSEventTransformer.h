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

#include "OMSEventTransformerConfig.h"
#include "EventTransformerBase.h"
#include "MessageSinkBase.h"
#include "JSONMessageBuffer.h"
#include "Event.h"

#include <string>
#include <memory>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>


class OMSEventTransformer: public EventTransformerBase {
public:
    OMSEventTransformer(OMSEventTransformerConfig config, const std::string& tag, std::shared_ptr<MessageSinkBase>& sink):
    _config(config), _tag(tag), _sink(sink)
    {}

    virtual void ProcessEvent(const Event& event);
    virtual void ProcessEventsGap(const EventGapReport& gap);

private:
    void process_record(const EventRecord& rec, int record_idx, int record_type, const std::string& record_name);
    void process_field(const EventRecordField& field);

    OMSEventTransformerConfig _config;
    std::string _tag;
    std::shared_ptr<MessageSinkBase> _sink;
    std::string _field_name;
    std::string _raw_name;
    std::string _interp_name;
    std::string _raw_value;
    std::string _value1;
    std::string _value2;

    JSONMessageBuffer _json_buffer;
};


#endif //AUOMS_OMSEVENTTRANSFORMER_H
