/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_EVENTTRANSFORMER_H
#define AUOMS_EVENTTRANSFORMER_H

#include "EventTransformerConfig.h"
#include "EventTransformerBase.h"
#include "MessageSinkBase.h"
#include "Event.h"

#include <string>
#include <memory>

class EventTransformer: public EventTransformerBase {
public:
    EventTransformer(EventTransformerConfig config, const std::string& tag, std::shared_ptr<MessageSinkBase>& sink):
            _config(config), _tag(tag), _sink(sink)
    {}

    virtual void ProcessEvent(const Event& event);
    virtual void ProcessEventsGap(const EventGapReport& gap);

private:
    void begin_message(const Event& event);
    void end_message(const Event& event);
    void cancel_message();
    void process_record(const EventRecord& rec, int record_idx, int record_type, const std::string& record_name, int record_type_idx, int record_type_count);
    void process_field(const EventRecordField& field);

    EventTransformerConfig _config;
    std::string _tag;
    std::shared_ptr<MessageSinkBase> _sink;
    std::string _field_name;
    std::string _field_name_temp;
    std::string _raw_value;
    std::string _value1;
    std::string _value2;
};


#endif //AUOMS_EVENTTRANSFORMER_H
