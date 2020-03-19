/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_FLUENTEVENTWRITER_H
#define AUOMS_FLUENTEVENTWRITER_H

#include "TextEventWriter.h"
#include "Logger.h"
#include <chrono>
#include <msgpack.hpp>

// represent one message. [[TS], {field1:"value", ...}]
class FluentMessage
{
private:
    int64_t timestamp;
    std::unordered_map<std::string, std::string> message_dict;

public:
    explicit FluentMessage()
    {
        timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    explicit FluentMessage(std::unordered_map<std::string, std::string> &_msg_dict) : message_dict(_msg_dict)
    {
        timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    MSGPACK_DEFINE(timestamp, message_dict)
};

// represents a pack of messages
class FluentEvent
{
private:
    std::string tag;
    std::unique_ptr<std::vector<FluentMessage>> messages;

public:
    explicit FluentEvent(const std::string &_tag) : tag(_tag)
    {
        messages = std::make_unique<std::vector<FluentMessage>>();
    }

    void Add(FluentMessage m)
    {
        messages->push_back(m);
    }

    MSGPACK_DEFINE(tag, messages)
};

class FluentEventWriter : public TextEventWriter
{
public:
    FluentEventWriter(TextEventWriterConfig config, const std::string &tag) : TextEventWriter(config), _tag(tag) {}
    virtual ssize_t WriteEvent(const Event &event, IWriter *writer);
    virtual ssize_t ReadAck(EventId &event_id, IReader *reader);

protected:
    void write_int32_field(const std::string &name, int32_t value);
    void write_int64_field(const std::string &name, int64_t value);
    void write_raw_field(const std::string &name, const char *value_data, size_t value_size);

    bool begin_event(const Event &event);
    void end_event(const Event &event) {}

    bool begin_record(const EventRecord &record, const std::string &record_type_name);
    void end_record(const EventRecord &record);

private:
    std::string _tag;
    FluentEvent* _fluentEvent;
    std::unordered_map<std::string, std::string> _eventCommonFields;
    std::unordered_map<std::string, std::string> _recordFields;
};

#endif //AUOMS_FLUENTEVENTWRITER_H
