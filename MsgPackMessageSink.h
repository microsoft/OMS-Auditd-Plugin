/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_MSG_PACK_MESSAGE_SINK_H
#define AUOMS_MSG_PACK_MESSAGE_SINK_H

#include "MessageSinkBase.h"
#include "OutputBase.h"
#include "Config.h"

#include <array>

#include <msgpack.hpp>

class MsgPackMessageSink: public MessageSinkBase {
public:
    static std::shared_ptr<MessageSinkBase> Create(std::unique_ptr<OutputBase>&& output, const Config& config) {
        bool use_ext_time = false;

        if (config.HasKey("msgpack_ext_time")) {
            use_ext_time = config.GetBool("msgpack_ext_time");
        }
        return std::shared_ptr<MessageSinkBase>(static_cast<MessageSinkBase *>(new MsgPackMessageSink(std::move(output), use_ext_time)));
    }

    MsgPackMessageSink(std::unique_ptr<OutputBase>&& output, bool use_ext_time): MessageSinkBase(std::move(output)), _use_ext_time(use_ext_time), _num_fields(0), _msg(BUFFER_SIZE), _buffer(BUFFER_SIZE), _packer(&_buffer) {}

    virtual void BeginMessage(const std::string& tag, uint64_t sec, uint32_t msec);
    virtual void EndMessage();
    virtual void CancelMessage();
    virtual void AddBoolField(const std::string& name, bool value);
    virtual void AddInt32Field(const std::string& name, int32_t value);
    virtual void AddInt64Field(const std::string& name, int64_t value);
    virtual void AddDoubleField(const std::string& name, double value);
    virtual void AddTimeField(const std::string& name, uint64_t sec, uint32_t msec);
    virtual void AddTimestampField(const std::string& name, uint64_t sec, uint32_t msec);
    virtual void AddStringField(const std::string& name, const std::string& value);
private:
    static constexpr size_t BUFFER_SIZE = 64*1024;

    void reset();
    void send_message();

    bool _use_ext_time;
    uint32_t _num_fields;
    msgpack::sbuffer _msg;
    msgpack::sbuffer _buffer;
    msgpack::packer<msgpack::sbuffer> _packer;
};


#endif //AUOMS_MSG_PACK_MESSAGE_SINK_H
