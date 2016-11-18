/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "MsgPackMessageSink.h"

#include "Logger.h"

extern "C" {
#include <arpa/inet.h>
}


void MsgPackMessageSink::reset()
{
    _msg.clear();
    _buffer.clear();
    _num_fields = 0;
}

void MsgPackMessageSink::send_message()
{
    while(check_open()) {
        if (_output->Write(_msg.data(), _msg.size()) != OutputBase::OK) {
            Logger::Warn("Write failed, closing connection");
            _output->Close();
            continue;
        }

        if (_output->Write(_buffer.data(), _buffer.size()) != OutputBase::OK) {
            Logger::Warn("Write failed, closing connection");
            _output->Close();
        } else {
            return;
        }
    }
}

void MsgPackMessageSink::BeginMessage(const std::string& tag, uint64_t sec, uint32_t msec)
{

    reset();
    msgpack::packer<msgpack::sbuffer> msg_packer(&_msg);
    msg_packer.pack_array(3);
    msg_packer.pack(tag);
    if (_use_ext_time) {
        std::array<uint32_t, 2> _ext_time;
        _ext_time[0] = htonl(static_cast<uint32_t>(sec));
        _ext_time[1] = htonl(msec * 1000000);
        msg_packer.pack_ext(8, 0);
        msg_packer.pack_ext_body(reinterpret_cast<const char *>(&_ext_time[0]), 8);
    } else {
        msg_packer.pack(static_cast<uint32_t>(sec));
    }
}

void MsgPackMessageSink::EndMessage()
{
    msgpack::packer<msgpack::sbuffer> msg_packer(&_msg);
    msg_packer.pack_map(_num_fields);

    send_message();
}

void MsgPackMessageSink::CancelMessage()
{
    reset();
}

void MsgPackMessageSink::AddBoolField(const std::string& name, bool value)
{
    _packer.pack(name);
    _packer.pack(value);
    _num_fields += 1;
}

void MsgPackMessageSink::AddInt32Field(const std::string& name, int32_t value)
{
    _packer.pack(name);
    _packer.pack(value);
    _num_fields += 1;
}

void MsgPackMessageSink::AddInt64Field(const std::string& name, int64_t value)
{
    _packer.pack(name);
    _packer.pack(value);
    _num_fields += 1;
}

void MsgPackMessageSink::AddDoubleField(const std::string& name, double value)
{
    _packer.pack(name);
    _packer.pack(value);
    _num_fields += 1;
}

void MsgPackMessageSink::AddTimeField(const std::string& name, uint64_t sec, uint32_t msec)
{
    _packer.pack(name);
    std::string time = formatTime(sec, msec);
    _packer.pack(time);
    _num_fields += 1;
}

void MsgPackMessageSink::AddTimestampField(const std::string& name, uint64_t sec, uint32_t msec)
{

    _packer.pack(name);
    std::string time = formatTime(sec, msec);
    _packer.pack(time);
    _num_fields += 1;
}

void MsgPackMessageSink::AddStringField(const std::string& name, const std::string& value)
{
    _packer.pack(name);
    _packer.pack(value);
    _num_fields += 1;
}
