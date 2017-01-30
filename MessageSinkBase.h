/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_MESSAGE_SINK_BASE_H
#define AUOMS_MESSAGE_SINK_BASE_H

#include "OutputBase.h"
#include "Config.h"
#include <cctype>
#include <string>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <functional>

class MessageSinkVirtBase {
public:
    virtual void AddBoolField(const std::string& name, bool value) = 0;
    virtual void AddInt32Field(const std::string& name, int32_t value) = 0;
    virtual void AddInt64Field(const std::string& name, int64_t value) = 0;
    virtual void AddDoubleField(const std::string& name, double value) = 0;
    virtual void AddTimeField(const std::string& name, uint64_t sec, uint32_t msec) = 0;
    virtual void AddTimestampField(const std::string& name, uint64_t sec, uint32_t msec) = 0;
    virtual void AddStringField(const std::string& name, const std::string& value) = 0;
    virtual void AddStringField(const std::string& name, const char* value_data, size_t value_size) = 0;

protected:
    std::string formatTime(uint64_t sec, uint32_t msec);
};

class MessageSinkBase: virtual public MessageSinkVirtBase
{
public:
    static constexpr int START_SLEEP_PERIOD = 1;
    static constexpr int MAX_SLEEP_PERIOD = 60;

    typedef std::function<std::shared_ptr<MessageSinkBase>(std::unique_ptr<OutputBase>&& output, const Config& config)> factory_function_t;

    static void RegisterSinkFactory(const std::string& name, std::function<std::shared_ptr<MessageSinkBase>(std::unique_ptr<OutputBase>&& output, const Config& config)> fn);
    static std::shared_ptr<MessageSinkBase> CreateSink(const std::string& name, std::unique_ptr<OutputBase>&& output, const Config& config);

    MessageSinkBase(std::unique_ptr<OutputBase>&& output): _output(std::move(output)), _closed(false), _sleep_period(START_SLEEP_PERIOD) {}

    virtual void Close();
    virtual void BeginMessage(const std::string& tag, uint64_t sec, uint32_t msec) = 0;
    virtual void EndMessage() = 0;
    virtual void CancelMessage() = 0;

protected:
    static std::mutex _static_lock;
    static std::unordered_map<std::string, factory_function_t> _sink_factories;

    bool check_open(std::function<void()> on_open = [](){});
    void close_internal(std::function<void()> on_close = [](){});

    std::mutex _lock;
    std::condition_variable _cond;
    std::unique_ptr<OutputBase> _output;
    bool _closed;
    int _sleep_period;
};

#endif //AUOMS_MESSAGE_SINK_BASE_H
