/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "MessageSinkBase.h"

#include "Logger.h"

#include <ctime>
#include <array>
#include <sstream>
#include <iomanip>

std::mutex MessageSinkBase::_static_lock;
std::unordered_map<std::string, MessageSinkBase::factory_function_t> MessageSinkBase::_sink_factories;

void MessageSinkBase::RegisterSinkFactory(const std::string& name, std::function<std::shared_ptr<MessageSinkBase>(std::unique_ptr<OutputBase>&& output, const Config& config)> fn)
{
    std::lock_guard<std::mutex> lock(_static_lock);
    _sink_factories[name] = fn;
}

std::shared_ptr<MessageSinkBase> MessageSinkBase::CreateSink(const std::string& name, std::unique_ptr<OutputBase>&& output, const Config& config)
{
    std::lock_guard<std::mutex> lock(_static_lock);

    auto it = _sink_factories.find(name);
    if (it != _sink_factories.end()) {
        return it->second(std::move(output), config);
    }
    return std::shared_ptr<MessageSinkBase>();
}

void MessageSinkBase::close_internal(std::function<void()> on_close)
{
    {
        std::lock_guard<std::mutex> lock(_lock);
        on_close();
        _closed = true;
    }
    _output->Close();
    _cond.notify_all();
}

void MessageSinkBase::Close()
{
    close_internal();
}

bool MessageSinkBase::check_open(std::function<void()> on_open)
{
    std::unique_lock<std::mutex> lock(_lock);
    while(!_closed) {
        lock.unlock();
        if (_output->IsOpen()) {
            return true;
        }
        if (_output->Open()) {
            lock.lock();
            if (_closed) {
                _output->Close();
                return false;
            }
            on_open();
            _sleep_period = START_SLEEP_PERIOD;
            return true;
        }

        Logger::Info("Sleeping %d seconds before re-trying connection", _sleep_period);

        lock.lock();
        _cond.wait_for(lock, std::chrono::seconds(_sleep_period), [this]() { return this->_closed; });
        _sleep_period = _sleep_period * 2;
        if (_sleep_period > MAX_SLEEP_PERIOD) {
            _sleep_period = MAX_SLEEP_PERIOD;
        }
    }
    return false;
}


std::string MessageSinkVirtBase::formatTime(uint64_t sec, uint32_t msec)
{
    std::time_t t = sec;
    struct tm tm;
    std::array<char, 128> buf;
    gmtime_r(&t, &tm);
    size_t tlen = std::strftime(&buf[0], buf.size(), "%Y-%m-%dT%H:%M:%S", &tm);
    std::ostringstream out;
    //out << std::string(&buf[0], tlen);
    out << sec;
    if (msec > 0)
    {
        out << "." << std::setw(3) << std::setfill('0') << msec;
    }
    //out << "Z";
    return out.str();
}
