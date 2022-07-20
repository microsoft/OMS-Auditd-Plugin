/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "Logger.h"

#include <cstdio>

extern "C" {
#include <unistd.h>
#include <syslog.h>
}

#define MAX_PAST_METRICS 10000

std::mutex Logger::_mutex;
std::string Logger::_ident;
bool Logger::_enable_syslog = false;
std::function<void(const char* ptr, size_t size)> Logger::_log_fn;
std::unordered_map<std::string, std::shared_ptr<LogMetric>> Logger::_current_metrics;
std::vector<std::shared_ptr<LogMetric>> Logger::_past_metrics;

void Logger::OpenSyslog(const std::string& ident, int facility)
{
    std::lock_guard<std::mutex> lock(_mutex);
    _ident = ident;
    openlog(_ident.c_str(), LOG_PERROR, LOG_DAEMON);
    _enable_syslog = true;
}

void Logger::Info(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_INFO, fmt, args);
    va_end(args);
}

void Logger::Warn(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_WARNING, fmt, args);
    va_end(args);
}

void Logger::Error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_ERR, fmt, args);
    va_end(args);
}

void Logger::Debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_DEBUG, fmt, args);
    va_end(args);
}

void Logger::_log_write(int level, const char* fmt, va_list ap)
{
    std::lock_guard<std::mutex> lock(_mutex);
    char buffer[64*1024];
    auto nr = vsnprintf(buffer, sizeof(buffer), fmt, ap);
    if (nr > 0) {
        if (nr > sizeof(buffer)-1) {
            nr = sizeof(buffer)-1;
        }
        if (nr > 1 && buffer[nr - 1] != '\n') {
            if (nr < sizeof(buffer)-1) {
                buffer[nr] = '\n';
                nr++;
            } else {
                buffer[nr - 1] = '\n';
            }
        }
        buffer[nr] = 0;
        if (_enable_syslog) {
            syslog(level, "%s", buffer);
        } else {
            auto ignored = write(2, buffer, nr);
        }
        if (_log_fn) {
            _log_fn(buffer, nr);
        }
        auto now = std::chrono::system_clock::now();
        std::string fmt_str = fmt;
        auto itr = _current_metrics.find(fmt_str);
        if (itr == _current_metrics.end()) {
            auto ret = _current_metrics.emplace(fmt_str, std::make_shared<LogMetric>(now));
            itr = ret.first;
        } else if (std::chrono::duration_cast<std::chrono::milliseconds>(now - itr->second->_start_time).count() > 60000 ) {
            if (_past_metrics.size() < MAX_PAST_METRICS) {
                _past_metrics.emplace_back(itr->second);
            }
            _current_metrics.erase(itr);
            auto ret = _current_metrics.emplace(fmt_str, std::make_shared<LogMetric>(now));
            itr = ret.first;
        }
        itr->second->_count += 1;
        itr->second->_end_time = now;
        if (itr->second->_count == 1) {
            itr->second->_fmt = fmt_str;
            itr->second->_first_msg.assign(buffer, nr);
        }
    }
}

size_t Logger::GetMetrics(std::vector<std::shared_ptr<LogMetric>>& metrics, bool flush_all) {
    std::lock_guard<std::mutex> lock(_mutex);

    auto now = std::chrono::system_clock::now();
    for (auto itr = _current_metrics.begin(); itr != _current_metrics.end(); ) {
        if (flush_all || std::chrono::duration_cast<std::chrono::milliseconds>(now - itr->second->_start_time).count() > 60000 ) {
            _past_metrics.emplace_back(itr->second);
            itr = _current_metrics.erase(itr);
        } else {
            itr++;
        }
    }

    metrics = _past_metrics;
    _past_metrics.clear();

    return metrics.size();
}
