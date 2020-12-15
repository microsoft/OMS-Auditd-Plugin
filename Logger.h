/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_LOGGER_H
#define AUOMS_LOGGER_H

#include <string>
#include <cstdarg>
#include <unordered_map>
#include <functional>
#include <memory>
#include <chrono>
#include <mutex>

class LogMetric {
public:
    LogMetric(std::chrono::system_clock::time_point time): _start_time(time), _end_time(time), _fmt(), _first_msg(), _count(0) {}
    std::chrono::system_clock::time_point _start_time;
    std::chrono::system_clock::time_point _end_time;

    std::string _fmt;
    std::string _first_msg;
    size_t _count;
};

class Logger {
public:
    static void OpenSyslog(const std::string& ident, int facility);
    static void SetLogFunction(std::function<void(const char* ptr, size_t size)> fn) { _log_fn = fn; }
    static void Info(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
    static void Warn(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
    static void Error(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
    static void Debug(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

    static size_t GetMetrics(std::vector<std::shared_ptr<LogMetric>>& metrics, bool flush_all);
private:
    static void _log_write(int level, const char* fmt, va_list ap);

    static std::mutex _mutex;
    static std::string _ident;
    static bool _enable_syslog;
    static std::function<void(const char* ptr, size_t size)> _log_fn;
    static std::unordered_map<std::string, std::shared_ptr<LogMetric>> _current_metrics;
    static std::vector<std::shared_ptr<LogMetric>> _past_metrics;
};


#endif //AUOMS_LOGGER_H
