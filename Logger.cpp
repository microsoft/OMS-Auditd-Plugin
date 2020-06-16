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

std::string Logger::_ident;
bool Logger::_enable_syslog = false;
std::function<void(const char* ptr, size_t size)> Logger::_log_fn;

void Logger::OpenSyslog(const std::string& ident, int facility)
{
    _ident = ident;
    openlog(_ident.c_str(), LOG_PERROR, LOG_DAEMON);
    _enable_syslog = true;
}

void Logger::Info(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_INFO, fmt, args);
}

void Logger::Warn(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_WARNING, fmt, args);
}

void Logger::Error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_ERR, fmt, args);
}

void Logger::Debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_write(LOG_DEBUG, fmt, args);
}

void Logger::_log_write(int level, const char* fmt, va_list ap)
{
    if (_enable_syslog) {
        vsyslog(level, fmt, ap);
    } else {
        char buffer[64*1024];
        auto nr = vsnprintf(buffer, sizeof(buffer), fmt, ap);
        if (nr > 0) {
            if (buffer[nr - 1] != '\n') {
                buffer[nr] = '\n';
                nr++;
            }
            buffer[nr] = 0;
            (void)write(2, buffer, nr);
            if (_log_fn) {
                _log_fn(buffer, nr);
            }
        }
    }
}

