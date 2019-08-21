/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_SYSLOGEVENTWRITER_H
#define AUOMS_SYSLOGEVENTWRITER_H

#include "TextEventWriter.h"

#include <string>
#include <sstream>
#include <memory>
#include <syslog.h>

class SyslogEventWriter: public TextEventWriter {
public:
    SyslogEventWriter(TextEventWriterConfig config) : TextEventWriter(config)
    {
	   openlog("sysmon", LOG_NOWAIT, LOG_USER);
    }

    ~SyslogEventWriter()
    {
	    closelog();
    }

private:
    void write_string_field(const std::string& name, const std::string& value);
    void write_raw_field(const std::string& name, const char* value_data, size_t value_size);

    bool begin_event(const Event& event);

    bool begin_record(const EventRecord& record, const std::string& record_type_name);
    void end_record(const EventRecord& record);

    const Event* _event;
    std::ostringstream _buffer;
};


#endif //AUOMS_SYSLOGEVENTWRITER_H
