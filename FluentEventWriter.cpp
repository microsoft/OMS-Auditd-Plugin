/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "FluentEventWriter.h"

ssize_t FluentEventWriter::WriteEvent(const Event &event, IWriter *writer)
{
    FluentEvent fluentEvent(_tag);

    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    for (auto rec: event) {
        std::unordered_map<std::string, std::string> body;

        std::stringstream str;
        time_t seconds = event.Seconds();
        time_t milliseconds = event.Milliseconds();
        str << std::put_time(gmtime(&seconds), "%FT%T") << "." << std::setw(3) << std::setfill('0') << milliseconds << "Z";
        body["Timestamp"] = str.str();

        std::ostringstream timestamp_str;
        timestamp_str << event.Seconds() << "."
                    << std::setw(3) << std::setfill('0')
                    << event.Milliseconds();

	    body["AuditID"] = timestamp_str.str() + ":" + std::to_string(event.Serial());
        body["Computer"] = hostname;
	    body["SerialNumber"] = std::to_string(event.Serial());
	    body["ProcessFlags"] = event.Flags()>>16;

        if ((event.Flags() & EVENT_FLAG_IS_AUOMS_EVENT) != 0) {
            body["MessageType"] = "AUOMS_EVENT";
        } else {
            body["MessageType"] = "AUDIT_EVENT";
        }

        body["RecordTypeCode"] = std::to_string(rec.RecordType());
        body["RecordType"] = std::string(rec.RecordTypeNamePtr(), rec.RecordTypeNameSize());
    	body["RecordText"] = std::string(rec.RecordTextPtr(), rec.RecordTextSize());

        for (auto f: rec) {
            body[std::string(f.FieldNamePtr(), f.FieldNameSize())] = std::string(f.RawValuePtr(), f.RawValueSize());
        }

        FluentMessage fluentMsg(body);
        fluentEvent.Add(fluentMsg);
    }

    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, fluentEvent);

    return writer->WriteAll(sbuf.data(), sbuf.size());
}

ssize_t FluentEventWriter::ReadAck(EventId &event_id, IReader *reader)
{
    std::array<uint8_t, 8 + 4 + 8> data;
    auto ret = reader->ReadAll(data.data(), data.size());
    if (ret != IO::OK)
    {
        return ret;
    }
    event_id = EventId(*reinterpret_cast<uint64_t *>(data.data()),
                       *reinterpret_cast<uint32_t *>(data.data() + 8),
                       *reinterpret_cast<uint64_t *>(data.data() + 12));
    return IO::OK;
}
