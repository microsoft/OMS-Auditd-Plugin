/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_RAWEVENTWRITER_H
#define AUOMS_RAWEVENTWRITER_H

#include "IEventWriter.h"

class RawEventWriter: public IEventWriter {
public:
    bool SupportsAckMode() override { return true; }

    ssize_t WriteEvent(const Event& event, IWriter* writer) override {
        return writer->WriteAll(event.Data(), event.Size());
    }

    ssize_t ReadAck(EventId& event_id, IReader* reader) override {
        std::array<uint8_t, 8+4+8> data;
        auto ret = reader->ReadAll(data.data(), data.size());
        if (ret != IO::OK) {
            return ret;
        }
        event_id = EventId(*reinterpret_cast<uint64_t*>(data.data()),
                           *reinterpret_cast<uint32_t*>(data.data()+8),
                           *reinterpret_cast<uint64_t*>(data.data()+12));
        return IO::OK;
    }
};


#endif //AUOMS_RAWEVENTWRITER_H
