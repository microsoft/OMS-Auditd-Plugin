/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "TextEventWriter.h"

#include <cstdlib>
#include <climits>

// ACK format: Sec:Msec:Serial\n all in fixed size HEX
ssize_t TextEventWriter::ReadAck(EventId& event_id, IReader* reader) {
    std::array<char, ((8+8+4)*2)+3> data;
    auto ret = reader->ReadAll(data.data(), data.size());
    if (ret != IO::OK) {
        return ret;
    }

    if (data[8*2] != ':' || data[(12*2)+1] != ':' || data[data.size()-1] != '\n') {
        return IO::FAILED;
    }

    data[8*2] = 0;
    data[(12*2)+1] = 0;
    data[data.size()-1] = 0;

    uint64_t sec;
    uint32_t msec;
    uint64_t serial;

    sec = strtoull(data.data(), nullptr, 16);
    msec = static_cast<uint32_t>(strtoul(&data[(8*2)+1], nullptr, 16));
    serial = strtoull(&data[(12*2)+2], nullptr, 16);

    if (sec == 0 || sec == ULLONG_MAX || msec == ULONG_MAX || serial == ULLONG_MAX) {
        return IO::FAILED;
    }

    event_id = EventId(sec, msec, serial);

    return IO::OK;
}
