/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_TESTEVENTQUEUE_H
#define AUOMS_TESTEVENTQUEUE_H

#include "Event.h"

#include <vector>


class TestEventQueue: public IEventBuilderAllocator {
public:
    virtual bool Allocate(void** data, size_t size) {
        _buffer.resize(size);
        *data = _buffer.data();
        return true;
    }

    virtual int Commit() {
        _events.emplace_back(std::make_shared<std::vector<uint8_t>>(_buffer.begin(), _buffer.end()));
        return 1;
    }

    virtual bool Rollback() {
        _buffer.resize(0);
        return true;
    }

    size_t GetEventCount() {
        return _events.size();
    }

    Event GetEvent(int idx) {
        auto event = _events[idx];
        return Event(event->data(), event->size());
    }

private:
    std::vector<uint8_t> _buffer;
    std::vector<std::shared_ptr<std::vector<uint8_t>>> _events;
};

#endif //AUOMS_TESTEVENTQUEUE_H
