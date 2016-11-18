/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_EVENTQUEUE_H
#define AUOMS_EVENTQUEUE_H

#include "Queue.h"

class EventQueue: public IEventBuilderAllocator {
public:
    EventQueue(std::shared_ptr<Queue> queue): _queue(queue), _data(nullptr), _size(0) {}

    virtual int Allocate(void** data, size_t size) {
        int ret = _queue->Allocate(data, size, true, 0);
        if (ret != 1) {
            return ret;
        }
        _data = *data;
        _size = size;
        return 1;
    }

    virtual int Commit() {
        Event event(_data, _size);
        return _queue->Commit(queue_msg_type_t::EVENT);
    }

    virtual int Rollback() {
        return _queue->Rollback();
    }

private:
    std::shared_ptr<Queue> _queue;
    void* _data;
    size_t _size;
};


#endif //AUOMS_EVENTQUEUE_H
