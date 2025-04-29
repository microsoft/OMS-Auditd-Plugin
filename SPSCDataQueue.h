/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_SPSCDATAQUEUE_H
#define AUOMS_SPSCDATAQUEUE_H

#include <cinttypes>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstring>
#include <list>

#include <sys/types.h>

class Segment;

class SPSCDataQueue {
public:
    SPSCDataQueue(size_t segment_size, size_t num_segments);

    uint8_t* Allocate(size_t size, size_t* loss_bytes);
    inline uint8_t* Allocate(size_t size) { return Allocate(size, nullptr); }

    void Commit(size_t size);

    void Close();

    ssize_t Get(uint8_t** ptr);

    void Release();

    bool IsClosed() { return _closed; }

private:
    std::mutex _mutex;
    std::condition_variable _cond;
    std::list<Segment*> _free;
    std::list<Segment*> _ready;
    Segment* _current_in;
    Segment* _current_out;
    std::atomic<bool> _closed;
};


#endif //AUOMS_SPSCDATAQUEUE_H
