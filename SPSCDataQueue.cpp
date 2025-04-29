/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "SPSCDataQueue.h"
#include <string>
#include <stdexcept>


class Segment {
public:
    static constexpr size_t MIN_ITEM_SIZE = 256;
    static constexpr uint32_t OPEN_STATE = 0L;
    static constexpr uint32_t FULL_STATE = 1L;
    static constexpr uint32_t SEALED_STATE = 2L;

    Segment(size_t size) {
        _size = size;
        _data = new uint8_t[size];
        _index.resize((size/MIN_ITEM_SIZE)+10);
        _head = 0;
        _pidx = 0;
        _cidx = 0;
        _sealed = false;
    }

    ~Segment() {
        delete _data;
    }

    uint32_t Allocate(uint8_t** ptr, size_t size) {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_sealed) {
            return SEALED_STATE;
        } else if (_head + std::max(size, MIN_ITEM_SIZE) > _size) {
            return FULL_STATE;
        }
        _index[_pidx] = static_cast<uint64_t>(_head) << 32U | size;
        *ptr = _data + _head;
        return OPEN_STATE;
    }

    void Commit(size_t size) {
        std::lock_guard<std::mutex> lock(_mutex);
        auto alloc_size = _index[_pidx] & 0xFFFFFFFF;
        if (size > alloc_size) {
            throw std::runtime_error("SPSCDataQueue: Commit size ("+std::to_string(size)+") greater than allocated size ("+std::to_string(alloc_size)+")");
        }
        _index[_pidx] = static_cast<uint64_t>(_head) << 32U | size;
        _head += std::max(size, MIN_ITEM_SIZE);
        _pidx += 1;
        _cond.notify_all();
    }

    void Seal() {
        std::lock_guard<std::mutex> lock(_mutex);
        _sealed = true;
        _cond.notify_all();
    }

    void Reset() {
        std::lock_guard<std::mutex> lock(_mutex);
        _head = 0;
        _pidx = 0;
        _cidx = 0;
        _sealed = false;
    }

    ssize_t Get(uint8_t** ptr) {
        std::unique_lock<std::mutex> lock(_mutex);
        while (!(_pidx > _cidx || _sealed)) {
            _cond.wait(lock);
        }
        if (_pidx > _cidx) {
            auto idx = _index[_cidx];
            *ptr = _data + (idx >> 32U);
            return idx & 0xFFFFFFFF;
        }
        return 0;
    }

    void Release() {
        std::lock_guard<std::mutex> lock(_mutex);
        _cidx += 1;
    }

    size_t Size() { return _head; }

private:
    std::mutex _mutex;
    std::condition_variable _cond;
    uint32_t _size;
    std::vector<uint64_t> _index; // X >> 32 = offset, x&0xFFFFFFFF = size
    uint32_t _head; // offset of first available byte that can be written by producer
    uint32_t _pidx;
    uint32_t _cidx;
    bool _sealed;
    uint8_t* _data;
};

SPSCDataQueue::SPSCDataQueue(size_t segment_size, size_t num_segments) {
    for (int i = 0; i < num_segments; ++i) {
        _free.push_back(new Segment(segment_size));
    }

    _current_in = _free.front();
    _current_out = _current_in;
    _free.pop_front();
    _closed = false;
}

uint8_t* SPSCDataQueue::Allocate(size_t size, size_t* loss_bytes) {
    std::unique_lock<std::mutex> lock(_mutex);
    if (_closed) {
        return nullptr;
    }
    uint8_t* ptr;
    uint32_t ret;
    do {
        lock.unlock();
        ret = _current_in->Allocate(&ptr, size);
        if (ret != Segment::OPEN_STATE) {
            lock.lock();
            if (ret != Segment::SEALED_STATE) {
                _current_in->Seal();
            }
            if (_closed) {
                return nullptr;
            }
            if (!_free.empty()) {
                _current_in = _free.front();
                _free.pop_front();
            } else {
                _current_in = _ready.front();
                _ready.pop_front();
                if (loss_bytes != nullptr) {
                    *loss_bytes = _current_in->Size();
                }
            }
            _current_in->Reset();
            _ready.push_back(_current_in);
            _cond.notify_all();
        }
    } while (ret != Segment::OPEN_STATE);

    return ptr;
}

void SPSCDataQueue::Commit(size_t size) {
    _current_in->Commit(size);
}

void SPSCDataQueue::Close() {
    std::unique_lock<std::mutex> lock(_mutex);
    _closed = true;
    auto out = _current_out;
    auto in = _current_in;
    lock.unlock();
    in->Seal();
    out->Seal();
    _cond.notify_all();
}

ssize_t SPSCDataQueue::Get(uint8_t** ptr) {
    std::unique_lock<std::mutex> lock(_mutex);
    ssize_t ret = 0;
    auto out = _current_out;
    lock.unlock();
    ret = out->Get(ptr);
    if (ret < 0) {
        return ret;
    }
    while (ret == 0) {
        lock.lock();
        _cond.wait(lock, [this](){ return !_ready.empty() || _closed; });
        if (!_ready.empty()) {
            _free.push_back(_current_out);
            _current_out = _ready.front();
            _ready.pop_front();
            out = _current_out;
            lock.unlock();
            ret = out->Get(ptr);
            continue;
        }
        // _ready is empty, therefore _close must == true
        return -1;
    }
    return ret;
}

void SPSCDataQueue::Release() {
    std::unique_lock<std::mutex> lock(_mutex);
    auto out = _current_out;
    lock.unlock();
    out->Release();
}
