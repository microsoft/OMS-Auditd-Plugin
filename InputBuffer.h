/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_INPUTBUFFER_H
#define AUOMS_INPUTBUFFER_H

#include <array>
#include <mutex>
#include <condition_variable>
#include <functional>

class InputBuffer {
public:
    static constexpr size_t MAX_DATA_SIZE = 256*1024;

    InputBuffer(): _data(std::make_unique<std::array<char,MAX_DATA_SIZE>>()), _data_size(0), _has_writer(false), _close(false) {}

    bool BeginWrite(void** data_ptr) {
        std::unique_lock<std::mutex> lock(_mutex);
        // Wait until there is no writer and buffer is empty
        _cond.wait(lock, [this]() { return _close || (!_has_writer && _data_size == 0); });
        if (_close) {
            *data_ptr = nullptr;
            return false;
        }
        *data_ptr = _data->data();
        return true;
    }

    bool CommitWrite(size_t size) {
        std::unique_lock<std::mutex> lock(_mutex);
        _has_writer = false;
        _data_size = size;
        _cond.notify_all();
        // Wait until reader has handled data in buffer
        _cond.wait(lock, [this]() { return _close || _data_size == 0; });
        if (_close) {
            return false;
        }
        return true;
    }

    void AbandonWrite() {
        std::unique_lock<std::mutex> lock(_mutex);
        _has_writer = false;
        _data_size = 0;
        _cond.notify_all();
    }

    bool HandleData(const std::function<void(void*,size_t)>& fn) {
        std::unique_lock<std::mutex> lock(_mutex);
        _cond.wait(lock, [this]() { return _close || _data_size != 0; });
        if (_data_size > 0) {
            fn(_data->data(), _data_size);
            _data_size = 0;
            _cond.notify_all();
            return true;
        }
        return false;
    }

    void Close() {
        std::unique_lock<std::mutex> lock(_mutex);
        _close = true;
        _cond.notify_all();
    }
private:
    std::mutex _mutex;
    std::condition_variable _cond;
    std::unique_ptr<std::array<char,MAX_DATA_SIZE>> _data;
    size_t _data_size;
    bool _has_writer;
    bool _close;
};


#endif //AUOMS_INPUTBUFFER_H
