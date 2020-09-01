/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_GATE_H
#define AUOMS_GATE_H

#include <mutex>
#include <condition_variable>

class Gate {
public:
    typedef enum {OPEN, CLOSED} state_t;

    Gate(state_t state = CLOSED): _state(state) {};

    void Open() {
        std::unique_lock lock(_mutex);
        if (_state != OPEN) {
            _state = OPEN;
            _cond.notify_all();
        }
    }

    void Close() {
        std::unique_lock lock(_mutex);
        if (_state != CLOSED) {
            _state = CLOSED;
            _cond.notify_all();
        }
    }

    state_t GetState() {
        std::unique_lock lock(_mutex);
        return _state;
    };

    // Return true if desired state reached, false on timeout
    bool Wait(state_t state, int timeout) {
        std::unique_lock lock(_mutex);
        if (timeout < 0) {
            _cond.wait(lock, [this, state]() { return _state == state; });
            return true;
        } else {
            return _cond.wait_for(lock, std::chrono::milliseconds(timeout),
                                  [this, state]() { return _state == state; });
        }
    }

private:
    std::mutex _mutex;
    std::condition_variable _cond;
    state_t _state;
};


#endif //AUOMS_GATE_H
