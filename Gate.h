//
// Created by tad on 2/28/19.
//

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
        return _cond.wait_for(lock, std::chrono::milliseconds(timeout), [this,state]() { return _state == state; });
    }

private:
    std::mutex _mutex;
    std::condition_variable _cond;
    state_t _state;
};


#endif //AUOMS_GATE_H
