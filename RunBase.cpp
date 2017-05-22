/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "RunBase.h"
#include "Logger.h"

#include <chrono>

#include <signal.h>

void* RunBase::thread_entry(void* ptr) {
    static_cast<RunBase*>(ptr)->thread_run();
    return nullptr;
}

void RunBase::thread_run() {
    sigset_t set;

    // Make sure these signals don't interrupt the thread
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // Make sure the thread will get interrupted by SIGQUIT
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    try {
        run();
    } catch (std::exception& ex) {
        Logger::Error("RunBase::thread_run: Unexpected exception thrown from run(): %s", ex.what());
    }

    {
        std::unique_lock<std::mutex> lock(_run_mutex);
        if (!_stop) {
            _stop = true;
            _run_cond.notify_all();
        }

        _stopped = true;
        lock.unlock();
        on_stop();
    }
}

void RunBase::Start() {
    std::lock_guard<std::mutex> lock(_run_mutex);
    if (!_start) {
        auto err = pthread_create(&_thread_id, nullptr, RunBase::thread_entry, this);
        if (err != 0) {
            throw std::system_error(err, std::system_category());
        }
        _start = true;
    }
}

void RunBase::Stop() {
    Stop(true);
}

void RunBase::Stop(bool wait) {
    std::unique_lock<std::mutex> lock(_run_mutex);
    if (!_stop) {
        _stop = true;
        _run_cond.notify_all();
        lock.unlock();
        // Make sure syscalls (e.g. sleep, read, write) get interrupted
        pthread_kill(_thread_id, SIGQUIT);
        lock.lock();
    }
    if (wait) {
        lock.unlock();
        Wait();
    }
}

bool RunBase::IsStopping() {
    std::lock_guard<std::mutex> lock(_run_mutex);
    return _stop;
}

void RunBase::Wait() {
    std::unique_lock<std::mutex> lock(_run_mutex);
    if (!_joined) {
        _joined = true;
        lock.unlock();
        pthread_join(_thread_id, nullptr);
        _run_cond.notify_all();
    } else {
        return _run_cond.wait(lock, [this]() { return _stopped; });
    }
}

bool RunBase::_sleep(int millis) {
    std::unique_lock<std::mutex> lock(_run_mutex);
    return _sleep_locked(lock, millis);
}

bool RunBase::_sleep_locked(std::unique_lock<std::mutex>& lock, int millis) {
    auto now = std::chrono::steady_clock::now();
    _run_cond.wait_until(lock, now + (std::chrono::milliseconds(1) * millis), [this]() { return _stop; });
    return _stop;
}

void RunBase::on_stop() {
    return;
}
