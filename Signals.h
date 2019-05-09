/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_SIGNALS_H
#define AUOMS_SIGNALS_H

#include <atomic>
#include <functional>
#include <mutex>

#include <pthread.h>

class Signals {
public:
    static void Init();
    static void InitThread();
    static void Start();
    static bool IsExit();
    static void Terminate();

    static void SetHupHandler(std::function<void()> fn) {
        std::lock_guard<std::mutex> _lock(_mutex);
        _hup_fn = fn;
    }
    static void SetExitHandler(std::function<void()> fn) {
        std::lock_guard<std::mutex> _lock(_mutex);
        _exit_fn = fn;
    }

private:
    static void run();

    static std::atomic<bool> _exit;
    static std::mutex _mutex;
    static std::function<void()> _hup_fn;
    static std::function<void()> _exit_fn;
    static pthread_t _main_id;
};


#endif //AUOMS_SIGNALS_H
