/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_RUNBASE_H
#define AUOMS_RUNBASE_H

#include <mutex>
#include <condition_variable>
#include <pthread.h>

class RunBase {
public:
    RunBase(): _start(false), _stop(true), _joining(true), _joined(true), _stopped(true), _thread_id(0) {}
    virtual ~RunBase();

    void Start();
    void Stop();
    void Stop(bool wait);
    bool IsStopping();
    bool IsStopped(); // Only returns true if stopped and waited
    void Wait();

protected:
    // Return true if _stop is true
    bool _sleep(int millis);
    bool _sleep_locked(std::unique_lock<std::mutex>& lock, int millis);

    // This method is called once when stop is triggered.
    // It is called before the RunBase thread is signaled to stop.
    // _run_mutex is not locked when it is called.
    virtual void on_stopping();

    // This method is called after run has exited. _run_mutex is not locked when it is called.
    virtual void on_stop();

    // This is the main method that is called by the RunBase thread
    virtual void run() = 0;

    std::mutex _run_mutex;
    std::condition_variable _run_cond;
    bool _start;
    bool _stop;
    bool _joining;
    bool _joined;
    bool _stopped;
    pthread_t _thread_id;

private:
    static void* thread_entry(void* ptr);
    void thread_run();
};


#endif //AUOMS_RUNBASE_H
