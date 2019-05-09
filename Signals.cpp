/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "Signals.h"

#include <thread>

#include <unistd.h>
#include <signal.h>

std::atomic<bool> Signals::_exit(false);
std::mutex Signals::_mutex;
std::function<void()> Signals::_hup_fn;
std::function<void()> Signals::_exit_fn;
pthread_t Signals::_main_id;

void handle_sigquit(int sig) {
    // Do nothing
}

// This must be called by the main thread before any other threads are started
void Signals::Init()
{
    _main_id = pthread_self();

    // Just ignore these signals
    signal(SIGALRM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    // SIGQUIT is used to interrupt threads blocked in syscalls
    struct sigaction sa;
    sa.sa_handler = handle_sigquit;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGQUIT, &sa, 0);

    // Block these signals in the main and all other threads.
    // These signals will be handled in the sig handler thread
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_BLOCK, &set, nullptr);
}

void Signals::InitThread()
{
    sigset_t set;

    // Make sure no signals interrupt the thread
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // Make sure the thread will get interrupted by SIGQUIT
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
}

void Signals::Start()
{
    // Start sig handler thread
    std::thread thread(Signals::run);
    thread.detach();
}

bool Signals::IsExit()
{
    return _exit.load();
}

void Signals::Terminate() {
    kill(getpid(), SIGTERM);
}

void Signals::run() {
    sigset_t set;

    // Block SIGQUIT
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    sigprocmask(SIG_BLOCK, &set, nullptr);

    // Wait for these signals
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);

    for (;;) {
        int sig = 0;
        auto ret = sigwait(&set, &sig);
        if (ret != 0) {
            return;
        }
        if (sig == SIGHUP) {
            std::lock_guard<std::mutex> _lock(_mutex);
            if (_hup_fn) {
                _hup_fn();
            }
        } else {
            _exit.store(true);
            {
                std::lock_guard<std::mutex> _lock(_mutex);
                if (_exit_fn) {
                    _exit_fn();
                }
            }
            // Break main thread out of blocking syscall
            pthread_kill(_main_id, SIGQUIT);
            return;
        }
    }
}
