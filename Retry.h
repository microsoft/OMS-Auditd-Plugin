/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_RETRY_H
#define AUOMS_RETRY_H

#include <functional>
#include <chrono>
#include <thread>

#include <unistd.h>

template<typename T, class Rep, class Period>
std::pair<T, bool> Retry(int max_retries, const std::chrono::duration<Rep, Period>& initial_sleep_duration, bool exponential, const std::function<T()>& fn, const std::function<bool(T)>& predicate) {
    std::chrono::duration<Rep, Period> sleep_duration = initial_sleep_duration;
    int count = 0;
    T val = fn();
    while(count < max_retries) {
        if (!predicate(val)) {
            return std::make_pair(val, false);
        }
        std::this_thread::sleep_for(sleep_duration);
        if (exponential) {
            sleep_duration = sleep_duration * sleep_duration.count();
        } else {
            sleep_duration += initial_sleep_duration;
        }
        count += 1;
        val = fn();
    }
    return std::make_pair(val, true);
}

#endif //AUOMS_RETRY_H
