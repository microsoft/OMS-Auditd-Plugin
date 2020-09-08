/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_FILEWATCHER_H
#define AUOMS_FILEWATCHER_H


#include "RunBase.h"

#include <functional>

#include <sys/inotify.h>


class FileWatcher: public RunBase {
public:
    typedef std::function<void(const std::string& dir, const std::string& name, uint32_t mask)> notify_fn_t;

    FileWatcher(notify_fn_t&& notify_fn, const std::vector<std::pair<std::string,uint32_t>>& watches): _fd(-1), _notify_fn(std::move(notify_fn)), _watches(watches) {}

protected:
    void on_stopping() override;
    void run() override;

private:
    int _fd;
    notify_fn_t _notify_fn;
    std::vector<std::pair<std::string,uint32_t>> _watches;

};


#endif //AUOMS_FILEWATCHER_H
