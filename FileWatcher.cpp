/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "FileWatcher.h"

#include "Logger.h"
#include "IO.h"

#include <cstring>

#include <unistd.h>


void FileWatcher::on_stopping() {
    std::lock_guard<std::mutex> lock(_run_mutex);
    if (_fd > 0) {
        close(_fd);
        _fd = -1;
    }
}

void FileWatcher::run() {
    /* Create the file descriptor for accessing the inotify API */
    int fd = inotify_init();
    if (fd == -1) {
        Logger::Error("FileWatcher: Failed to init inotify socket: %s", std::strerror(errno));
        return;
    }

    std::unordered_map<int, std::string> watch_map;
    for (auto& w: _watches) {
        int wd;
        wd = inotify_add_watch(fd, w.first.c_str(), w.second);
        if (wd == -1) {
            close(fd);
            Logger::Error("FileWatcher: Failed add watch for '%s': %s", w.first.c_str(), std::strerror(errno));
            return;
        }
        watch_map.emplace(wd, w.first);
    }

    {
        std::lock_guard<std::mutex> lock(_run_mutex);
        if (!_stop) {
            _fd = fd;
        } else {
            close(fd);
            return;
        }
    }

    char buf[4096]
            __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t nr;
    char *ptr;

    IOBase conn(fd);

    while (!IsStopping()) {
        nr = conn.Read(buf, sizeof buf, [this]() { return IsStopping(); });
        if (nr <= 0) {
            close(fd);
            if (nr == IO::FAILED) {
                Logger::Warn("FileWatcher: failed to read from inotify socket: %s", std::strerror(errno));
            }
            return;
        }

        /* Loop over all events in the buffer */
        for (ptr = buf; ptr < buf + nr; ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;

            auto itr = watch_map.find(event->wd);
            if (itr != watch_map.end()) {
                _notify_fn(itr->second, event->name, event->mask);
            }
        }
    }
}
