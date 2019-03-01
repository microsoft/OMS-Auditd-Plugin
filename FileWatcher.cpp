//
// Created by tad on 2/27/19.
//

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
