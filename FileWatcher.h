//
// Created by tad on 2/27/19.
//

#ifndef AUOMS_FILEWATCHER_H
#define AUOMS_FILEWATCHER_H


#include "RunBase.h"

#include <functional>

#include <sys/inotify.h>


class FileWatcher: public RunBase {
public:
    typedef std::function<void(const std::string& dir, const std::string& name, uint32_t mask)> notify_fn_t;

    FileWatcher(notify_fn_t notify_fn, const std::vector<std::pair<std::string,uint32_t>>& watches): _fd(-1), _notify_fn(std::move(notify_fn)), _watches(watches) {}

protected:
    void on_stopping() override;
    void run() override;

private:
    int _fd;
    notify_fn_t _notify_fn;
    std::vector<std::pair<std::string,uint32_t>> _watches;

};


#endif //AUOMS_FILEWATCHER_H
