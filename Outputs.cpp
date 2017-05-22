/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Outputs.h"

#include "Logger.h"

#include <cstring>

extern "C" {
#include <dirent.h>
#include <unistd.h>
}

void Outputs::Reload() {
    Logger::Info("Reload requested");
    std::unique_lock<std::mutex> lock(_run_mutex);
    _do_reload = true;
    _run_cond.notify_all();
}

void Outputs::on_stop() {
    for( auto ent: _outputs) {
        ent.second->Stop();
    }
    _outputs.clear();
}

void Outputs::run() {
    do_conf_sync();

    std::unique_lock<std::mutex> lock(_run_mutex);
    while (!_stop) {
        _run_cond.wait(lock, [this]() { return _stop || _do_reload; });
        if (_do_reload) {
            _do_reload = false;
            lock.unlock();
            do_conf_sync();
            lock.lock();
        }
    }
}

void Outputs::do_conf_sync() {
    std::unique_lock<std::mutex> lock(_mutex);

    std::unordered_map<std::string, std::string> new_outputs;

    std::array<char, 1024> buffer;

    auto dir = opendir(_conf_dir.c_str());
    if (dir == nullptr) {
        Logger::Error("Outputs: Failed to open outconf dir (%s): %s", _conf_dir.c_str(), std::strerror(errno));
        return;
    }

    struct dirent* dent;
    while(readdir_r(dir, reinterpret_cast<struct dirent*>(buffer.data()), &dent) == 0) {
        if (dent == nullptr) {
            break;
        }

        std::string name(&dent->d_name[0]);
        if (name.length() > 5) {
            auto prefix_len = name.length() - 5;
            if (name.substr(prefix_len, 5) == ".conf") {
                new_outputs[name.substr(0, prefix_len)] = _conf_dir + "/" + name;
            }
        }
    }
    closedir(dir);

    std::unordered_map<std::string, std::shared_ptr<Output>> to_delete;
    for(auto ent: _outputs) {
        if (new_outputs.find(ent.first) == new_outputs.end()) {
            to_delete.insert(ent);
        }
    }

    for(auto ent: to_delete) {
        _outputs.erase(ent.first);
        ent.second->Stop();
        ent.second->Delete();
    }

    for(auto ent: new_outputs) {
        auto it = _outputs.find(ent.first);
        if (it != _outputs.end()) {
            if (it->second->IsValid()) {
                it->second->Reload();
            } else {
                it->second->Stop();
                it->second->Delete();
                _outputs.erase(it);
                it = _outputs.end();
            }
        }

        if (it == _outputs.end()) {
            auto cursor_file = _cursor_dir + "/" + ent.first + ".cursor";
            auto o = std::make_shared<Output>(ent.first, ent.second, cursor_file, _allowed_socket_dirs, _queue);
            _outputs.insert(std::make_pair(ent.first, o));
            o->Start();
        }
    }
}
