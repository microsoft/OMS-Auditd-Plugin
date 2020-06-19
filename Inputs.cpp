/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <cstring>
#include "Inputs.h"
#include "Logger.h"

bool Inputs::Initialize() {
    Logger::Info("Inputs initializing");

    _op_status->SetErrorCondition(ErrorCategory::DATA_COLLECTION, "No collectors connected!");

    return _listener.Open();
}

void Inputs::on_stopping() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _listener.Close();
}

void Inputs::on_stop() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _buffer->Close();

    while(!_inputs.empty()) {
        auto i = _inputs.begin()->second;
        lock.unlock();
        i->Stop();
        lock.lock();
    }

    _inputs.clear();
    cleanup();

    Logger::Info("Inputs stopped");
}

void Inputs::run() {
    Logger::Info("Inputs starting");

    while(!IsStopping()) {
        int newfd = _listener.Accept();
        if (newfd > 0) {
            Logger::Info("Inputs: new connection: fd == %d", newfd);
            if (!IsStopping()) {
                add_connection(newfd);
            } else {
                close(newfd);
            }
        } else {
            return;
        }
    }
}

void Inputs::cleanup() {
    for (auto input : _inputs_to_clean) {
        input->Stop();
    }
    _inputs_to_clean.clear();
}

void Inputs::add_connection(int fd) {
    std::lock_guard<std::mutex> lock(_run_mutex);

    cleanup();

    auto input = std::make_shared<Input>(std::make_unique<IOBase>(fd), _buffer, [this, fd]() { remove_connection(fd); });
    _inputs.insert(std::make_pair(fd, input));
    input->Start();
    _op_status->ClearErrorCondition(ErrorCategory::DATA_COLLECTION);
}

void Inputs::remove_connection(int fd) {
    std::lock_guard<std::mutex> lock(_run_mutex);
    auto it = _inputs.find(fd);
    if (it != _inputs.end()) {
        _inputs_to_clean.push_back(it->second);
        _inputs.erase(fd);
    }

    if (_inputs.empty()) {
        _op_status->SetErrorCondition(ErrorCategory::DATA_COLLECTION, "No collectors connected!");
    }
}
