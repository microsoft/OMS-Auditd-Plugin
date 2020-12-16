/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Input.h"
#include "Event.h"
#include "Logger.h"

void Input::on_stopping() {
    _conn->Close();
}

void Input::on_stop() {
    _stop_fn();
    Logger::Info("Input(%d): Stopped", _fd);
}

void Input::run() {
    Logger::Info("Input(%d): Started", _fd);

    while (!IsStopping()) {
        void* ptr = nullptr;
        if (!_buffer->BeginWrite(&ptr)) {
            Logger::Info("Input(%d): Stopping", _fd);
            on_stopping();
            return;
        }
        auto ret = _reader.ReadEvent(ptr, _buffer->MAX_DATA_SIZE, _conn.get(), [this]() { return IsStopping(); });
        if (ret <= 0) {
            if (!IsStopping()) {
                switch (ret) {
                    case IO::FAILED:
                        Logger::Info("Input(%d): Stopping due to failed event read", _fd);
                        break;
                    case IO::CLOSED:
                        Logger::Info("Input(%d): Stopping due to closed connection", _fd);
                        break;
                    case IO::INTERRUPTED:
                        Logger::Info("Input(%d): Stopping due to interrupted event read", _fd);
                        break;
                    default:
                        Logger::Info("Input(%d): Stopping due to failed event read", _fd);
                        break;
                }
            }
            _buffer->AbandonWrite();
            // For CLOSED and INTERRUPTED just stop.
            // INTERRUPTED should only be returned if IsStopping() is true
            on_stopping();
            return;
        }

        if (_buffer->CommitWrite(ret)) {
            Event event(ptr, ret);

            ret = _reader.WriteAck(event, _conn.get());
            if (ret != IO::OK) {
                if (!IsStopping()) {
                    switch (ret) {
                        case IO::FAILED:
                            Logger::Info("Input(%d): Stopping due to failed ack write", _fd);
                            break;
                        case IO::CLOSED:
                            Logger::Info("Input(%d): Stopping due to closed connection", _fd);
                            break;
                        case IO::INTERRUPTED:
                            Logger::Info("Input(%d): Stopping due to interrupted ack write", _fd);
                            break;
                        default:
                            Logger::Info("Input(%d): Stopping due to failed ack write", _fd);
                            break;
                    }
                }
                // For CLOSED and INTERRUPTED just stop.
                // INTERRUPTED should only be returned is IsStopping() is true
                on_stopping();
                return;
            }
        } else {
            Logger::Info("Input(%d): Stopping", _fd);
            on_stopping();
            return;
        }
    }

    Logger::Info("Input(%d): Stopping", _fd);
}
