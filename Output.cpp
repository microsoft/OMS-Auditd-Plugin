/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Output.h"
#include "Logger.h"
#include "UnixDomainWriter.h"

#include "OMSEventWriter.h"
#include "JSONEventWriter.h"
#include "MsgPackEventWriter.h"
#include "RawEventWriter.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
}

bool Output::IsValid() {
    std::lock_guard<std::mutex> lock(_mutex);
    return _config_valid;
}

void Output::Reload() {
    std::unique_ptr<Config> config(new Config());

    try {
        config->Load(_conf_path);
    } catch (std::runtime_error& ex) {
        Logger::Error("Output(%s): Failed to reload configuration: %s", _name.c_str(), ex.what());
        return;
    }

    std::lock_guard<std::mutex> lock(_mutex);

    if (!_config || *_config != *config) {
        _config = std::move(config);
        _reload_pending = true;
        Logger::Info("Output(%s): Reloading config", _name.c_str());
    }
}

// Delete any resources associated with the output
void Output::Delete() {
    delete_cursor_file();
    Logger::Info("Output(%s): Removed", _name.c_str());
}


bool Output::read_cursor_file() {
    std::array<uint8_t, QueueCursor::DATA_SIZE> data;

    int fd = open(_cursor_path.c_str(), O_RDONLY);
    if (fd < 0) {
        if (errno != ENOENT) {
            Logger::Error("Output(%s): Failed to open cursor file (%s): %s", _name.c_str(), _cursor_path.c_str(), std::strerror(errno));
            return false;
        } else {
            _cursor = QueueCursor::TAIL;
            return true;
        }
    }

    auto ret = read(fd, data.data(), data.size());
    if (ret != data.size()) {
        if (ret >= 0) {
            Logger::Error("Output(%s): Failed to read cursor file (%s): only %d bytes out of %d where read", _name.c_str(), _cursor_path.c_str(), std::strerror(errno), ret, data.size());
        } else {
            Logger::Error("Output(%s): Failed to read cursor file (%s): %s", _name.c_str(), _cursor_path.c_str(), std::strerror(errno));
        }
        close(fd);
        return false;
    }
    close(fd);

    _cursor.from_data(data);

    return true;
}

bool Output::write_cursor_file() {
    std::array<uint8_t, QueueCursor::DATA_SIZE> data;
    _cursor.to_data(data);

    int fd = open(_cursor_path.c_str(), O_WRONLY|O_CREAT, 0600);
    if (fd < 0) {
        Logger::Error("Output(%s): Failed to open/create cursor file (%s): %s", _name.c_str(), _cursor_path.c_str(), std::strerror(errno));
        return false;
    }

    auto ret = write(fd, data.data(), data.size());
    if (ret != data.size()) {
        if (ret >= 0) {
            Logger::Error("Output(%s): Failed to write cursor file (%s): only %d bytes out of %d where written", _name.c_str(), _cursor_path.c_str(), std::strerror(errno), ret, data.size());
        } else {
            Logger::Error("Output(%s): Failed to write cursor file (%s): %s", _name.c_str(), _cursor_path.c_str(), std::strerror(errno));
        }
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

bool Output::delete_cursor_file() {
    auto ret = unlink(_cursor_path.c_str());
    if (ret != 0 && errno != ENOENT) {
        Logger::Error("Output(%s): Failed to delete cursor file (%s): %s", _name.c_str(), _cursor_path.c_str(), std::strerror(errno));
        return false;
    }
    return true;
}

bool Output::configure() {
    std::string format = "oms";

    if (_config->HasKey("output_format")) {
        format = _config->GetString("output_format");
    }

    if (!_config->HasKey("output_socket")) {
        Logger::Error("Output(%s): Missing required parameter: output_socket", _name.c_str());
        return false;
    }

    auto socket_path = _config->GetString("output_socket");
    for (auto dir: _allowed_socket_dirs) {
        if (socket_path.length() > dir.length() && socket_path.substr(0, dir.length()) == dir) {
            _socket_path = socket_path;
            break;
        }
    }

    if (_socket_path.empty()) {
        Logger::Error("Output(%s): Invalid output_socket parameter value: '%s'", _name.c_str(), socket_path.c_str());
        return false;
    }

    if (format == "oms") {
        OMSEventWriterConfig config;
        if (!config.LoadFromConfig(*_config)) {
            return false;
        }

        _event_writer = std::unique_ptr<IEventWriter>(static_cast<IEventWriter*>(new OMSEventWriter(config)));
    } else if (format == "json") {
        _event_writer = std::unique_ptr<IEventWriter>(static_cast<IEventWriter*>(new JSONEventWriter()));
    } else if (format == "msgpack") {
        _event_writer = std::unique_ptr<IEventWriter>(static_cast<IEventWriter*>(new MsgPackEventWriter()));
    } else if (format == "raw") {
        _event_writer = std::unique_ptr<IEventWriter>(static_cast<IEventWriter*>(new RawEventWriter()));
    } else {
        Logger::Error("Output(%s): Invalid output_format parameter value: '%s'", _name.c_str(), format.c_str());
        return false;
    }

    _writer = std::unique_ptr<UnixDomainWriter>(new UnixDomainWriter(_socket_path));

    std::lock_guard<std::mutex> lock(_mutex);
    _config_valid = true;
    return true;
}

bool Output::check_open()
{
    int sleep_period = START_SLEEP_PERIOD;

    while(!IsStopping() && !is_reload_pending()) {
        if (_writer->IsOpen()) {
            return true;
        }
        Logger::Info("Output(%s): Connecting", _name.c_str());
        if (_writer->Open()) {
            if (IsStopping() || is_reload_pending()) {
                _writer->Close();
                return false;
            }
            Logger::Info("Output(%s): Connected", _name.c_str());
            return true;
        }

        Logger::Info("Output(%s): Sleeping %d seconds before re-trying connection", _name.c_str(), sleep_period);

        if (_sleep(sleep_period*1000)) {
            return false;
        }

        sleep_period = sleep_period * 2;
        if (sleep_period > MAX_SLEEP_PERIOD) {
            sleep_period = MAX_SLEEP_PERIOD;
        }
    }
    return false;
}

bool Output::handle_events() {
    std::array<uint8_t, Queue::MAX_ITEM_SIZE> data;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    int32_t sleep_millis = 100;
    bool cursor_changed = false;

    while(!IsStopping() && !is_reload_pending()) {
        QueueCursor cursor;
        size_t size = data.size();

        auto ret = _queue->Get(_cursor, data.data(), &size, &cursor, sleep_millis);
        if (ret == Queue::CLOSED) {
            return false;
        }

        if (ret == Queue::OK) {
            Event event(data.data(), size);
            if (!_event_writer->WriteEvent(event, _writer.get())) {
                if (!write_cursor_file()) {
                    return false;
                }
                return !IsStopping();
            }
            _cursor = cursor;
            cursor_changed = true;
        }

        auto since_start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        if (since_start < 100) {
            sleep_millis = 100 - static_cast<int32_t>(since_start);
        } else {
            if (cursor_changed) {
                if(!write_cursor_file()) {
                    return false;
                }
                cursor_changed = false;
            }
            start = std::chrono::steady_clock::now();
            sleep_millis = 100;
        }
    }
    if (cursor_changed) {
        if(!write_cursor_file()) {
            return false;
        }
    }
    return is_reload_pending() && !IsStopping();
}

bool Output::is_reload_pending() {
    std::lock_guard<std::mutex> lock(_mutex);
    return _reload_pending;
}

void Output::clear_reload_pending() {
    std::lock_guard<std::mutex> lock(_mutex);
    _reload_pending = false;
}

void Output::on_stop() {
    if (_writer) {
        _writer->Close();
    }
    write_cursor_file();
    Logger::Info("Output(%s): Stopped", _name.c_str());
}

void Output::run() {
    Logger::Info("Output(%s): Started", _name.c_str());

    Logger::Info("Output(%s): Reading configuration (%s)", _name.c_str(), _conf_path.c_str());
    _config = std::unique_ptr<Config>(new Config());
    try {
        _config->Load(_conf_path);
    } catch (std::runtime_error& ex) {
        Logger::Error("Output(%s): Failed to load configuration: %s", _name.c_str(), ex.what());
        return;
    }

    if (!read_cursor_file()) {
        Logger::Error("Output(%s): Aborting because cursor file is unreadable", _name.c_str());
        return;
    }

    while(!IsStopping()) {
        clear_reload_pending();

        if (!configure()) {
            std::lock_guard<std::mutex> lock(_mutex);
            _config_valid = false;
            return;
        }

        while (check_open()) {
            if (!handle_events()) {
                return;
            }
            _writer->Close();
        }
        _writer->Close();
    }

    Logger::Info("Output(%s): Stopped", _name.c_str());
}
