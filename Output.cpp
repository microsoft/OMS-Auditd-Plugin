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
#include "FluentEventWriter.h"
#include "RawEventWriter.h"
#include "SyslogEventWriter.h"
#include "FileUtils.h"

#include <functional>

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
}

/****************************************************************************
 *
 ****************************************************************************/

void AckReader::Init(std::shared_ptr<IEventWriter> event_writer,
                     std::shared_ptr<IOBase> writer) {
    _event_writer = event_writer;
    _writer = writer;
    _event_ids.clear();
}

void AckReader::AddPendingAck(const EventId& id) {
    std::lock_guard<std::mutex> _lock(_mutex);

    auto it = _event_ids.find(id);
    if (it == _event_ids.end()) {
        _event_ids.emplace(id, false);
    }
}

void AckReader::RemoveAck(const EventId& id) {
    std::lock_guard<std::mutex> _lock(_mutex);

    _event_ids.erase(id);
}

bool AckReader::WaitForAck(const EventId& id, long timeout) {
    std::unique_lock<std::mutex> _lock(_mutex);

    if (_event_ids.count(id) == 0) {
        _event_ids.emplace(id, false);
    }

    if (!_cond.wait_for(_lock, std::chrono::milliseconds(timeout), [this, &id]{ return _event_ids[id]; })) {
        return false;
    }

    _event_ids.erase(id);

    return true;
}

void AckReader::handle_ack(const EventId& id) {
    std::lock_guard<std::mutex> _lock(_mutex);

    auto it = _event_ids.find(id);
    if (it != _event_ids.end()) {
        it->second = true;
        _cond.notify_all();
    }
}

void AckReader::run() {
    EventId id;
    while(_event_writer->ReadAck(id, _writer.get()) == IO::OK) {
        handle_ack(id);
    }

    // The connection is lost, Close writer here so that Output::handle_events will exit
    _writer->Close();
}

/****************************************************************************
 *
 ****************************************************************************/

std::shared_ptr<IEventWriter> RawOnlyEventWriterFactory::CreateEventWriter(const std::string& name, const Config& config) {
    std::string format = "raw";

    if (config.HasKey("output_format")) {
        format = config.GetString("output_format");
    }

    if (format == "raw") {
        return std::unique_ptr<IEventWriter>(static_cast<IEventWriter*>(new RawEventWriter()));
    } else {
        return nullptr;
    }
}

/****************************************************************************
 *
 ****************************************************************************/

bool Output::IsConfigDifferent(const Config& config) {
    return *_config != config;
}

bool Output::Load(std::unique_ptr<Config>& config) {
    Logger::Info("Output(%s): Loading config", _name.c_str());

    _config = std::unique_ptr<Config>(new(Config));
    *_config = *config;

    std::string format = "oms";

    if (_config->HasKey("output_format")) {
        format = _config->GetString("output_format");
    }

    // For syslog skip the socket check as this writes directly to Syslog
    std::string socket_path = "";

    if (format.compare("syslog")) {
        if (!_config->HasKey("output_socket")) {
            Logger::Error("Output(%s): Missing required parameter: output_socket", _name.c_str());
            return false;
        } 
        socket_path = _config->GetString("output_socket");
    }

    _event_writer = _writer_factory->CreateEventWriter(_name, *_config);
    if (!_event_writer) {
        return false;
    }

    if (_filter_factory) {
        _event_filter = _filter_factory->CreateEventFilter(_name, *_config);
    } else {
        _event_filter.reset();
    }

    if (config->HasKey("aggregation_rules")) {
        AggregationRule::RulesFromJSON(config->GetJSON("aggregation_rules"), _aggregation_rules);
    }

    if (socket_path != _socket_path || !_writer) {
        _socket_path = socket_path;
        _writer = std::unique_ptr<UnixDomainWriter>(new UnixDomainWriter(_socket_path));
    }

    if (_config->HasKey("enable_ack_mode")) {
        try {
            _ack_mode = _config->GetBool("enable_ack_mode");
        } catch (std::exception) {
            Logger::Error("Output(%s): Invalid enable_ack_mode parameter value", _name.c_str());
            return false;
        }

        if (_ack_mode && !_event_writer->SupportsAckMode()) {
            Logger::Warn("Output(%s): Specified output_format does not support ACK Mode, ignoring 'enable_ack_mode=true'", format.c_str());
            _ack_mode = false;
        }
    }

    if (_ack_mode) {
        if (_config->HasKey("ack_timeout")) {
            try {
                _ack_timeout = _config->GetInt64("ack_timeout");
            } catch (std::exception) {
                Logger::Error("Output(%s): Invalid ack_timeout parameter value", _name.c_str());
                return false;
            }
        }
        if (_ack_timeout == 0 || (_ack_timeout > 0 && _ack_timeout < MIN_ACK_TIMEOUT)) {
            Logger::Warn("Output(%s): ack_timeout parameter value to small (%ld), using (%ld)", _name.c_str(), _ack_timeout, MIN_ACK_TIMEOUT);
            _ack_timeout = MIN_ACK_TIMEOUT;
        }
    }

    return true;
}

// Delete any resources associated with the output
void Output::Delete() {
    _queue->RemoveCursor(_name);
    Logger::Info("Output(%s): Removed", _name.c_str());
}

bool Output::check_open()
{
    int sleep_period = START_SLEEP_PERIOD;

    while(!IsStopping()) {
        if (_writer->IsOpen()) {
            return true;
        }
        Logger::Info("Output(%s): Connecting to %s", _name.c_str(), _socket_path.c_str());
        if (_writer->Open()) {
            if (IsStopping()) {
                _writer->Close();
                return false;
            }
            Logger::Info("Output(%s): Connected", _name.c_str());
            return true;
        } else {
            Logger::Warn("Output(%s): Failed to connect to '%s': %s", _name.c_str(), _socket_path.c_str(), std::strerror(errno));
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

ssize_t Output::send_event(const Event& event) {
    EventId id(event.Seconds(), event.Milliseconds(), event.Serial());
    if (_ack_mode) {
        _ack_reader->AddPendingAck(id);
    }
    auto ret = _event_writer->WriteEvent(event, _writer.get());
    switch (ret) {
    case IEventWriter::NOOP:
         _ack_reader->RemoveAck(id);
        return IWriter::OK;
    case IWriter::OK:
        if (_ack_mode) {
            if (!_ack_reader->WaitForAck(id, _ack_timeout)) {
                Logger::Warn("Output(%s): Timeout waiting for ack", _name.c_str());
                return IO::TIMEOUT;
            }
        }
        return IWriter::OK;
    default:
         _ack_reader->RemoveAck(id);
        return ret;
    }
}

// Return true of the write succeeded
bool Output::handle_queue_event(const Event& event, uint32_t priority, uint64_t sequence) {
    auto ret = send_event(event);
    if (ret != IWriter::OK) {
        return false;
    }

    _queue->Commit(_cursor_handle, priority, sequence);

    return true;
}

// Return <err,false> of the write failed
std::pair<int64_t, bool> Output::handle_agg_event(const Event& event) {
    auto ret = send_event(event);
    return std::make_pair(static_cast<int64_t>(ret), ret == IWriter::OK);
}

bool Output::handle_events(bool checkOpen) {
    _queue->Rollback(_cursor_handle);

    if (_ack_mode) {
        _ack_reader->Init(_event_writer, _writer);
        _ack_reader->Start();
    }

    while(!IsStopping() && (!checkOpen || _writer->IsOpen())) {
        if (_event_aggregator) {
            std::tuple<bool, int64_t, bool> agg_ret;
            do {
                agg_ret = _event_aggregator->HandleEvent([this, checkOpen](const Event& event) -> std::pair<int64_t, bool> {
                    if (IsStopping() || !(checkOpen && _writer->IsOpen())) {
                        return std::make_pair(0, false);
                    }
                    return handle_agg_event(event);
                });
            } while (std::get<0>(agg_ret));
            if (std::get<0>(agg_ret) && !std::get<2>(agg_ret)) {
                // The write failed, so assume the connection is bad
                break;
            }
        }

        std::pair<std::shared_ptr<QueueItem>,bool> get_ret;
        get_ret = _queue->Get(_cursor_handle, 100, !_ack_mode);

        if(get_ret.first) {
            Event event(get_ret.first->Data(), get_ret.first->Size());
            bool filtered = _event_filter && _event_filter->IsEventFiltered(event);
            if (!filtered) {
                if (_event_aggregator) {
                    if (_event_aggregator->AddEvent(event)) {
                        // The event was consumed
                        continue;
                    }
                }
                if (!handle_queue_event(event, get_ret.first->Priority(), get_ret.first->Sequence())) {
                    // The write failed, so assume the connection is bad
                    break;
                }
            }
        }
    }

    // writer must be closed before calling _ack_reader->Stop(), or the stop may hang until the connection is closed remotely.
    _writer->Close();

    if (_ack_mode) {
        _ack_reader->Stop();
    }

    if (!IsStopping()) {
        Logger::Info("Output(%s): Connection lost", _name.c_str());
    }

    return !IsStopping();
}

void Output::on_stopping() {
    Logger::Info("Output(%s): Stopping", _name.c_str());
    _queue->Close(_cursor_handle);
    if (_writer) {
        _writer->CloseWrite();
    }
}

void Output::on_stop() {
    if (_ack_reader) {
        _ack_reader->Stop();
    }

    if (_writer) {
        _writer->Close();
    }

    if (_event_aggregator) {
        if (!_save_file.empty()) {
            try {
                _event_aggregator->Save(_save_file);
            } catch (const std::exception& ex) {
                Logger::Error("Output(%s): Failed to save event aggregation state to '%s': %s", _name.c_str(), _save_file.c_str(), ex.what());
            }
        } else {
            Logger::Error("Output(%s): Failed to save event aggregation state: No save file defined", _name.c_str());
        }
        _event_aggregator.reset();
    }

    Logger::Info("Output(%s): Stopped", _name.c_str());
}

void Output::run() {
    Logger::Info("Output(%s): Started", _name.c_str());

    if (_aggregation_rules.size() > 0) {
        _event_aggregator = std::make_shared<EventAggregator>();
        if (!_save_file.empty() && PathExists(_save_file)) {
            if (!IsOnlyRootWritable(_save_file)) {
                Logger::Error("Output(%s): Event aggregation state file is non-root writable '%s': It will ignored and removed", _name.c_str(), _save_file.c_str());
                _event_aggregator = std::make_shared<EventAggregator>();
            } else {
                try {
                    _event_aggregator->Load(_save_file);
                } catch (const std::exception& ex) {
                    Logger::Error("Output(%s): Failed to load event aggregation state from '%s': %s", _name.c_str(), _save_file.c_str(), ex.what());
                    _event_aggregator = std::make_shared<EventAggregator>();
                }
            }
            if (unlink(_save_file.c_str()) != 0) {
                Logger::Error("Output(%s): Failed to remove aggregation state file '%s': %s", _name.c_str(), _save_file.c_str(), std::strerror(errno));
            }
        }
        try {
            _event_aggregator->SetRules(_aggregation_rules);
        } catch (const std::exception& ex) {
            Logger::Error("Output(%s): Failed to set event aggregation rules: %s", _name.c_str(), ex.what());
            _event_aggregator.reset();
        }
    } else {
        if (!_save_file.empty() && PathExists(_save_file)) {
            if (unlink(_save_file.c_str()) != 0) {
                Logger::Error("Output(%s): Failed to remove aggregation state file '%s': %s", _name.c_str(), _save_file.c_str(), std::strerror(errno));
            }
        }
    }

    _cursor_handle = _queue->OpenCursor(_name);
    if (!_cursor_handle) {
        Logger::Error("Output(%s): Aborting because cursor is invalid", _name.c_str());
        return;
    }

    bool checkOpen = true;

    if (!_config->HasKey("output_socket")) {
        checkOpen = false;
    }

    while(!IsStopping()) {
        while (!checkOpen || check_open()) {
            if (!handle_events(checkOpen)) {
                return;
            }
        }
    }
}
