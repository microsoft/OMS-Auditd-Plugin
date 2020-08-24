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
#include "SyslogEventWriter.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
}


/****************************************************************************
 *
 ****************************************************************************/

AckQueue::AckQueue(size_t max_size): _max_size(max_size), _closed(false), _have_auto_cursor(false), _next_seq(0), _auto_cursor_seq(0) {}

void AckQueue::Init(const std::shared_ptr<PriorityQueue>& queue, const std::shared_ptr<QueueCursorHandle>& cursor_handle) {
    _queue = queue;
    _cursor_handle = cursor_handle;
    _closed = false;
    _event_ids.clear();
    _cursors.clear();
    _auto_cursors.clear();
    _next_seq = 0;
    _have_auto_cursor = false;
    _auto_cursor_seq = 0;
}

void AckQueue::Close() {
    std::unique_lock<std::mutex> _lock(_mutex);
    _closed = true;
    _cond.notify_all();
}

bool AckQueue::IsClosed() {
    std::unique_lock<std::mutex> _lock(_mutex);
    return _closed;
}

bool AckQueue::Add(const EventId& event_id, uint32_t priority, uint64_t seq, long timeout) {
    std::unique_lock<std::mutex> _lock(_mutex);

    if (_cond.wait_for(_lock, std::chrono::milliseconds(timeout), [this]() { return _closed || _event_ids.size() < _max_size; })) {
        auto qseq = _next_seq++;
        _event_ids.emplace(event_id, qseq);
        _cursors.emplace(qseq, _CursorEntry(event_id, priority, seq));
        return true;
    }
    return false;
}

void AckQueue::SetAutoCursor(uint32_t priority, uint64_t seq) {
    std::unique_lock<std::mutex> _lock(_mutex);

    _auto_cursor_seq = _next_seq++;
    _auto_cursors[priority] = seq;
    _have_auto_cursor = true;
}

void AckQueue::ProcessAutoCursor() {
    std::unique_lock<std::mutex> _lock(_mutex);

    if (_have_auto_cursor) {
        for (auto& c : _auto_cursors) {
            _queue->Commit(_cursor_handle, c.first, c.second);
        }
        _auto_cursors.clear();
        _have_auto_cursor = false;
    }
}

void AckQueue::Remove(const EventId& event_id) {
    std::unique_lock<std::mutex> _lock(_mutex);

    auto eitr = _event_ids.find(event_id);
    if (eitr == _event_ids.end()) {
        return;
    }
    auto seq = eitr->second;
    _event_ids.erase(eitr);

    _cursors.erase(seq);
}

bool AckQueue::Wait(int millis) {
    std::unique_lock<std::mutex> _lock(_mutex);

    auto now = std::chrono::steady_clock::now();
    return _cond.wait_until(_lock, now + std::chrono::milliseconds(millis), [this] { return _event_ids.empty(); });
}

void AckQueue::Ack(const EventId& event_id) {
    std::unique_lock<std::mutex> _lock(_mutex);

    std::unordered_map<uint32_t, uint64_t> found_seq;

    auto eitr = _event_ids.find(event_id);
    if (eitr != _event_ids.end()) {
        auto seq = eitr->second;
        _event_ids.erase(eitr);
        _cond.notify_all(); // _event_ids was modified, so notify any waiting Add calls

        // Find and remove all from cursors that are <= seq
        while (!_cursors.empty() && _cursors.begin()->first <= seq) {
            auto& entry = _cursors.begin()->second;
            // Make sure to remove any associated event ids from _event_ids.
            _event_ids.erase(entry._event_id);
            auto itr = found_seq.find(entry._priority);
            if (itr == found_seq.end() || itr->second < entry._seq) {
                found_seq[entry._priority] = entry._seq;
            }
            _cursors.erase(_cursors.begin());
        }
    }

    if (_have_auto_cursor) {
        if (_cursors.empty() || _cursors.begin()->first > _auto_cursor_seq) {
            for (auto& c : _auto_cursors) {
                auto itr = found_seq.find(c.first);
                if (itr == found_seq.end() || itr->second < c.second) {
                    found_seq[c.first] = c.second;
                }
            }
            _auto_cursors.clear();
            _have_auto_cursor = false;
        }
    }

    for (auto& c : found_seq) {
        _queue->Commit(_cursor_handle, c.first, c.second);
    }
}

/****************************************************************************
 *
 ****************************************************************************/
void AckReader::Init(std::shared_ptr<IEventWriter> event_writer,
                     std::shared_ptr<IOBase> writer,
                     std::shared_ptr<AckQueue> ack_queue) {
    _event_writer = event_writer;
    _writer = writer;
    _queue = ack_queue;
}

void AckReader::run() {
    EventId id;
    while(_event_writer->ReadAck(id, _writer.get()) == IO::OK) {
        _queue->Ack(id);
    }
    // The connection is lost, Close writer here so that Output::handle_events will exit
    _writer->Close();

    _queue->ProcessAutoCursor();

    // Make sure any waiting AckQueue::Add() returns immediately instead of waiting for the timeout.
    _queue->Close();
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
    }

    if (_ack_mode) {
        uint64_t ack_queue_size = DEFAULT_ACK_QUEUE_SIZE;
        if (_config->HasKey("ack_queue_size")) {
            try {
                ack_queue_size = _config->GetUint64("ack_queue_size");
            } catch (std::exception) {
                Logger::Error("Output(%s): Invalid ack_queue_size parameter value", _name.c_str());
                return false;
            }
        }
        if (ack_queue_size < 1) {
            Logger::Error("Output(%s): Invalid ack_queue_size parameter value", _name.c_str());
            return false;
        }

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

        if (!_ack_queue || _ack_queue->MaxSize() != ack_queue_size) {
            _ack_queue = std::make_shared<AckQueue>(ack_queue_size);
        }
    } else {
        if (_ack_queue) {
            _ack_queue.reset();
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

bool Output::handle_events(bool checkOpen) {
    _queue->Rollback(_cursor_handle);

    if (_ack_mode) {
        _ack_queue->Init(_queue, _cursor_handle);
        _ack_reader->Init(_event_writer, _writer, _ack_queue);
        _ack_reader->Start();
    }

    while(!IsStopping() && (!checkOpen || _writer->IsOpen())) {
        std::pair<std::shared_ptr<QueueItem>,bool> get_ret;
        do {
            get_ret = _queue->Get(_cursor_handle, 100, !_ack_mode);
        } while((!get_ret.first && !get_ret.second) && (!checkOpen || _writer->IsOpen()));

        if (get_ret.first && (!checkOpen || _writer->IsOpen()) && !IsStopping()) {
            Event event(get_ret.first->Data(), get_ret.first->Size());
            bool filtered = _event_filter && _event_filter->IsEventFiltered(event);
            if (!filtered) {
                if (_ack_mode) {
                    // Avoid racing with receiver, add ack before sending event
                    if (!_ack_queue->Add(EventId(event.Seconds(), event.Milliseconds(), event.Serial()),
                                         get_ret.first->Priority(), get_ret.first->Sequence(),
                                         _ack_timeout)) {
                        if (!_ack_queue->IsClosed()) {
                            Logger::Error("Output(%s): Timeout waiting for Acks", _name.c_str());
                        }
                        break;
                    }
                }

                auto ret = _event_writer->WriteEvent(event, _writer.get());
                if (ret == IEventWriter::NOOP) {
                    if (_ack_mode) {
                        // The event was not sent, so remove it's ack
                        _ack_queue->Remove(EventId(event.Seconds(), event.Milliseconds(), event.Serial()));
                        // And update the auto cursor
                        _ack_queue->SetAutoCursor(get_ret.first->Priority(), get_ret.first->Sequence());
                    }
                } else if (ret != IWriter::OK) {
                    break;
                }

                if (!_ack_mode) {
                    _queue->Commit(_cursor_handle, get_ret.first->Priority(), get_ret.first->Sequence());
                }
            } else {
                if (_ack_mode) {
                    _ack_queue->SetAutoCursor(get_ret.first->Priority(), get_ret.first->Sequence());
                } else {
                    _queue->Commit(_cursor_handle, get_ret.first->Priority(), get_ret.first->Sequence());
                }
            }
        }
    }

    if (_ack_mode) {
        // Wait a short time for final acks to arrive
        _ack_queue->Wait(100);
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
    if (_ack_queue) {
        _ack_queue->Close();
    }
}

void Output::on_stop() {
    if (_ack_reader) {
        _ack_reader->Stop();
    }
    if (_writer) {
        _writer->Close();
    }
    Logger::Info("Output(%s): Stopped", _name.c_str());
}

void Output::run() {
    Logger::Info("Output(%s): Started", _name.c_str());

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
