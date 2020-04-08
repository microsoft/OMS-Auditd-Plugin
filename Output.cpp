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

AckQueue::AckQueue(size_t max_size): _max_size(max_size), _closed(false), _head(0), _tail(0), _size(0) {
    _ring.reserve(max_size);
    for (size_t i = 0; i < max_size; i++) {
        _ring.emplace_back(EventId(0, 0, 0), 0, 0);
    }
}

void AckQueue::Close() {
    std::unique_lock<std::mutex> _lock(_mutex);
    _closed = true;
    _cond.notify_all();
}

bool AckQueue::Add(const EventId& event_id, uint32_t priority, uint64_t seq) {
    std::unique_lock<std::mutex> _lock(_mutex);

    _cond.wait(_lock, [this]() { return _closed || _size < _max_size; });
    if (_size < _max_size) {
        _ring[_head] = _RingEntry(event_id, priority, seq);
        _size++;
        _head++;
        if (_head >= _max_size) {
            _head = 0;
        }
        return true;
    } else {
        return false;
    }
}

bool AckQueue::Wait(int millis) {
    std::unique_lock<std::mutex> _lock(_mutex);

    auto now = std::chrono::steady_clock::now();
    return _cond.wait_until(_lock, now + (std::chrono::milliseconds(1) * millis), [this] { return _size == 0; });
}

bool AckQueue::Ack(const EventId& event_id, uint32_t& priority, uint64_t& seq) {
    std::unique_lock<std::mutex> _lock(_mutex);

    ssize_t last = -1;
    while(_size > 0 && _ring[_tail]._id <= event_id) {
        last = _tail;
        _tail++;
        _size--;
        if (_tail >= _max_size) {
            _tail = 0;
        }
    }
    if (last < 0) {
        return false;
    }
    priority = _ring[last]._priority;
    seq = _ring[last]._seq;
    _cond.notify_all();
    return true;
}

/****************************************************************************
 *
 ****************************************************************************/
void AckReader::Init(std::shared_ptr<IEventWriter> event_writer,
                     std::shared_ptr<IOBase> writer,
                     std::shared_ptr<QueueCursor> cursor,
                     std::shared_ptr<AckQueue> ack_queue) {
    _event_writer = event_writer;
    _writer = writer;
    _cursor = cursor;
    _queue = ack_queue;
}

void AckReader::run() {
    EventId id;
    uint32_t priority;
    uint64_t seq;
    while(_event_writer->ReadAck(id, _writer.get()) == IO::OK) {
        if (_queue->Ack(id, priority, seq)) {
            _cursor->Commit(priority, seq);
        }
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
    if (_ack_mode) {
        _ack_reader->Init(_event_writer, _writer, _cursor, _ack_queue);
        _ack_reader->Start();
    }

    while(!IsStopping() && (!checkOpen || _writer->IsOpen())) {
        std::pair<std::shared_ptr<QueueItem>,bool> ret;
        do {
            ret = _cursor->Get(100, !_ack_mode);
        } while((!ret.first && !ret.second) && (!checkOpen || _writer->IsOpen()));

        if (ret.first && (!checkOpen || _writer->IsOpen()) && !IsStopping()) {
            Event event(ret.first->Data(), ret.first->Size());
            bool filtered = _event_filter && _event_filter->IsEventFiltered(event);
            if (!filtered) {
                auto ret = _event_writer->WriteEvent(event, _writer.get());
                if (ret == IEventWriter::NOOP) {
                    filtered = true;
                } else if (ret != IWriter::OK) {
                    break;
                }
            }
            if (_ack_mode && !filtered) {
                _ack_queue->Add(EventId(event.Seconds(), event.Milliseconds(), event.Serial()), ret.first->Priority(), ret.first->Sequence());
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
    _cursor->Close();
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

    _cursor = _queue->OpenCursor(_name);
    if (!_cursor) {
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
