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


/****************************************************************************
 *
 ****************************************************************************/

AckQueue::AckQueue(size_t max_size): _max_size(max_size), _closed(false), _head(0), _tail(0), _size(0) {
    _ring.reserve(max_size);
    for (size_t i; i < max_size; i++) {
        _ring.emplace_back(EventId(0, 0, 0), QueueCursor(0, 0));
    }
}

void AckQueue::Close() {
    std::unique_lock<std::mutex> _lock(_mutex);
    _closed = true;
    _cond.notify_all();
}

bool AckQueue::Add(const EventId& event_id, const QueueCursor& cursor) {
    std::unique_lock<std::mutex> _lock(_mutex);

    _cond.wait(_lock, [this]() { return _closed || _size < _max_size; });
    if (_size < _max_size) {
        _ring[_head] = std::make_pair(event_id, cursor);
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

bool AckQueue::Ack(const EventId& event_id, QueueCursor& cursor) {
    std::unique_lock<std::mutex> _lock(_mutex);

    ssize_t last = -1;
    while(_size > 0 && _ring[_tail].first <= event_id) {
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
    cursor = _ring[last].second;
    _cond.notify_all();
    return true;
}

/****************************************************************************
 *
 ****************************************************************************/

bool CursorWriter::Read() {
    std::lock_guard<std::mutex> lock(_mutex);

    std::array<uint8_t, QueueCursor::DATA_SIZE> data;

    int fd = open(_path.c_str(), O_RDONLY);
    if (fd < 0) {
        if (errno != ENOENT) {
            Logger::Error("Output(%s): Failed to open cursor file (%s): %s", _name.c_str(), _path.c_str(), std::strerror(errno));
            return false;
        } else {
            _cursor = QueueCursor::TAIL;
            return true;
        }
    }

    auto ret = read(fd, data.data(), data.size());
    if (ret != data.size()) {
        if (ret >= 0) {
            Logger::Error("Output(%s): Failed to read cursor file (%s): only %d bytes out of %d where read", _name.c_str(), _path.c_str(), std::strerror(errno), ret, data.size());
        } else {
            Logger::Error("Output(%s): Failed to read cursor file (%s): %s", _name.c_str(), _path.c_str(), std::strerror(errno));
        }
        close(fd);
        return false;
    }
    close(fd);

    _cursor.from_data(data);

    return true;
}

bool CursorWriter::Write() {
    std::lock_guard<std::mutex> lock(_mutex);

    std::array<uint8_t, QueueCursor::DATA_SIZE> data;
    _cursor.to_data(data);

    int fd = open(_path.c_str(), O_WRONLY|O_CREAT, 0600);
    if (fd < 0) {
        Logger::Error("Output(%s): Failed to open/create cursor file (%s): %s", _name.c_str(), _path.c_str(), std::strerror(errno));
        return false;
    }

    auto ret = write(fd, data.data(), data.size());
    if (ret != data.size()) {
        if (ret >= 0) {
            Logger::Error("Output(%s): Failed to write cursor file (%s): only %d bytes out of %d where written", _name.c_str(), _path.c_str(), std::strerror(errno), ret, data.size());
        } else {
            Logger::Error("Output(%s): Failed to write cursor file (%s): %s", _name.c_str(), _path.c_str(), std::strerror(errno));
        }
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

bool CursorWriter::Delete() {
    auto ret = unlink(_path.c_str());
    if (ret != 0 && errno != ENOENT) {
        Logger::Error("Output(%s): Failed to delete cursor file (%s): %s", _name.c_str(), _path.c_str(), std::strerror(errno));
        return false;
    }
    return true;
}

QueueCursor CursorWriter::GetCursor() {
    std::lock_guard<std::mutex> lock(_mutex);
    return _cursor;
}

void CursorWriter::UpdateCursor(const QueueCursor& cursor) {
    std::lock_guard<std::mutex> lock(_mutex);
    _cursor = cursor;
    _cursor_updated = true;
    _cond.notify_all();
}

void CursorWriter::on_stopping() {
    std::lock_guard<std::mutex> lock(_mutex);
    _cursor_updated = true;
    _cond.notify_all();
}

void CursorWriter::run() {
    while (!IsStopping()) {
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _cond.wait(lock, [this]{ return _cursor_updated;});
            _cursor_updated = false;
        }
        Write();
        _sleep(100);
    }
    Write();
}

/****************************************************************************
 *
 ****************************************************************************/
void AckReader::Init(std::shared_ptr<IEventWriter> event_writer,
                     std::shared_ptr<IOBase> writer,
                     std::shared_ptr<AckQueue> ack_queue,
                     std::shared_ptr<CursorWriter> cursor_writer) {
    _event_writer = event_writer;
    _writer = writer;
    _queue = ack_queue;
    _cursor_writer = cursor_writer;
}

void AckReader::run() {
    EventId id;
    QueueCursor cursor;
    while(_event_writer->ReadAck(id, _writer.get()) == IO::OK) {
        if (_queue->Ack(id, cursor)) {
            _cursor_writer->UpdateCursor(cursor);
        }
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

    if (!_config->HasKey("output_socket")) {
        Logger::Error("Output(%s): Missing required parameter: output_socket", _name.c_str());
        return false;
    }

    auto socket_path = _config->GetString("output_socket");

    _procFilter = std::shared_ptr<ProcFilter>(new ProcFilter(_user_db));
    _procFilter->ParseConfig(_config);

    if (format == "oms") {
        OMSEventWriterConfig oms_config;
        if (!oms_config.LoadFromConfig(*_config)) {
            return false;
        }

        _event_writer = std::unique_ptr<IEventWriter>(static_cast<IEventWriter*>(new OMSEventWriter(oms_config, _user_db)));
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
    _cursor_writer->Delete();
    Logger::Info("Output(%s): Removed", _name.c_str());
}

bool Output::check_open()
{
    int sleep_period = START_SLEEP_PERIOD;

    while(!IsStopping()) {
        if (_writer->IsOpen()) {
            return true;
        }
        Logger::Info("Output(%s): Connecting", _name.c_str());
        if (_writer->Open()) {
            if (IsStopping()) {
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

    _cursor = _cursor_writer->GetCursor();
    _cursor_writer->Start();

    if (_ack_mode) {
        _ack_reader->Init(_event_writer, _writer, _ack_queue, _cursor_writer);
        _ack_reader->Start();
    }

    while(!IsStopping()) {
		std::ostringstream timestamp_str;

		// Update the process inventory and emit inventory events if appropriate
		struct timeval tv;
		gettimeofday(&tv, nullptr);

		uint64_t sec = static_cast<uint64_t>(tv.tv_sec);
		uint32_t msec = static_cast<uint32_t>(tv.tv_usec)/1000;

		if (_last_proc_fetch+PROCESS_INVENTORY_FETCH_INTERVAL <= sec) {
			bool gen_events = false;
			if (_last_proc_event_gen+PROCESS_INVENTORY_EVENT_INTERVAL <= sec) {
				gen_events = true;
			}

            DoProcessInventory(_writer.get(), gen_events);

			_last_proc_fetch = sec;
			if (gen_events) {
				_last_proc_event_gen = sec;
			}

		}

        QueueCursor cursor;
        size_t size = data.size();

        auto ret = _queue->Get(_cursor, data.data(), &size, &cursor, -1);
        if (ret == Queue::CLOSED) {
            break;
        }

        if (ret == Queue::OK) {
            Event event(data.data(), size);

            // Check if this event should be filtered.
			std::string exe, args, user, syscall;
			int pid, ppid;

            for (auto rec : event) {
                for (auto field : rec) {
                    std::string field_name;
                    field_name.assign(field.FieldName(), field.FieldNameSize());
                    if (field_name == "exe") {
                        exe = field.RawValue();
                    } else if (field_name == "cmdline") {
                        std::string value;
                        value.assign(field.RawValue(), field.RawValueSize());
                        auto idx = value.find(" ");
                        if ((idx == std::string::npos) || (value.length() == idx+1)) {
                            args = "";
                        } else {
                            args = value.substr(idx+1, std::string::npos);
                        }
                    } else if (field_name == "uid") {
                        user = field.InterpValue();
                    } else if (field_name == "syscall") {
                        syscall = field.InterpValue();
                    } else if (field_name == "pid") {
                        pid = std::stoi(field.RawValue());
                    } else if (field_name == "ppid") {
                        ppid = std::stoi(field.RawValue());
                    }
                }
            }

            if (syscall == "execve") {
                _procFilter->AddProcess(pid, ppid, exe, args, user);
            }

            if (!_procFilter->FilterProcessSyscall(pid, syscall)) {
                auto ret = _event_writer->WriteEvent(event, _writer.get());
                if (ret != IWriter::OK) {
                    if (ret == IO::FAILED) {
                        Logger::Info("Output(%s): Connection lost", _name.c_str());
                    }
                    break;
                }
            }

            _cursor = cursor;
            if (_ack_mode) {
                _ack_queue->Add(EventId(event.Seconds(), event.Milliseconds(), event.Serial()), _cursor);
            } else {
                _cursor_writer->UpdateCursor(cursor);
            }
        }
    }

    if (_ack_mode) {
        // Wait a short time for final acks to arrive
        _ack_queue->Wait(100);
        _ack_reader->Stop();
    }

    _cursor_writer->Stop();

    return !IsStopping();
}

void Output::on_stopping() {
    Logger::Info("Output(%s): Stopping", _name.c_str());
    _queue->Interrupt();
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
    if (_cursor_writer) {
        _cursor_writer->Stop();
    }
    _cursor_writer->Write();
    Logger::Info("Output(%s): Stopped", _name.c_str());
}

void Output::run() {
    Logger::Info("Output(%s): Started", _name.c_str());

    if (!_cursor_writer->Read()) {
        Logger::Error("Output(%s): Aborting because cursor file is unreadable", _name.c_str());
        return;
    }

    _cursor = _cursor_writer->GetCursor();

    while(!IsStopping()) {
        while (check_open()) {
            if (!handle_events()) {
                return;
            }
            _writer->Close();
        }
    }
}

bool Output::generate_proc_event(ProcessInfo* pinfo, uint64_t sec, uint32_t msec, IWriter *writer) {
    auto ret = _event_builder->BeginEvent(sec, msec, 0, 1);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }

//    uint16_t num_fields = 16;
    uint16_t num_fields = 17;

    ret = _event_builder->BeginRecord(PROCESS_INVENTORY_RECORD_TYPE, PROCESS_INVENTORY_RECORD_NAME, "", num_fields);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    if (!add_int_field("pid", pinfo->pid(), FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    if (!add_int_field("ppid", pinfo->ppid(), FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    if (!add_int_field("ses", pinfo->ses(), FIELD_TYPE_SESSION)) {
        return false;
    }

    if (!add_str_field("starttime", pinfo->starttime().c_str(), FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    if (!add_uid_field("uid", pinfo->uid(), FIELD_TYPE_UID)) {
        return false;
    }

    if (!add_uid_field("euid", pinfo->euid(), FIELD_TYPE_UID)) {
        return false;
    }

    if (!add_uid_field("suid", pinfo->suid(), FIELD_TYPE_UID)) {
        return false;
    }

    if (!add_uid_field("fsuid", pinfo->fsuid(), FIELD_TYPE_UID)) {
        return false;
    }

    if (!add_gid_field("gid", pinfo->gid(), FIELD_TYPE_GID)) {
        return false;
    }

    if (!add_gid_field("egid", pinfo->egid(), FIELD_TYPE_GID)) {
        return false;
    }

    if (!add_gid_field("sgid", pinfo->sgid(), FIELD_TYPE_GID)) {
        return false;
    }

    if (!add_gid_field("fsgid", pinfo->fsgid(), FIELD_TYPE_GID)) {
        return false;
    }

    if (!add_str_field("comm", pinfo->comm().c_str(), FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    if (!add_str_field("exe", pinfo->exe().c_str(), FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    pinfo->format_cmdline(_cmdline);

    bool cmdline_truncated = false;
    if (_cmdline.size() > UINT16_MAX-1) {
        _cmdline.resize(UINT16_MAX-1);
        cmdline_truncated = true;
    }

    if (!add_str_field("cmdline", _cmdline.c_str(), FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    if (!add_str_field("cmdline_truncated", cmdline_truncated ? "true" : "false", FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    if (!add_str_field("key", PROCESS_INVENTORY_RECORD_KEY, FIELD_TYPE_UNCLASSIFIED)) {
        return false;
    }

    ret = _event_builder->EndRecord();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    ret = _event_builder->EndEvent();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }
}

ssize_t Output::DoProcessInventory(IWriter *writer, bool output_events) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);

    uint64_t sec = static_cast<uint64_t>(tv.tv_sec);
    uint32_t msec = static_cast<uint32_t>(tv.tv_usec)/1000;

    auto pinfo = ProcessInfo::Open();
    if (!pinfo) {
        Logger::Error("Failed to open '/proc': %s", strerror(errno));
        return IO::FAILED;
    }

    std::multimap<uint64_t, ProcInfo> procs;

    while (pinfo->next()) {
        procs.insert(std::pair<uint64_t, ProcInfo>(pinfo->start(), pinfo.get()));
        if (output_events) {
            generate_proc_event(pinfo.get(), sec, msec, writer);
        }
    }

    _procFilter->UpdateProcesses(procs);

    return IO::OK;
}

bool Output::add_int_field(const char* name, int val, event_field_type_t ft) {
    _tmp_val.assign(std::to_string(val));
    return add_str_field(name, _tmp_val.c_str(), ft);
}

bool Output::add_str_field(const char* name, const char* val, event_field_type_t ft) {
    int ret = _event_builder->AddField(name, val, nullptr, ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
}

bool Output::add_uid_field(const char* name, int uid, event_field_type_t ft) {
    _tmp_val.assign(std::to_string(uid));
    std::string user = _user_db->GetUserName(uid);
    int ret = _event_builder->AddField(name, _tmp_val.c_str(), user.c_str(), ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
    return add_str_field(name, _tmp_val.c_str(), ft);
}

bool Output::add_gid_field(const char* name, int gid, event_field_type_t ft) {
    _tmp_val.assign(std::to_string(gid));
    std::string user = _user_db->GetGroupName(gid);
    int ret = _event_builder->AddField(name, _tmp_val.c_str(), user.c_str(), ft);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }
    return true;
    return add_str_field(name, _tmp_val.c_str(), ft);
}

void Output::cancel_event()
{
    if (_event_builder->CancelEvent() != 1) {
        throw std::runtime_error("Queue Closed");
    }
}

