/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_OUTPUT_H
#define AUOMS_OUTPUT_H

#include "RunBase.h"
#include "PriorityQueue.h"
#include "Config.h"
#include "EventId.h"
#include "OMSEventWriter.h"
#include "IO.h"
#include "IEventFilter.h"

#include <string>
#include <mutex>
#include <memory>
#include <vector>

/****************************************************************************
 *
 ****************************************************************************/

class AckQueue {
public:
    AckQueue(size_t max_size);

    size_t MaxSize() {
        return _max_size;
    }

    void Init(const std::shared_ptr<PriorityQueue>& queue, const std::shared_ptr<QueueCursorHandle>& cursor_handle);

    void Close();

    bool IsClosed();

    // Return false if timeout, true if added
    bool Add(const EventId& event_id, uint32_t priority, uint64_t seq, long timeout);

    // Set (or update) auto cursor
    void SetAutoCursor(uint32_t priority, uint64_t seq);

    // Get and clear auto cursor
    void ProcessAutoCursor();

    void Remove(const EventId& event_id);

    // Returns false on timeout, true is queue is empty
    bool Wait(int millis);

    void Ack(const EventId& event_id);

private:
    class _CursorEntry {
    public:
        _CursorEntry(EventId event_id, uint32_t priority, uint64_t seq): _event_id(event_id), _priority(priority), _seq(seq) {}
        EventId _event_id;
        uint32_t _priority;
        uint64_t _seq;
    };
    std::mutex _mutex;
    std::condition_variable _cond;
    std::unordered_map<EventId, uint64_t> _event_ids;
    std::map<uint64_t, _CursorEntry> _cursors;
    size_t _max_size;
    std::shared_ptr<PriorityQueue> _queue;
    std::shared_ptr<QueueCursorHandle> _cursor_handle;
    bool _closed;
    bool _have_auto_cursor;
    uint64_t _next_seq;
    uint64_t _auto_cursor_seq;
    std::unordered_map<uint32_t, uint64_t> _auto_cursors;
};

/****************************************************************************
 *
 ****************************************************************************/

class Output;

class AckReader: public RunBase {
public:

    AckReader(const std::string& name): _name(name)
    {}

    void Init(std::shared_ptr<IEventWriter> event_writer,
              std::shared_ptr<IOBase> writer,
              std::shared_ptr<AckQueue> ack_queue);

protected:
    virtual void run();

    std::string _name;
    std::shared_ptr<IEventWriter> _event_writer;
    std::shared_ptr<IOBase> _writer;
    std::shared_ptr<AckQueue> _queue;
};

/****************************************************************************
 *
 ****************************************************************************/

class IEventWriterFactory {
public:
    virtual std::shared_ptr<IEventWriter> CreateEventWriter(const std::string& name, const Config& config) = 0;
};

class RawOnlyEventWriterFactory: public IEventWriterFactory {
public:
    RawOnlyEventWriterFactory() {}

    virtual std::shared_ptr<IEventWriter> CreateEventWriter(const std::string& name, const Config& config) override;
};


/****************************************************************************
 *
 ****************************************************************************/

class IEventFilterFactory {
public:
    virtual std::shared_ptr<IEventFilter> CreateEventFilter(const std::string& name, const Config& config) = 0;
};

class AllPAssEventFilterFactory: public IEventFilterFactory {
public:
    AllPAssEventFilterFactory() {}

    virtual std::shared_ptr<IEventFilter> CreateEventFilter(const std::string& name, const Config& config) override;
};

/****************************************************************************
 *
 ****************************************************************************/

class Output: public RunBase {
public:
    static constexpr int START_SLEEP_PERIOD = 1;
    static constexpr int MAX_SLEEP_PERIOD = 60;
    static constexpr int DEFAULT_ACK_QUEUE_SIZE = 1000;
    static constexpr long MIN_ACK_TIMEOUT = 100;

    Output(const std::string& name, const std::shared_ptr<PriorityQueue>& queue, const std::shared_ptr<IEventWriterFactory>& writer_factory, const std::shared_ptr<IEventFilterFactory>& filter_factory):
            _name(name), _queue(queue), _writer_factory(writer_factory), _filter_factory(filter_factory), _ack_mode(false), _ack_timeout(10000)
    {
        _ack_reader = std::unique_ptr<AckReader>(new AckReader(name));
    }

    bool IsConfigDifferent(const Config& config);

    // Return false if load failed
    bool Load(std::unique_ptr<Config>& config);

    // Delete any resources associated with the output
    void Delete();

protected:
    friend class AckReader;

    virtual void on_stopping();
    virtual void on_stop();
    virtual void run();

    // Return true on success, false if Output should stop.
    bool check_open();

    // Return true if writer closed and Output should reconnect, false if Output should stop.
    bool handle_events(bool checkOpen=true);

    std::mutex _mutex;
    std::string _name;
    std::string _socket_path;
    std::shared_ptr<PriorityQueue> _queue;
    std::shared_ptr<IEventWriterFactory> _writer_factory;
    std::shared_ptr<IEventFilterFactory> _filter_factory;
    bool _ack_mode;
    long _ack_timeout;
    std::unique_ptr<Config> _config;
    std::shared_ptr<QueueCursorHandle> _cursor_handle;
    std::shared_ptr<IEventWriter> _event_writer;
    std::shared_ptr<IEventFilter> _event_filter;
    std::shared_ptr<IOBase> _writer;
    std::shared_ptr<AckQueue> _ack_queue;
    std::unique_ptr<AckReader> _ack_reader;
};


#endif //AUOMS_OUTPUT_H
