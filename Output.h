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

    void Close();

    bool Add(const EventId& event_id, uint32_t priority, uint64_t seq);

    // Returns false on timeout, true is queue is empty
    bool Wait(int millis);

    bool Ack(const EventId& event_id, uint32_t& priority, uint64_t& seq);

private:
    class _RingEntry {
    public:
        _RingEntry(EventId id, uint32_t p, uint64_t s): _id(id), _priority(p), _seq(s) {}
        EventId _id;
        uint32_t _priority;
        uint64_t _seq;
    };

    std::mutex _mutex;
    std::condition_variable _cond;
    std::vector<_RingEntry> _ring;
    size_t _max_size;
    bool _closed;
    size_t _head;
    size_t _tail;
    size_t _size;
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
              std::shared_ptr<QueueCursor> cursor,
              std::shared_ptr<AckQueue> ack_queue);

protected:
    virtual void run();

    std::string _name;
    std::shared_ptr<IEventWriter> _event_writer;
    std::shared_ptr<IOBase> _writer;
    std::shared_ptr<QueueCursor> _cursor;
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

    Output(const std::string& name, const std::shared_ptr<PriorityQueue>& queue, const std::shared_ptr<IEventWriterFactory>& writer_factory, const std::shared_ptr<IEventFilterFactory>& filter_factory):
            _name(name), _queue(queue), _writer_factory(writer_factory), _filter_factory(filter_factory), _ack_mode(false)
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
    std::unique_ptr<Config> _config;
    std::shared_ptr<QueueCursor> _cursor;
    std::shared_ptr<IEventWriter> _event_writer;
    std::shared_ptr<IEventFilter> _event_filter;
    std::shared_ptr<IOBase> _writer;
    std::shared_ptr<AckQueue> _ack_queue;
    std::unique_ptr<AckReader> _ack_reader;
};


#endif //AUOMS_OUTPUT_H
