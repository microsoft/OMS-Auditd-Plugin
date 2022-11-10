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
#include "EventAggregator.h"

#include <string>
#include <mutex>
#include <memory>
#include <vector>

/****************************************************************************
 *
 ****************************************************************************/

class Output;

class AckReader: public RunBase {
public:

    AckReader(const std::string& name): _name(name)
    {}

    void Init(std::shared_ptr<IEventWriter> event_writer,
              std::shared_ptr<IOBase> writer);

    void AddPendingAck(const EventId& id);
    void RemoveAck(const EventId& id);
    bool WaitForAck(const EventId& id, long timeout);

protected:
    void handle_ack(const EventId& id);
    virtual void run();

    std::mutex _mutex;
    std::condition_variable _cond;
    std::string _name;
    std::shared_ptr<IEventWriter> _event_writer;
    std::shared_ptr<IOBase> _writer;
    std::unordered_map<EventId, bool> _event_ids;
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

/****************************************************************************
 *
 ****************************************************************************/

class Output: public RunBase {
public:
    static constexpr int START_SLEEP_PERIOD = 1;
    static constexpr int MAX_SLEEP_PERIOD = 60;
    static constexpr int DEFAULT_ACK_QUEUE_SIZE = 1000;
    static constexpr long MIN_ACK_TIMEOUT = 100;
    static constexpr long DEFAULT_ACK_TIMEOUT = 300*1000; // 5 minutes

    Output(const std::string& name, const std::string& save_dir, const std::shared_ptr<PriorityQueue>& queue, const std::shared_ptr<IEventWriterFactory>& writer_factory, const std::shared_ptr<IEventFilterFactory>& filter_factory):
            _name(name), _save_dir(save_dir), _queue(queue), _writer_factory(writer_factory), _filter_factory(filter_factory), _ack_mode(false), _ack_timeout(DEFAULT_ACK_TIMEOUT)
    {
        _ack_reader = std::unique_ptr<AckReader>(new AckReader(name));
        _save_file = _save_dir + "/" + name + ".aggsavefile";
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

    ssize_t send_event(const Event& event);
    bool handle_queue_event(const Event& event, uint32_t priority, uint64_t sequence);
    std::pair<int64_t, bool> handle_agg_event(const Event& event);

    // Return true if writer closed and Output should reconnect, false if Output should stop.
    bool handle_events(bool checkOpen=true);

    std::mutex _mutex;
    std::string _name;
    std::string _save_dir;
    std::string _save_file;
    std::string _socket_path;
    std::shared_ptr<PriorityQueue> _queue;
    std::shared_ptr<IEventWriterFactory> _writer_factory;
    std::shared_ptr<IEventFilterFactory> _filter_factory;
    bool _ack_mode;
    uint64_t _ack_timeout;
    std::unique_ptr<Config> _config;
    std::shared_ptr<QueueCursorHandle> _cursor_handle;
    std::shared_ptr<IEventWriter> _event_writer;
    std::shared_ptr<IEventFilter> _event_filter;
    std::shared_ptr<IOBase> _writer;
    std::vector<std::shared_ptr<AggregationRule>> _aggregation_rules;
    std::shared_ptr<EventAggregator> _event_aggregator;
    std::unique_ptr<AckReader> _ack_reader;
};


#endif //AUOMS_OUTPUT_H
