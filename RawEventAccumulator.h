/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_EVENTACCUMULATOR_H
#define AUOMS_EVENTACCUMULATOR_H

#include "RawEventRecord.h"

#include <map>

class RawEvent {
public:
    static constexpr size_t MAX_EVENT_SIZE = 1024*1024; // Prevent runaway accumulation of records for an event
    static constexpr size_t MAX_NUM_EXECVE_RECORDS = 100; // Make sure there will be room in event for PATH/CWD records that follow EXECVE records.

    explicit RawEvent(EventId event_id): _event_id(event_id), _num_execve_records(0), _num_dropped_records(0), _size(0) {}

    // Returns true if the event is now complete;
    bool AddRecord(std::unique_ptr<RawEventRecord> record);

    int AddEvent(EventBuilder& builder);

private:
    EventId _event_id;
    std::vector<std::unique_ptr<RawEventRecord>> _records;
    std::unordered_map<RecordType, int> _drop_count;
    int _num_execve_records;
    int _num_dropped_records;
    size_t _size;
};

class RawEventAccumulator {
public:
    explicit RawEventAccumulator(const std::shared_ptr<EventBuilder>& builder): _builder(builder) {}

    int AddRecord(std::unique_ptr<RawEventRecord> record);
    int Flush();

private:
    std::shared_ptr<EventBuilder> _builder;
    std::map<EventId, std::unique_ptr<RawEvent>> _events;
};


#endif //AUOMS_EVENTACCUMULATOR_H
