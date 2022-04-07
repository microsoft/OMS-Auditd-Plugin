/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "EventProcessorTests"
#include <boost/test/unit_test.hpp>

#include "PriorityQueue.h"
#include "Logger.h"
#include "TempDir.h"
#include "TestEventData.h"
#include "RawEventProcessor.h"
#include "RawEventAccumulator.h"
#include "StringUtils.h"
#include "EventPrioritizer.h"
#include "InputBuffer.h"

#include <fstream>
#include <stdexcept>
#include <iostream>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

void write_file(const std::string& path, const std::string& text) {
    std::ofstream out;
    out.exceptions(std::ofstream::failbit|std::ofstream::badbit|std::ofstream::eofbit);
    out.open(path);
    out << text;
    out.close();
}

class RawEventQueue: public IEventBuilderAllocator {
public:
    explicit RawEventQueue(std::shared_ptr<RawEventProcessor> proc): _buffer(), _size(0), _proc(std::move(proc)) {}

    bool Allocate(void** data, size_t size) override {
        if (_size != size) {
            _size = size;
        }
        if (_buffer.size() < _size) {
            _buffer.resize(_size);
        }
        *data = _buffer.data();
        return true;
    }

    int Commit() override {
        if (_size > InputBuffer::MAX_DATA_SIZE) {
            return -1;
        }
        _proc->ProcessData(_buffer.data(), _size);
        _size = 0;
        return 1;
    }

    bool Rollback() override {
        _size = 0;
        return true;
    }

private:
    std::vector<uint8_t> _buffer;
    size_t _size;
    std::shared_ptr<RawEventProcessor> _proc;
};


void diff_event(int idx, const Event& e, const Event& a) {
    std::stringstream msg;
    if (e.Seconds() != a.Seconds()) {
        msg << "Event["<<idx<<"] Seconds Mismatch: expected " << e.Seconds() << ", got " << a.Seconds();
        throw std::runtime_error(msg.str());
    }
    if (e.Milliseconds() != a.Milliseconds()) {
        msg << "Event["<<idx<<"] Milliseconds Mismatch: expected " << e.Milliseconds() << ", got " << a.Milliseconds();
        throw std::runtime_error(msg.str());
    }
    if (e.Serial() != a.Serial()) {
        msg << "Event["<<idx<<"] Serial Mismatch: expected " << e.Serial() << ", got " << a.Serial();
        throw std::runtime_error(msg.str());
    }
    if (e.Flags() != a.Flags()) {
        msg << "Event["<<idx<<"] Flags Mismatch: expected " << e.Flags() << ", got " << a.Flags();
        throw std::runtime_error(msg.str());
    }
    if (e.Pid() != a.Pid()) {
        msg << "Event["<<idx<<"] Pid Mismatch: expected " << e.Pid() << ", got " << a.Pid();
        throw std::runtime_error(msg.str());
    }

    if (e.NumRecords() != a.NumRecords()) {
        msg << "Event["<<idx<<"] NumRecords Mismatch: expected " << e.NumRecords() << ", got " << a.NumRecords();
        throw std::runtime_error(msg.str());
    }

    for (int r = 0; r < e.NumRecords(); ++r) {
        auto er = e.RecordAt(r);
        auto ar = a.RecordAt(r);

        if (er.RecordType() != ar.RecordType()) {
            msg << "Event["<<idx<<"].Record[" << r << "] RecordType Mismatch: expected " << er.RecordType() << ", got " << ar.RecordType();
            throw std::runtime_error(msg.str());
        }

        if (er.RecordTypeNamePtr() == nullptr || ar.RecordTypeNamePtr() == nullptr) {
            if (er.RecordTypeNamePtr() != ar.RecordTypeNamePtr()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected "
                    << (er.RecordTypeNamePtr() == nullptr ? "null" : er.RecordTypeName())
                    << ", got "
                    << (ar.RecordTypeNamePtr() == nullptr ? "null" : ar.RecordTypeName());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordTypeNamePtr(), ar.RecordTypeNamePtr()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected " << er.RecordTypeNamePtr() << ", got " << ar.RecordTypeNamePtr();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.RecordTextPtr() == nullptr || ar.RecordTextPtr() == nullptr) {
            if (er.RecordTextPtr() != ar.RecordTextPtr()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected "
                    << (er.RecordTextPtr() == nullptr ? "null" : er.RecordTextPtr())
                    << ", got "
                    << (ar.RecordTextPtr() == nullptr ? "null" : ar.RecordTextPtr());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordTextPtr(), ar.RecordTextPtr()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected " << er.RecordTextPtr() << ", got " << ar.RecordTextPtr();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.NumFields() != ar.NumFields()) {
            msg << "Event["<<idx<<"].Record[" << r << "] NumFields Mismatch: expected " << er.NumFields() << ", got " << ar.NumFields() << "\n";

            std::unordered_set<std::string> _en;
            std::unordered_set<std::string> _an;

            for (auto f : er) {
                _en.emplace(f.FieldNamePtr(), f.FieldNameSize());
            }

            for (auto f : ar) {
                _an.emplace(f.FieldNamePtr(), f.FieldNameSize());
            }

            for (auto name : _en) {
                if (_an.count(name) == 0) {
                    msg << "    Expected Field Name Not Found: " << name << "\n";
                }
            }

            for (auto name : _an) {
                if (_en.count(name) == 0) {
                    msg << "    Unxpected Field Name Found: " << name << "\n";
                }
            }

            throw std::runtime_error(msg.str());
        }

        for (int f = 0; f < er.NumFields(); ++f) {
            auto ef = er.FieldAt(f);
            auto af = ar.FieldAt(f);

            if (ef.FieldNamePtr() == nullptr || af.FieldNamePtr() == nullptr) {
                if (ef.FieldNamePtr() != af.FieldNamePtr()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected "
                        << (ef.FieldNamePtr() == nullptr ? "null" : ef.FieldNamePtr())
                        << ", got "
                        << (af.FieldNamePtr() == nullptr ? "null" : af.FieldNamePtr());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.FieldNamePtr(), af.FieldNamePtr()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected " << ef.FieldNamePtr() << ", got " << af.FieldNamePtr();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.RawValuePtr() == nullptr || af.RawValuePtr() == nullptr) {
                if (ef.RawValuePtr() != af.RawValuePtr()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected "
                        << (ef.RawValuePtr() == nullptr ? "null" : ef.RawValuePtr())
                        << ", got "
                        << (af.RawValuePtr() == nullptr ? "null" : af.RawValuePtr());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.RawValuePtr(), af.RawValuePtr()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected " << ef.RawValuePtr() << ", got " << af.RawValuePtr();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.InterpValuePtr() == nullptr || af.InterpValuePtr() == nullptr) {
                if (ef.InterpValuePtr() != af.InterpValuePtr()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] (Name="<<ef.FieldName()<<") InterpValue Mismatch: expected "
                        << (ef.InterpValuePtr() == nullptr ? "null" : ef.InterpValuePtr())
                        << ", got "
                        << (af.InterpValuePtr() == nullptr ? "null" : af.InterpValuePtr());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.InterpValuePtr(), af.InterpValuePtr()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] (Name="<<ef.FieldName()<<") InterpValue Mismatch: expected " << ef.InterpValuePtr() << ", got " << af.InterpValuePtr();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.FieldType() != af.FieldType()) {
                msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] (Name="<<ef.FieldName()<<") FieldType Mismatch: expected " << static_cast<uint>(ef.FieldType()) << ", got " << static_cast<uint>(af.FieldType());
                throw std::runtime_error(msg.str());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE( basic_test ) {
    TempDir dir("/tmp/EventProcessorTests");

    write_file(dir.Path() + "/passwd", passwd_file_text);
    write_file(dir.Path() + "/group", group_file_text);

    auto user_db = std::make_shared<UserDB>(dir.Path());

    user_db->update();

    auto expected_queue = new TestEventQueue();
    auto actual_queue = new TestEventQueue();
    auto metrics_queue = new TestEventQueue();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto expected_allocator = std::shared_ptr<IEventBuilderAllocator>(expected_queue);
    auto actual_allocator = std::shared_ptr<IEventBuilderAllocator>(actual_queue);
    auto metrics_allocator = std::shared_ptr<IEventBuilderAllocator>(metrics_queue);
    auto expected_builder = std::make_shared<EventBuilder>(expected_allocator, prioritizer);
    auto actual_builder = std::make_shared<EventBuilder>(actual_allocator, prioritizer);
    auto metrics_builder = std::make_shared<EventBuilder>(metrics_allocator, prioritizer);

    auto proc_filter = std::make_shared<ProcFilter>(user_db);
    std::shared_ptr<FiltersEngine> filtersEngine; // Intentionally left unassigned
    std::shared_ptr<ProcessTree> processTree; // Intentionally left unassigned

    auto metrics = std::make_shared<Metrics>("test", metrics_builder);

    auto cmdline_redactor = std::make_shared<CmdlineRedactor>();
    auto test_rule = std::make_shared<const CmdlineRedactionRule>(test_redaction_rule_filename, test_redaction_rule_name, test_redaction_rule_regex, '*');
    cmdline_redactor->AddRule(test_rule);

    auto raw_proc = std::make_shared<RawEventProcessor>(actual_builder, user_db, cmdline_redactor, processTree, filtersEngine, metrics);

    auto actual_raw_queue = new RawEventQueue(raw_proc);
    auto actual_raw_allocator = std::shared_ptr<IEventBuilderAllocator>(actual_raw_queue);
    auto actual_raw_builder = std::make_shared<EventBuilder>(actual_raw_allocator, prioritizer);

    for (auto e : test_events) {
        e.Write(expected_builder);
    }

    RawEventAccumulator accumulator(actual_raw_builder, metrics);

    for (int i = 0; i < raw_test_events.size(); i++) {
        auto raw_event = raw_test_events[i];
        auto do_flush = raw_events_do_flush[i];
        std::string event_txt = raw_event;
        auto lines = split(event_txt, '\n');
        for (auto& line: lines) {
            std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();
            std::memcpy(record->Data(), line.c_str(), line.size());
            if (record->Parse(RecordType::UNKNOWN, line.size())) {
                accumulator.AddRecord(std::move(record));
            } else {
                Logger::Warn("Received unparsable event data: %s", line.c_str());
            }
        }
        if (do_flush) {
            accumulator.Flush(0);
        }
    }

    BOOST_REQUIRE_EQUAL(expected_queue->GetEventCount(), actual_queue->GetEventCount());

    for (size_t idx = 0; idx < expected_queue->GetEventCount(); ++idx) {
        diff_event(idx, expected_queue->GetEvent(idx), actual_queue->GetEvent(idx));
    }
}

BOOST_AUTO_TEST_CASE( oversized_event_test ) {
    TempDir dir("/tmp/EventProcessorTests");

    write_file(dir.Path() + "/passwd", passwd_file_text);
    write_file(dir.Path() + "/group", group_file_text);

    auto user_db = std::make_shared<UserDB>(dir.Path());

    user_db->update();

    auto actual_queue = new TestEventQueue();
    auto metrics_queue = new TestEventQueue();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto actual_allocator = std::shared_ptr<IEventBuilderAllocator>(actual_queue);
    auto metrics_allocator = std::shared_ptr<IEventBuilderAllocator>(metrics_queue);
    auto actual_builder = std::make_shared<EventBuilder>(actual_allocator, prioritizer);
    auto metrics_builder = std::make_shared<EventBuilder>(metrics_allocator, prioritizer);

    auto proc_filter = std::make_shared<ProcFilter>(user_db);
    auto filtersEngine = std::make_shared<FiltersEngine>();
    auto processTree = std::make_shared<ProcessTree>(user_db, filtersEngine);

    auto metrics = std::make_shared<Metrics>("test", metrics_builder);

    auto cmdline_redactor = std::make_shared<CmdlineRedactor>();

    auto raw_proc = std::make_shared<RawEventProcessor>(actual_builder, user_db, cmdline_redactor, processTree, filtersEngine, metrics);

    auto actual_raw_queue = new RawEventQueue(raw_proc);
    auto actual_raw_allocator = std::shared_ptr<IEventBuilderAllocator>(actual_raw_queue);
    auto actual_raw_builder = std::make_shared<EventBuilder>(actual_raw_allocator, prioritizer);

    RawEventAccumulator accumulator(actual_raw_builder, metrics);

    auto lines = split(oversized_event_text, '\n');
    for (auto& line: lines) {
        std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();
        std::memcpy(record->Data(), line.c_str(), line.size());
        if (record->Parse(RecordType::UNKNOWN, line.size())) {
            accumulator.AddRecord(std::move(record));
        } else {
            Logger::Warn("Received unparsable event data: %s", line.c_str());
        }
    }
    accumulator.Flush(0);

    BOOST_REQUIRE_EQUAL(actual_queue->GetEventCount(), 1);

    Event e = actual_queue->GetEvent(0);
    BOOST_REQUIRE_LE(e.Size(), InputBuffer::MAX_DATA_SIZE);
}
