/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "AuditEventProcessor.h"
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "EventProcessorTests"
#include <boost/test/unit_test.hpp>

#include "Queue.h"
#include "Logger.h"
#include "TempDir.h"
#include "TestEventData.h"
#include <fstream>
#include <stdexcept>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

const std::string passwd_file_text = R"passwd(
root:x:0:0:root:/root:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
user:x:1000:1000:User,,,:/home/user:/bin/bash
)passwd";

const std::string group_file_text = R"group(
root:x:0:
adm:x:4:user
nogroup:x:65534:
user:x:1000:
)group";

void write_file(const std::string& path, const std::string& text) {
    std::ofstream out;
    out.exceptions(std::ofstream::failbit|std::ofstream::badbit|std::ofstream::eofbit);
    out.open(path);
    out << text;
    out.close();
}

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

        if (er.RecordTypeName() == nullptr || ar.RecordTypeName() == nullptr) {
            if (er.RecordTypeName() != ar.RecordTypeName()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected "
                    << (er.RecordTypeName() == nullptr ? "null" : er.RecordTypeName())
                    << ", got "
                    << (ar.RecordTypeName() == nullptr ? "null" : ar.RecordTypeName());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordTypeName(), ar.RecordTypeName()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected " << er.RecordTypeName() << ", got " << ar.RecordTypeName();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.RecordText() == nullptr || ar.RecordText() == nullptr) {
            if (er.RecordText() != ar.RecordText()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected "
                    << (er.RecordText() == nullptr ? "null" : er.RecordText())
                    << ", got "
                    << (ar.RecordText() == nullptr ? "null" : ar.RecordText());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordText(), ar.RecordText()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected " << er.RecordText() << ", got " << ar.RecordText();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.NumFields() != ar.NumFields()) {
            msg << "Event["<<idx<<"].Record[" << r << "] NumFields Mismatch: expected " << er.NumFields() << ", got " << ar.NumFields() << "\n";

            std::unordered_set<std::string> _en;
            std::unordered_set<std::string> _an;

            for (auto f : er) {
                _en.emplace(f.FieldName(), f.FieldNameSize());
            }

            for (auto f : ar) {
                _an.emplace(f.FieldName(), f.FieldNameSize());
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

            if (ef.FieldName() == nullptr || af.FieldName() == nullptr) {
                if (ef.FieldName() != af.FieldName()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected "
                        << (ef.FieldName() == nullptr ? "null" : ef.FieldName())
                        << ", got "
                        << (af.FieldName() == nullptr ? "null" : af.FieldName());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.FieldName(), af.FieldName()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected " << ef.FieldName() << ", got " << af.FieldName();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.RawValue() == nullptr || af.RawValue() == nullptr) {
                if (ef.RawValue() != af.RawValue()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected "
                        << (ef.RawValue() == nullptr ? "null" : ef.RawValue())
                        << ", got "
                        << (af.RawValue() == nullptr ? "null" : af.RawValue());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.RawValue(), af.RawValue()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected " << ef.RawValue() << ", got " << af.RawValue();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.InterpValue() == nullptr || af.InterpValue() == nullptr) {
                if (ef.InterpValue() != af.InterpValue()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] InterpValue Mismatch: expected "
                        << (ef.InterpValue() == nullptr ? "null" : ef.InterpValue())
                        << ", got "
                        << (af.InterpValue() == nullptr ? "null" : af.InterpValue());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.InterpValue(), af.InterpValue()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] InterpValue Mismatch: expected " << ef.InterpValue() << ", got " << af.InterpValue();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.FieldType() != af.FieldType()) {
                msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldType Mismatch: expected " << ef.FieldType() << ", got " << af.FieldType();
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
    auto expected_allocator = std::shared_ptr<IEventBuilderAllocator>(expected_queue);
    auto actual_allocator = std::shared_ptr<IEventBuilderAllocator>(actual_queue);
    auto expected_builder = std::make_shared<EventBuilder>(expected_allocator);
    auto actual_builder = std::make_shared<EventBuilder>(actual_allocator);
    auto proc_filter = std::make_shared<ProcFilter>(user_db);

    for (auto e : test_events) {
        e.Write(expected_builder);
    }

    load_libaudit_symbols();

    AuditEventProcessor aep(actual_builder, user_db, proc_filter);

    aep.Initialize();

    for (auto raw_event : raw_test_events) {
        aep.ProcessData(raw_event, strlen(raw_event));
        aep.Flush();
    }

    BOOST_REQUIRE_EQUAL(expected_queue->GetEventCount(), actual_queue->GetEventCount());

    for (size_t idx = 0; idx < expected_queue->GetEventCount(); ++idx) {
        diff_event(idx, expected_queue->GetEvent(idx), actual_queue->GetEvent(idx));
    }
}
