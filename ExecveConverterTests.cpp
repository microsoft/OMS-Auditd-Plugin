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
#define BOOST_TEST_MODULE "ExecveConverterTests"
#include <boost/test/unit_test.hpp>

#include "Logger.h"
#include "RawEventAccumulator.h"
#include "StringUtils.h"
#include "ExecveConverter.h"
#include "TestEventQueue.h"

#include <fstream>
#include <stdexcept>
#include <iostream>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

class RawEventQueue: public IEventBuilderAllocator {
public:
    explicit RawEventQueue(std::vector<std::string>& cmdlines): _buffer(), _size(0), _cmdlines(cmdlines) {}

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
        Event event(_buffer.data(), _size);
        std::vector<EventRecord> recs;
        for(auto& rec :event) {
            if (rec.RecordType() == static_cast<uint32_t>(RecordType::EXECVE)) {
                recs.emplace_back(rec);
            }
        }
        _converter.Convert(recs, _cmdline);
        _cmdlines.emplace_back(_cmdline);
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
    std::vector<std::string>& _cmdlines;
    ExecveConverter _converter;
    std::string _cmdline;
};

class TestData {
public:
    std::string test_name;
    std::vector<std::string> event_records;
    std::string cmdline;
};

std::vector<TestData> test_data = {
        {
                "one-arg",
                {
                        R"event(type=EXECVE msg=audit(1.001:1): argc=1 a0="arg1")event",
                },
                R"cmdline(arg1)cmdline"
        },
        {
                "two-arg",
                {
                        R"event(type=EXECVE msg=audit(1.001:2): argc=2 a0="arg1" a1="arg2")event",
                },
                R"cmdline(arg1 arg2)cmdline"
        },
        {
                "missing-arg",
                {
                        R"event(type=EXECVE msg=audit(1.001:3): argc=5 a0="arg1" a1="arg2")event",
                        R"event(type=EXECVE msg=audit(1.001:3): a4="arg5")event",
                },
                R"cmdline(arg1 arg2 <2...3> arg5)cmdline"
        },
        {
                "multi-part-arg",
                {
                        R"event(type=EXECVE msg=audit(1.001:4): argc=4 a0="arg1" a1="arg2" a2_len=5 a2[0]=3031)event",
                        R"event(type=EXECVE msg=audit(1.001:4): a2[1]=323334 a3="arg4")event",
                },
                R"cmdline(arg1 arg2 01234 arg4)cmdline"
        },
        {
                "multi-part-arg-at-end",
                {
                        R"event(type=EXECVE msg=audit(1.001:4): argc=3 a0="arg1" a1="arg2" a2_len=5 a2[0]=3031)event",
                        R"event(type=EXECVE msg=audit(1.001:4): a2[1]=323334)event",
                },
                R"cmdline(arg1 arg2 01234)cmdline"
        },
        {
                "missing-arg-piece-beginning",
                {
                        R"event(type=EXECVE msg=audit(1.001:5): argc=4 a0="arg1" a1="arg2" a2_len=5)event",
                        R"event(type=EXECVE msg=audit(1.001:5): a2[1]=323334 a3="arg4")event",
                },
                R"cmdline(arg1 arg2 <...>234 arg4)cmdline"
        },
        {
                "missing-arg-piece-middle",
                {
                        R"event(type=EXECVE msg=audit(1.001:6): argc=4 a0="arg1" a1="arg2" a2_len=5 a2[0]=3031)event",
                        R"event(type=EXECVE msg=audit(1.001:6): a2[2]=3334 a3="arg4")event",
                },
                R"cmdline(arg1 arg2 01<...>34 arg4)cmdline"
        },
        {
                "missing-arg-piece-end",
                {
                        R"event(type=EXECVE msg=audit(1.001:7): argc=4 a0="arg1" a1="arg2" a2_len=5 a2[0]=3031)event",
                        R"event(type=EXECVE msg=audit(1.001:7): a3="arg4")event",
                },
                R"cmdline(arg1 arg2 01<...> arg4)cmdline"
        },
        {
                "missing-arg-piece-end-at-end",
                {
                        R"event(type=EXECVE msg=audit(1.001:7): argc=4 a0="arg1" a1="arg2" a2_len=5 a2[0]=3031)event",
                },
                R"cmdline(arg1 arg2 01<...>)cmdline"
        },
        {
                "multi-part-len-only",
                {
                        R"event(type=EXECVE msg=audit(1.001:7): argc=4 a0="arg1" a1="arg2" a2_len=5)event",
                        R"event(type=EXECVE msg=audit(1.001:7): a3="arg4")event",
                },
                R"cmdline(arg1 arg2 <2...2> arg4)cmdline"
        },
        {
                "multi-part-missing-len",
                {
                        R"event(type=EXECVE msg=audit(1.001:7): argc=4 a0="arg1" a1="arg2" a2[0]=3031)event",
                        R"event(type=EXECVE msg=audit(1.001:7): a2[1]=323334 a3="arg4")event",
                },
                R"cmdline(arg1 arg2 <2...2> arg4)cmdline"
        },
};

BOOST_AUTO_TEST_CASE( basic_test ) {
    std::vector<std::string> actual_cmdlines;

    auto prioritizer = DefaultPrioritizer::Create(0);
    auto raw_queue = new RawEventQueue(actual_cmdlines);
    auto raw_allocator = std::shared_ptr<IEventBuilderAllocator>(raw_queue);
    auto raw_builder = std::make_shared<EventBuilder>(raw_allocator, prioritizer);

    auto metrics_queue = new TestEventQueue();
    auto metrics_allocator = std::shared_ptr<IEventBuilderAllocator>(metrics_queue);
    auto metrics_builder = std::make_shared<EventBuilder>(metrics_allocator, prioritizer);
    auto metrics = std::make_shared<Metrics>("test", metrics_builder);

    RawEventAccumulator accumulator(raw_builder, metrics);

    for (auto& test : test_data) {
        for (auto& line: test.event_records) {
            std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();
            std::memcpy(record->Data(), line.data(), line.size());
            if (record->Parse(RecordType::UNKNOWN, line.size())) {
                accumulator.AddRecord(std::move(record));
            } else {
                Logger::Warn("Received unparsable event data: %s", line.c_str());
            }
        }
        accumulator.Flush(0);
    }

    BOOST_REQUIRE_EQUAL(test_data.size(), actual_cmdlines.size());

    for (size_t idx = 0; idx < test_data.size(); ++idx) {
        BOOST_REQUIRE_MESSAGE(test_data[idx].cmdline == actual_cmdlines[idx], "Test [" << test_data[idx].test_name << "] failed: \nExpected: " << test_data[idx].cmdline << "\nGot: " << actual_cmdlines[idx]);
    }
}
