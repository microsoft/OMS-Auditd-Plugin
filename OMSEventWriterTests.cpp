/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "OMSEventWriter.h"
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "OMSEventWriterTests"
#include <boost/test/unit_test.hpp>

#include "Queue.h"
#include "Logger.h"
#include "IO.h"
#include "TempDir.h"
#include "TestEventData.h"
#include "TestEventWriter.h"
#include <fstream>
#include <stdexcept>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

BOOST_AUTO_TEST_CASE( basic_test ) {
    TestEventWriter writer;
    auto queue = new TestEventQueue();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto allocator = std::shared_ptr<IEventBuilderAllocator>(queue);
    auto builder = std::make_shared<EventBuilder>(allocator, prioritizer);

    for (auto e : test_events) {
        e.Write(builder);
    }

    EventWriterConfig config;
    config.FieldNameOverrideMap = TestConfigFieldNameOverrideMap;
    config.InterpFieldNameMap = TestConfigInterpFieldNameMap;
    config.FilterRecordTypeSet = TestConfigFilterRecordTypeSet;
    config.FilterFieldNameSet = TestConfigFilterFieldNameSet;

    OMSEventWriter oms_writer(config);

    for (size_t i = 0; i < queue->GetEventCount(); ++i) {
        oms_writer.WriteEvent(queue->GetEvent(i), &writer);
    }

    BOOST_REQUIRE_EQUAL(writer.GetEventCount(), oms_test_events.size());

    for (int i = 0; i < writer.GetEventCount(); ++i) {
        BOOST_REQUIRE_EQUAL(writer.GetEvent(i), oms_test_events[i]);
    }
}
