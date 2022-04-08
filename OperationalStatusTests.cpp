/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include "OperationalStatus.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "OperationalStatusTests"

#include <boost/test/unit_test.hpp>

#include "TempFile.h"
#include "TestEventQueue.h"

BOOST_AUTO_TEST_CASE( basic_test ) {
    TempFile file("OperationalStatusTests.");

    auto test_queue = new TestEventQueue();
    auto test_allocator = std::shared_ptr<IEventBuilderAllocator>(test_queue);

    OperationalStatus status(file.Path(), test_allocator);

    status.SetErrorCondition(ErrorCategory::AUDIT_RULES_FILE, "Encountered parse errors:\n"
                                                             "    Failed to parse line 1: Invalid option 'arch=b64'");

    status.SendStatus();
}