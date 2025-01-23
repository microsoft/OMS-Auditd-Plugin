/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#define BOOST_TEST_MODULE "ProcessInfoTests"
#include <boost/test/included/unit_test.hpp>

#include "ProcessInfo.h"
#include "Logger.h"
#include "StringUtils.h"
#include <vector>

class ProcessInfoTests {
public:
    static int ExtractCGroupContainerId(ProcessInfo& processInfo, const std::string& content) {
        return processInfo.ExtractCGroupContainerId(content);
    }
};

BOOST_AUTO_TEST_CASE(container_id_extraction_test) {
    // Create an instance of ProcessInfo using the Open method
    auto processInfo = ProcessInfo::Open(0);

    // Ensure the instance is valid
    BOOST_REQUIRE(processInfo != nullptr);

    // Test containerd format
    std::string containerd_line = "some text /containerd-ebe83cd204c5 more text\n";
    BOOST_CHECK_EQUAL(ProcessInfoTests::ExtractCGroupContainerId(*processInfo, containerd_line), 0);
    BOOST_CHECK_EQUAL(processInfo->container_id(), "ebe83cd204c5");

    // Test Docker format
    std::string docker_line = "some text /docker/ebe83cd204c5 more text\n";
    BOOST_CHECK_EQUAL(ProcessInfoTests::ExtractCGroupContainerId(*processInfo, docker_line), 0);
    BOOST_CHECK_EQUAL(processInfo->container_id(), "ebe83cd204c5");

    // Test system.slice Docker format
    std::string system_docker_line = "some text /system.slice/docker-ebe83cd204c5 more text\n";
    BOOST_CHECK_EQUAL(ProcessInfoTests::ExtractCGroupContainerId(*processInfo, system_docker_line), 0);
    BOOST_CHECK_EQUAL(processInfo->container_id(), "ebe83cd204c5");

    // Test system.slice complex Docker format
    std::string complex_format_line = "12:devices:/system.slice/docker.service/antares/customer/site/lwasv2-php-test/9c088fd6_lwasv2-php-test\n";
    BOOST_CHECK_EQUAL(ProcessInfoTests::ExtractCGroupContainerId(*processInfo, complex_format_line), 0);
    BOOST_CHECK_EQUAL(processInfo->container_id(), "9c088fd6_lwa");

    // Test invalid format
    std::string invalid_line = "some text without container id\n";
    BOOST_CHECK_NE(ProcessInfoTests::ExtractCGroupContainerId(*processInfo, invalid_line), 0);
}