/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "ProcessTreeTests"
#include <boost/test/unit_test.hpp>

#include "ProcessTree.h"
#include "Logger.h"
#include "TestEventData.h"
#include "RawEventAccumulator.h"
#include "StringUtils.h"
#include "EventPrioritizer.h"

#include <iostream>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

BOOST_AUTO_TEST_CASE( basic_test ) {
    std::shared_ptr<ProcessTree> _processTree;
    const std::string containerid = "ebe83cd204c5";

    const std::string exe1 = "/containerd-shim";
    const std::string exe2 = "/containerd-shim-runc-v2";

    const std::string cmdline1 = "containerdshim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/ebe83cd204c57dc745ce21b595e6aaabf805dc4046024e8eacb84633d2461ec1 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc";
    const std::string cmdline2 = "/usr/bin/containerd-shim-runc-v2 -namespace moby -id    ebe83cd204c57dc745ce21b595e6aaabf805dc4046024e8eacb84633d2461ec1    -address /run/containerd/containerd.sock";

    auto res = _processTree->ExtractContainerId(exe1, cmdline1);
    BOOST_REQUIRE_EQUAL(res, containerid);
    res = _processTree->ExtractContainerId(exe2, cmdline2);
    BOOST_REQUIRE_EQUAL(res, containerid);
}
