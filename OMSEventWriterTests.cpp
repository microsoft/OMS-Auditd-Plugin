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
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "OMSEventWriterTests"
#include <boost/test/unit_test.hpp>

#include "Queue.h"
#include "Logger.h"
#include "IO.h"
#include "TempDir.h"
#include "TestEventData.h"
#include <fstream>
#include <stdexcept>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};


class TestEventWriter: public IWriter {
public:
    virtual ssize_t WriteAll(const void *buf, size_t size) {
        _buf.assign(reinterpret_cast<const char*>(buf), size);
        _events.emplace_back(_buf);
        return size;
    }

    size_t GetEventCount() {
        return _events.size();
    }

    std::string GetEvent(int idx) {
        return _events[idx];
    }

private:
    std::string _buf;
    std::vector<std::string> _events;
};

BOOST_AUTO_TEST_CASE( basic_test ) {
    TestEventWriter writer;
    auto queue = new TestEventQueue();
    auto allocator = std::shared_ptr<IEventBuilderAllocator>(queue);
    auto builder = std::make_shared<EventBuilder>(allocator);

    for (auto e : test_events) {
        e.Write(builder);
    }

    OMSEventWriterConfig config;
    config.FieldNameOverrideMap = std::unordered_map<std::string, std::string> {
            {"1327", "PROCTITLE"},
    };

    config.InterpFieldNameMap = std::unordered_map<std::string, std::string> {
            {"uid", "user"},
            {"auid", "audit_user"},
            {"euid", "effective_user"},
            {"suid", "set_user"},
            {"fsuid", "filesystem_user"},
            {"inode_uid", "inode_user"},
            {"oauid", "o_audit_user"},
            {"ouid", "o_user"},
            {"obj_uid", "obj_user"},
            {"sauid", "sender_audit_user"},
            {"gid", "group"},
            {"egid", "effective_group"},
            {"fsgid", "filesystem_group"},
            {"inode_gid", "inode_group"},
            {"new_gid", "new_group"},
            {"obj_gid", "obj_group"},
            {"ogid", "owner_group"},
            {"sgid", "set_group"},
    };

    config.FilterFlagsMask = 4;

    config.FilterRecordTypeSet = std::unordered_set<std::string> {
            "BPRM_FCAPS",
            "CRED_ACQ",
            "CRED_DISP",
            "CRED_REFR",
            "CRYPTO_KEY_USER",
            "CRYPTO_SESSION",
            "LOGIN",
            "PROCTITLE",
            "USER_ACCT",
            "USER_CMD",
            "USER_END",
            "USER_LOGOUT",
            "USER_START",
    };

    config.FilterFieldNameSet = std::unordered_set<std::string> {
            "arch_r",
            "ses_r",
            "mode_r",
            "syscall_r",
    };

    OMSEventWriter oms_writer(config, nullptr);

    for (size_t i = 0; i < queue->GetEventCount(); ++i) {
        oms_writer.WriteEvent(queue->GetEvent(i), &writer);
    }

    BOOST_REQUIRE_EQUAL(writer.GetEventCount(), oms_test_events.size());

    for (int i = 0; i < writer.GetEventCount(); ++i) {
        BOOST_REQUIRE_EQUAL(writer.GetEvent(i), oms_test_events[i]);
    }
}
