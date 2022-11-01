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
#define BOOST_TEST_MODULE "EventMatcherTests"
#include <boost/test/unit_test.hpp>

#include <memory>

#include "EventMatcher.h"
#include "TestEventData.h"
#include "TestEventWriter.h"
#include "FieldType.h"
#include "RecordType.h"

class TestRule {
public:
    TestRule(bool should_match, const std::string& rule_json):
        _should_match(should_match) {
        _rule = EventMatchRule::FromJSON(rule_json);
    }

    int _should_match;
    std::shared_ptr<EventMatchRule> _rule;
};

class FieldMatcherTest {
public:
    FieldMatcherTest(const std::string& name, const std::vector<TestRule>& rules): _name(name), _rules(rules), _error() {}

    bool RunTest(const Event& event) {
        std::shared_ptr<EventMatchRule> match_rule = nullptr;
        std::vector<std::shared_ptr<EventMatchRule>> event_rules;
        for (auto& r : _rules) {
            event_rules.emplace_back(r._rule);
            if (!match_rule && r._should_match) {
                match_rule = r._rule;
            }
        }

        EventMatcher matcher;

        if (!matcher.Compile(event_rules)) {
            _error = "Test (" + _name + ") Failed:";
            for (auto& e : matcher.Errors()) {
                _error += "\n";
                _error += e;
            }
            return false;
        }

        // Double compile is intentional to ensure that second compile doesn't break anything
        if (!matcher.Compile(event_rules)) {
            _error = "Test (" + _name + ") Failed:";
            for (auto& e : matcher.Errors()) {
                _error += "\n";
                _error += e;
            }
            return false;
        }

        auto midx = matcher.Match(event);
        std::shared_ptr<EventMatchRule> m = nullptr;
        if (midx > -1) {
            m = event_rules[midx];
        }
        if (match_rule) {
            if (m != match_rule) {
                if (m) {
                    _error = "Test (" + _name + ") Failed: Expected to match: " + match_rule->ToJSONString() + "\nBut instead matched: " + m->ToJSONString();
                } else {
                    _error = "Test (" + _name + ") Failed: Expected to match: " + match_rule->ToJSONString() + "\nBut instead matched nothing";
                }
                return false;
            }
        } else {
            if (m) {
                _error = "Test (" + _name + ") Failed: Should have matched nothing, but instead matched: " + m->ToJSONString();
                return false;
            }
        }
        return true;
    }

    inline const std::string& Error() {
        return _error;
    }
private:
    std::string _name;
    std::vector<TestRule> _rules;
    std::string _error;
};

BOOST_AUTO_TEST_CASE( basic_test ) {
    auto allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(allocator), prioritizer);

    builder->BeginEvent(0, 0, 0, 1);
    builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "", "", 5);
    builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    builder->AddField("user", "1000", "test_user", field_type_t::UID);
    builder->AddField("group", "1000", "test_group", field_type_t::GID);
    builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    builder->AddField("cmdline", "testcmd arg1 arg2 arg3 lastarg", nullptr, field_type_t::UNESCAPED);
    builder->EndRecord();
    if (builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(allocator->IsCommited(), true);

    std::vector<std::string> patterns = {std::initializer_list<std::string>({"testcmd","connect"})};

    std::vector<FieldMatcherTest> tests = {
        {
            "record type no match",
            {{
                {false, R"json({"record_types": ["AUOMS_SYSCALL"], "field_rules": [{"name": "syscall", "op": "eq", "value": "execve"}]})json"},
            }}
        },
        {
            "1 field eq, match",
            {{
                {true, R"json({"record_types": ["AUOMS_SYSCALL","AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "eq", "value": "execve"}]})json"},
            }}
        },
        {
            "1 field eq, not match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "eq", "value": "open"}]})json"},
            }}
        },
        {
            "1 field !eq, match",
            {{
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "!eq", "value": "open"}]})json"},
            }}
        },
        {
            "1 field !eq, not match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "!eq", "value": "execve"}]})json"},
            }}
        },
        {
            "no field eq, not match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "nofield", "op": "eq", "value": "execve"}]})json"},
            }}
        },
        {
            "1 field in, match",
            {{
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "in", "values": ["execve","execveat","connect"]}]})json"},
            }}
        },
        {
            "1 field in, not match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "in", "values": ["open","execveat","connect"]}]})json"},
            }}
        },
        {
            "1 field !in, match",
            {{
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "!in", "values": ["open","execveat","connect"]}]})json"},
            }}
        },
        {
            "1 field !in, not match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "!in", "values": ["execve","execveat","connect"]}]})json"},
            }}
        },
        {
            "1 field re, match",
            {{
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "cmdline", "op": "re", "values": ["^testcmd.*$", "^.*lastarg$"]}]})json"},
            }}
        },
        {
            "1 field re, not match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "cmdline", "op": "re", "values": ["^bash.*$", "^.*lastarg$"]}]})json"},
            }}
        },
        {
            "1 field !re, match",
            {{
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "cmdline", "op": "!re", "values": ["^bash.*$", "^.*lastarg$"]}]})json"},
            }}
        },
        {
            "1 field !re, not match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "cmdline", "op": "!re", "values": ["^testcmd.*$", "^.*lastarg$"]}]})json"},
            }}
        },
        {
            "2 fields eq, match",
            {{
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "eq", "value": "execve"},
                    {"name": "user", "op": "eq", "value": "test_user"}
                ]})json"},
            }}
        },
        {
            "2 fields eq, no match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "eq", "value": "execve"},
                    {"name": "user", "op": "eq", "value": "bob"}
                ]})json"},
            }}
        },
        {
            "2 rules, 1 field eq, match first",
            {{
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "eq", "value": "execve"}]})json"},
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "user", "op": "eq", "value": "test_user"}]})json"},
            }}
        },
        {
            "3 rules, 1 field eq, match last",
            {{
                {false, R"json({"record_types": ["AUOMS_SYSCALL"], "field_rules": [{"name": "syscall", "op": "eq", "value": "execve"}]})json"},
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "doesnotexist", "op": "eq", "value": "placeholder"}]})json"},
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [{"name": "syscall", "op": "eq", "value": "execve"}]})json"},
            }}
        },
        {
            "2 fields, 3 rules eq, match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "eq", "value": "execve"},
                    {"name": "user", "op": "eq", "value": "bob"}
                ]})json"},
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "eq", "value": "execve"},
                    {"name": "doesnotexist", "op": "eq", "value": "placeholder"}
                ]})json"},
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "eq", "value": "execve"},
                    {"name": "user", "op": "eq", "value": "test_user"}
                ]})json"},
            }}
        },
        {
            "2 fields, 3 rules eq, match",
            {{
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "eq", "value": "execve"},
                    {"name": "user", "op": "!re", "value":"^test_.*$"}
                ]})json"},
                {false, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "in", "values": ["execve","execveat"]},
                    {"name": "doesnotexist", "op": "!re", "value":"placeholder"}
                ]})json"},
                {true, R"json({"record_types": ["AUOMS_EXECVE"], "field_rules": [
                    {"name": "syscall", "op": "eq", "value": "execve"},
                    {"name": "user", "op": "eq", "value":"test_user"}
                ]})json"},
            }}
        },
    };

    for (auto& test : tests) {
        if (!test.RunTest(allocator->GetEvent())) {
            BOOST_FAIL(test.Error());
        }
    }
}