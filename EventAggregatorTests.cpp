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
#define BOOST_TEST_MODULE "EventAggregatorTests"
#include <boost/test/unit_test.hpp>

#include <memory>

#include "EventAggregator.h"
#include "TestEventData.h"
#include "TestEventWriter.h"
#include "FieldType.h"
#include "RecordType.h"
#include "TempFile.h"


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
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<TestEventQueue>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(2, 0, 2, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 19);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:02.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["0.000","1.000","2.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["0","1","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("raw_test", R"json(["raw0","raw1","raw2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("interp_test", R"json(["interp0","interp1","interp2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("dyn_test", R"json(["test0","test1","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_null", R"json(["","",""])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_a", R"json(["test0","","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    out_builder->BeginEvent(5, 0, 5, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 19);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:03.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:05.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["3.000","4.000","5.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["3","4","5"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("raw_test", R"json(["raw3","raw4","raw5"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("interp_test", R"json(["interp3","interp4","interp5"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("dyn_test", R"json(["test3","test4","test5"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_null", R"json(["","",""])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_a", R"json(["","test4",""])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->GetEventCount(), 2);

    for (int i = 0; i < 8; ++i) {
        char raw_str[16];
        char interp_str[16];
        char test_str[16];
        snprintf(raw_str, sizeof(raw_str), "raw%i", i);
        snprintf(interp_str, sizeof(interp_str), "interp%i", i);
        snprintf(test_str, sizeof(test_str), "test%i", i);

        uint16_t num_fields = 12;
        if (i % 2 == 0) {
            num_fields += 1;
        }

        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", num_fields);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->AddField("test_r", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_drop", "012345", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_i", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_d", test_str, nullptr, field_type_t::UNCLASSIFIED);
        } else {
            in_builder->AddField("test_d", "bad", test_str, field_type_t::UNCLASSIFIED);
        }
        in_builder->AddField("test_null", "bad", nullptr, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_a", test_str, nullptr, field_type_t::UNCLASSIFIED);
        }
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {},
            "test_r": {
                "mode": "raw",
                "output_name": "raw_test"
            },
            "test_i": {
                "mode": "interp",
                "output_name": "interp_test"
            },
            "test_d": {
                "output_name": "dyn_test"
            },
            "test_null": {
                "mode": "interp"
            },
            "test_drop": {
                "mode": "drop"
            },
            "test_a": {
                "mode": "raw"
            }
        },
        "max_count": 3
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    int output_event_index = 0;

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_consume_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(output_event_index), event);
        return std::make_pair(1, true);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_no_consume_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(output_event_index), event);
        return std::make_pair(-1, false);
    };

    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    auto added = agg->AddEvent(in_allocator->GetEvent(3));
    BOOST_REQUIRE_EQUAL(added, true);

    auto ret = agg->HandleEvent(diff_no_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), -1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), false);

    ret = agg->HandleEvent(diff_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);

    output_event_index = 1;

    for (int i = 4; i < 6; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    added = agg->AddEvent(in_allocator->GetEvent(6));
    BOOST_REQUIRE_EQUAL(added, true);

    ret = agg->HandleEvent(diff_no_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), -1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), false);

    ret = agg->HandleEvent(diff_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}

BOOST_AUTO_TEST_CASE( test_max_size ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(9, 0, 9, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 15);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:09.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "10", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["0.000","1.000","2.000","3.000","4.000","5.000","6.000","7.000","8.000","9.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["0","1","2","3","4","5","6","7","8","9"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2","2","2","2","2","2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test", R"json(["test0","test1","test2","test3","test4","test5","test6","test7","test8","test9"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    for (int i = 0; i < 11; ++i) {
        char test_str[16];
        snprintf(test_str, sizeof(test_str), "test%i", i);

        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 8);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->AddField("test", test_str, nullptr, field_type_t::UNCLASSIFIED);
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {},
            "test": {}
        },
        "max_size": 128
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };

    for (int i = 0; i < 10; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    auto added = agg->AddEvent(in_allocator->GetEvent(10));
    BOOST_REQUIRE_EQUAL(added, true);

    auto ret = agg->HandleEvent(diff_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}


BOOST_AUTO_TEST_CASE( test_max_pending ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(1, 0, 1, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 14);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:01.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:01.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["1.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["1"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {}
        },
        "max_pending": 1,
        "max_size": 128
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };

    in_builder->BeginEvent(1, 0, 1, 1);
    in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 7);
    in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
    in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    in_builder->EndRecord();
    if (in_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    in_builder->BeginEvent(2, 0, 2, 1);
    in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 7);
    in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    in_builder->AddField("ppid", "2", nullptr, field_type_t::UNCLASSIFIED);
    in_builder->AddField("pid", "4", nullptr, field_type_t::UNCLASSIFIED);
    in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    in_builder->EndRecord();
    if (in_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    auto added = agg->AddEvent(in_allocator->GetEvent(0));
    BOOST_REQUIRE_EQUAL(added, true);
    auto ret = agg->HandleEvent(ignore_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);

    added = agg->AddEvent(in_allocator->GetEvent(1));
    BOOST_REQUIRE_EQUAL(added, true);

    ret = agg->HandleEvent(diff_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}

BOOST_AUTO_TEST_CASE( test_max_time ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(2, 0, 2, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 15);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:02.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["0.000","1.000","2.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["0","1","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test", R"json(["test0","test1","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    for (int i = 0; i < 8; ++i) {
        char test_str[16];
        snprintf(test_str, sizeof(test_str), "test%i", i);

        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 8);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->AddField("test", test_str, nullptr, field_type_t::UNCLASSIFIED);
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {},
            "test": {}
        },
        "max_time": 1
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);


    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };

    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    sleep(2);

    auto ret = agg->HandleEvent(diff_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);

    BOOST_REQUIRE_EQUAL(agg->NumPendingAggregates(), 0);
    BOOST_REQUIRE_EQUAL(agg->NumReadyAggregates(), 0);

    for (int i = 4; i < 8; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }
}

BOOST_AUTO_TEST_CASE( test_double_set_rules ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(2, 0, 2, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 19);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:02.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["0.000","1.000","2.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["0","1","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("raw_test", R"json(["raw0","raw1","raw2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("interp_test", R"json(["interp0","interp1","interp2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("dyn_test", R"json(["test0","test1","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_null", R"json(["","",""])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_a", R"json(["test0","","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    for (int i = 0; i < 4; ++i) {
        char raw_str[16];
        char interp_str[16];
        char test_str[16];
        snprintf(raw_str, sizeof(raw_str), "raw%i", i);
        snprintf(interp_str, sizeof(interp_str), "interp%i", i);
        snprintf(test_str, sizeof(test_str), "test%i", i);

        uint16_t num_fields = 12;
        if (i % 2 == 0) {
            num_fields += 1;
        }

        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", num_fields);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->AddField("test_r", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_drop", "012345", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_i", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_d", test_str, nullptr, field_type_t::UNCLASSIFIED);
        } else {
            in_builder->AddField("test_d", "bad", test_str, field_type_t::UNCLASSIFIED);
        }
        in_builder->AddField("test_null", "bad", nullptr, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_a", test_str, nullptr, field_type_t::UNCLASSIFIED);
        }
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {},
            "test_r": {
                "mode": "raw",
                "output_name": "raw_test"
            },
            "test_i": {
                "mode": "interp",
                "output_name": "interp_test"
            },
            "test_d": {
                "output_name": "dyn_test"
            },
            "test_null": {
                "mode": "interp"
            },
            "test_drop": {
                "mode": "drop"
            },
            "test_a": {
                "mode": "raw"
            }
        },
        "max_count": 3,
        "max_size": 8192,
        "max_time": 86400,
        "send_first": false
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);
    agg->SetRules(rules);

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };


    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    auto ret = agg->HandleEvent(ignore_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);

    auto added = agg->AddEvent(in_allocator->GetEvent(3));
    BOOST_REQUIRE_EQUAL(added, true);

    ret = agg->HandleEvent(diff_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}

BOOST_AUTO_TEST_CASE( test_save_load_new_obj ) {
    TempFile tmpFile("/tmp/agg_save_load_");
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(2, 0, 2, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 19);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:02.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["0.000","1.000","2.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["0","1","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("raw_test", R"json(["raw0","raw1","raw2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("interp_test", R"json(["interp0","interp1","interp2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("dyn_test", R"json(["test0","test1","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_null", R"json(["","",""])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_a", R"json(["test0","","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    for (int i = 0; i < 4; ++i) {
        char raw_str[16];
        char interp_str[16];
        char test_str[16];
        snprintf(raw_str, sizeof(raw_str), "raw%i", i);
        snprintf(interp_str, sizeof(interp_str), "interp%i", i);
        snprintf(test_str, sizeof(test_str), "test%i", i);

        uint16_t num_fields = 12;
        if (i % 2 == 0) {
            num_fields += 1;
        }

        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", num_fields);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->AddField("test_r", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_drop", "012345", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_i", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_d", test_str, nullptr, field_type_t::UNCLASSIFIED);
        } else {
            in_builder->AddField("test_d", "bad", test_str, field_type_t::UNCLASSIFIED);
        }
        in_builder->AddField("test_null", "bad", nullptr, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_a", test_str, nullptr, field_type_t::UNCLASSIFIED);
        }
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {},
            "test_r": {
                "mode": "raw",
                "output_name": "raw_test"
            },
            "test_i": {
                "mode": "interp",
                "output_name": "interp_test"
            },
            "test_d": {
                "output_name": "dyn_test"
            },
            "test_null": {
                "mode": "interp"
            },
            "test_drop": {
                "mode": "drop"
            },
            "test_a": {
                "mode": "raw"
            }
        },
        "max_count": 3,
        "max_size": 8192,
        "max_time": 86400,
        "send_first": false
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };

    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    agg->Save(tmpFile.Path());

    auto agg2 = std::make_shared<EventAggregator>();
    agg2->Load(tmpFile.Path());

    auto ret = agg2->HandleEvent(ignore_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);

    auto added = agg2->AddEvent(in_allocator->GetEvent(3));
    BOOST_REQUIRE_EQUAL(added, true);

    ret = agg2->HandleEvent(diff_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}


BOOST_AUTO_TEST_CASE( test_save_load_same_obj ) {
    TempFile tmpFile("/tmp/agg_save_load_");
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(2, 0, 2, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 19);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:00:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:00:02.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["0.000","1.000","2.000"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["0","1","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("raw_test", R"json(["raw0","raw1","raw2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("interp_test", R"json(["interp0","interp1","interp2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("dyn_test", R"json(["test0","test1","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_null", R"json(["","",""])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("test_a", R"json(["test0","","test2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    for (int i = 0; i < 4; ++i) {
        char raw_str[16];
        char interp_str[16];
        char test_str[16];
        snprintf(raw_str, sizeof(raw_str), "raw%i", i);
        snprintf(interp_str, sizeof(interp_str), "interp%i", i);
        snprintf(test_str, sizeof(test_str), "test%i", i);

        uint16_t num_fields = 12;
        if (i % 2 == 0) {
            num_fields += 1;
        }

        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", num_fields);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->AddField("test_r", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_drop", "012345", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("test_i", raw_str, interp_str, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_d", test_str, nullptr, field_type_t::UNCLASSIFIED);
        } else {
            in_builder->AddField("test_d", "bad", test_str, field_type_t::UNCLASSIFIED);
        }
        in_builder->AddField("test_null", "bad", nullptr, field_type_t::UNCLASSIFIED);
        if (i % 2 == 0) {
            in_builder->AddField("test_a", test_str, nullptr, field_type_t::UNCLASSIFIED);
        }
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {},
            "test_r": {
                "mode": "raw",
                "output_name": "raw_test"
            },
            "test_i": {
                "mode": "interp",
                "output_name": "interp_test"
            },
            "test_d": {
                "output_name": "dyn_test"
            },
            "test_null": {
                "mode": "interp"
            },
            "test_drop": {
                "mode": "drop"
            },
            "test_a": {
                "mode": "raw"
            }
        },
        "max_count": 3,
        "max_size": 8192,
        "max_time": 86400,
        "send_first": false
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };

    agg->Save(tmpFile.Path());

    agg->Load(tmpFile.Path());
    agg->SetRules(rules);

    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    auto ret = agg->HandleEvent(ignore_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);

    auto added = agg->AddEvent(in_allocator->GetEvent(3));
    BOOST_REQUIRE_EQUAL(added, true);

    ret = agg->HandleEvent(diff_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}


BOOST_AUTO_TEST_CASE( basic_time_serial_delta ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(62, 2, 102, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 15);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:01:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:01:02.002Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_serial", "100", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("event_times", R"json(["0","1001","2002"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("serials", R"json(["0","1","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    for (int i = 0; i < 4; ++i) {
        in_builder->BeginEvent(i+60, i, i+100, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 7);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {}
        },
        "time_field_mode": "delta",
        "serial_field_mode": "delta",
        "max_count": 3
    })json";


    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_consume_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_no_consume_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(-1, false);
    };

    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    auto added = agg->AddEvent(in_allocator->GetEvent(3));
    BOOST_REQUIRE_EQUAL(added, true);

    auto ret = agg->HandleEvent(diff_no_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), -1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), false);

    ret = agg->HandleEvent(diff_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}


BOOST_AUTO_TEST_CASE( basic_time_serial_drop ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    auto out_allocator = std::make_shared<BasicEventBuilderAllocator>();
    auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

    out_builder->BeginEvent(62, 2, 102, 1);
    out_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), "AUOMS_AGGREGATE", "", 12);
    out_builder->AddField("original_record_type_code", "14688", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("original_record_type", "AUOMS_EXECVE", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("first_event_time", "1970-01-01T00:01:00.000Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("last_event_time", "1970-01-01T00:01:02.002Z", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("num_aggregated_events", "3", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
    out_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->AddField("user", "1000", "test_user", field_type_t::UID);
    out_builder->AddField("group", "1000", "test_group", field_type_t::GID);
    out_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
    out_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
    out_builder->AddField("pid", R"json(["2","2","2"])json", nullptr, field_type_t::UNCLASSIFIED);
    out_builder->EndRecord();
    if (out_builder->EndEvent() != 1) {
        BOOST_FAIL("EndEvent failed");
    }

    BOOST_CHECK_EQUAL(out_allocator->IsCommited(), true);

    for (int i = 0; i < 4; ++i) {
        in_builder->BeginEvent(i+60, i, i+100, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 7);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("pid", "2", nullptr, field_type_t::UNCLASSIFIED);
        in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
        in_builder->AddField("group", "1000", "test_group", field_type_t::GID);
        in_builder->AddField("exe", "\"/usr/local/bin/testcmd\"", nullptr, field_type_t::ESCAPED);
        in_builder->AddField("cmdline", "testcmd", nullptr, field_type_t::UNESCAPED);
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                {
                    "name": "syscall",
                    "op": "eq",
                    "value": "execve"
                },
                {
                    "name": "cmdline",
                    "op": "eq",
                    "value": "testcmd"
                }
            ]
        },
        "aggregation_fields": {
            "pid": {}
        },
        "time_field_mode": "drop",
        "serial_field_mode": "drop",
        "max_count": 3
    })json";

    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        return std::make_pair(-1, false);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_consume_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(1, true);
    };

    std::function<std::pair<long int, bool>(const Event&)> diff_no_consume_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
        diff_event(0, out_allocator->GetEvent(), event);
        return std::make_pair(-1, false);
    };

    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent(ignore_fn);
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }

    auto added = agg->AddEvent(in_allocator->GetEvent(3));
    BOOST_REQUIRE_EQUAL(added, true);

    auto ret = agg->HandleEvent(diff_no_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), -1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), false);

    ret = agg->HandleEvent(diff_consume_fn);
    BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
    BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
    BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
}

// BOOST_AUTO_TEST_CASE( test_aggregation_with_extended_fields ) {
//     auto in_allocator = std::make_shared<TestEventQueue>();
//     auto prioritizer = DefaultPrioritizer::Create(0);
//     auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

//     auto out_allocator = std::make_shared<TestEventQueue>();
//     auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

//     // Build input event data with extended fields
//     for (int i = 0; i < 5; ++i) {
//         char test_str[16];
//         snprintf(test_str, sizeof(test_str), "test_%d", i);

//         in_builder->BeginEvent(i, 0, i, 1);
//         in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 5 + i);
//         in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
//         in_builder->AddField("pid", std::to_string(100 + i).c_str(), nullptr, field_type_t::UNCLASSIFIED);
//         in_builder->AddField("ppid", "1", nullptr, field_type_t::UNCLASSIFIED);
//         in_builder->AddField("user", "1000", "test_user", field_type_t::UID);
//         in_builder->AddField("cmdline", test_str, nullptr, field_type_t::UNESCAPED);
//         in_builder->AddField("effective_user", "euid", nullptr, field_type_t::UNCLASSIFIED);
//         in_builder->EndRecord();
//         if (in_builder->EndEvent() != 1) {
//             BOOST_FAIL("EndEvent failed");
//         }
//     }

//     // Aggregation rule JSON matching extended fields
//     std::string agg_rule_json = R"json({
//         "match_rule": {
//             "record_types": ["AUOMS_EXECVE"],
//             "field_rules": [
//                 {
//                     "name": "syscall",
//                     "op": "eq",
//                     "value": "execve"
//                 },
//                 {
//                     "name": "cmdline",
//                     "op": "re",
//                     "value": "test_.*"
//                 }
//             ]
//         },
//         "aggregation_fields": {
//             "pid": {},
//             "ppid": {},
//             "user": {},
//             "effective_user": {},
//             "cmdline": {}
//         },
//         "max_count": 3,
//         "max_size": 2048
//     })json";

//     std::vector<std::shared_ptr<AggregationRule>> rules;
//     rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

//     auto agg = std::make_shared<EventAggregator>();
//     agg->SetRules(rules);

//     std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
//         return std::make_pair(-1, false);
//     };

//     // Process the events and check the result
//     for (int i = 0; i < 5; ++i) {
//         auto added = agg->AddEvent(in_allocator->GetEvent(i));
//         BOOST_REQUIRE_EQUAL(added, true);
//         auto ret = agg->HandleEvent(ignore_fn);
//         BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
//     }

//     // After 3 events, it should have aggregated and output the event
//     BOOST_REQUIRE_EQUAL(agg->NumReadyAggregates(), 1);
//     agg->HandleEvent([&](const Event& event) -> std::pair<int64_t, bool> {
//         diff_event(0, out_allocator->GetEvent(), event);
//         return std::make_pair(1, true);
//     });

//     BOOST_REQUIRE_EQUAL(out_allocator->GetEventCount(), 1);
// }

BOOST_AUTO_TEST_CASE( test_large_input_events ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    // Create large events close to the max_size limit
    for (int i = 0; i < 2; ++i) {
        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 10);
        for (int j = 0; j < 10; ++j) {
            in_builder->AddField(("field" + std::to_string(j)).c_str(), "value", nullptr, field_type_t::UNCLASSIFIED);
        }
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    // Aggregation rule with max_size constraint
    std::string agg_rule_json = R"json({
        "match_rule": { "record_types": ["AUOMS_EXECVE"] },
        "aggregation_fields": { "field0": {} },
        "max_size": 512
    })json";

    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    for (int i = 0; i < 2; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
    }

    // Ensure max_size is respected
    BOOST_REQUIRE_EQUAL(agg->NumReadyAggregates(), 1);
}

BOOST_AUTO_TEST_CASE( test_aggregation_with_missing_fields ) {
    auto in_allocator = std::make_shared<TestEventQueue>();
    auto prioritizer = DefaultPrioritizer::Create(0);
    auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

    // Build input events where some fields are missing
    for (int i = 0; i < 3; ++i) {
        in_builder->BeginEvent(i, 0, i, 1);
        in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 3 + i);
        in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
        in_builder->AddField("pid", std::to_string(100 + i).c_str(), nullptr, field_type_t::UNCLASSIFIED);
        in_builder->EndRecord();
        if (in_builder->EndEvent() != 1) {
            BOOST_FAIL("EndEvent failed");
        }
    }

    // Aggregation rule without all fields
    std::string agg_rule_json = R"json({
        "match_rule": {
            "record_types": ["AUOMS_EXECVE"],
            "field_rules": [
                { "name": "syscall", "op": "eq", "value": "execve" }
            ]
        },
        "aggregation_fields": { "pid": {} },
        "max_count": 3
    })json";

    std::vector<std::shared_ptr<AggregationRule>> rules;
    rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));

    auto agg = std::make_shared<EventAggregator>();
    agg->SetRules(rules);

    // Add events and ensure aggregation still works
    for (int i = 0; i < 3; ++i) {
        auto added = agg->AddEvent(in_allocator->GetEvent(i));
        BOOST_REQUIRE_EQUAL(added, true);
        auto ret = agg->HandleEvent([](const Event&) { return std::make_pair(-1, false); });
        BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
    }
}

// BOOST_AUTO_TEST_CASE( test_field_modes_raw_interp_drop ) {
//     // Initialize allocators and builders for input and output events
//     auto in_allocator = std::make_shared<TestEventQueue>();
//     auto prioritizer = DefaultPrioritizer::Create(0);
//     auto in_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(in_allocator), prioritizer);

//     auto out_allocator = std::make_shared<TestEventQueue>();
//     auto out_builder = std::make_shared<EventBuilder>(std::dynamic_pointer_cast<IEventBuilderAllocator>(out_allocator), prioritizer);

//     // Build the input events with various fields
//     for (int i = 0; i < 4; ++i) {
//         in_builder->BeginEvent(i, 0, i, 1);
//         in_builder->BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", 7);
//         in_builder->AddField("syscall", "59", "execve", field_type_t::SYSCALL);
//         in_builder->AddField("pid", std::to_string(100 + i), nullptr, field_type_t::UNCLASSIFIED); // PIDs differ in events
//         in_builder->AddField("user", std::to_string(1000 + i), "user_" + std::to_string(i), field_type_t::UID);
//         in_builder->AddField("cmdline", "cmd_" + std::to_string(i), nullptr, field_type_t::UNESCAPED);
//         in_builder->AddField("group", std::to_string(2000 + i), "group_" + std::to_string(i), field_type_t::GID);
//         in_builder->EndRecord();
//         if (in_builder->EndEvent() != 1) {
//             BOOST_FAIL("EndEvent failed");
//         }
//     }

//     // Define the aggregation rules with field modes
//     std::string agg_rule_json = R"json({
//         "match_rule": {
//             "record_types": ["AUOMS_EXECVE"],
//             "field_rules": [
//                 {
//                     "name": "syscall",
//                     "op": "eq",
//                     "value": "execve"
//                 }
//             ]
//         },
//         "aggregation_fields": {
//             "pid": {
//                 "mode": "raw",
//                 "output_name": "raw_pid"
//             },
//             "user": {
//                 "mode": "interp",
//                 "output_name": "interp_user"
//             },
//             "cmdline": {
//                 "mode": "drop"
//             }
//         },
//         "max_count": 3
//     })json";

//     // Create aggregation rule and assign it to the EventAggregator
//     std::vector<std::shared_ptr<AggregationRule>> rules;
//     rules.emplace_back(AggregationRule::FromJSON(agg_rule_json));
//     auto agg = std::make_shared<EventAggregator>();
//     agg->SetRules(rules);

//     // Define custom handling functions
//     std::function<std::pair<long int, bool>(const Event&)> ignore_fn = [&](const Event& event) -> std::pair<int64_t, bool> {
//         return std::make_pair(-1, false); // Do nothing, just return
//     };

//     std::function<std::pair<long int, bool>(const Event&)> check_aggregated_event = [&](const Event& event) -> std::pair<int64_t, bool> {
//         // Check if aggregated event has the correct fields
//         BOOST_CHECK(event.NumRecords() == 1);
//         auto record = event.RecordAt(0);

//         // Verify aggregation fields are processed correctly
//         auto raw_pid = record.GetFieldByName("raw_pid");
//         BOOST_CHECK(raw_pid != nullptr);
//         BOOST_CHECK(raw_pid->RawValue() == "[\"100\",\"101\",\"102\"]"); // Raw mode for pid

//         auto interp_user = record.GetFieldByName("interp_user");
//         BOOST_CHECK(interp_user != nullptr);
//         BOOST_CHECK(interp_user->InterpValue() == "[\"user_0\",\"user_1\",\"user_2\"]"); // Interp mode for user

//         auto cmdline = record.GetFieldByName("cmdline");
//         BOOST_CHECK(cmdline == nullptr); // Dropped field cmdline

//         return std::make_pair(1, true); // Successfully processed
//     };

//     // Add the first three events and handle them
//     for (int i = 0; i < 3; ++i) {
//         auto added = agg->AddEvent(in_allocator->GetEvent(i));
//         BOOST_REQUIRE_EQUAL(added, true); // Ensure the event was added
//         auto ret = agg->HandleEvent(ignore_fn); // Check if it triggers the aggregation
//         BOOST_REQUIRE_EQUAL(std::get<0>(ret), false);
//     }

//     // Add the fourth event and trigger the aggregation
//     auto added = agg->AddEvent(in_allocator->GetEvent(3));
//     BOOST_REQUIRE_EQUAL(added, true); // Ensure the event was added

//     // Check the aggregated event
//     auto ret = agg->HandleEvent(check_aggregated_event);
//     BOOST_REQUIRE_EQUAL(std::get<0>(ret), true);
//     BOOST_REQUIRE_EQUAL(std::get<1>(ret), 1);
//     BOOST_REQUIRE_EQUAL(std::get<2>(ret), true);
// }