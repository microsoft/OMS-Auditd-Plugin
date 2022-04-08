/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "FluentEventWriter.h"
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "FluentEventWriterTests"
#include <boost/test/unit_test.hpp>

#include "Queue.h"
#include "TestEventData.h"
#include <msgpack.hpp>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include "TestEventWriter.h"

#define INITIAL_BUFFER_CAPACITY 8192

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
    config.HostnameValue = TestConfigHostnameValue;
    config.IncludeRecordTextField = true;

    FluentEventWriter fluent_writer(config, "LINUX_AUDITD_BLOB");

    for (size_t i = 0; i < queue->GetEventCount(); ++i) {
        fluent_writer.WriteEvent(queue->GetEvent(i), &writer);
    }

    std::string _buf;
    std::vector<std::string> jsonEvents;

    for (int i = 0; i < writer.GetEventCount(); ++i) {
        msgpack::unpacker unp;
        msgpack::object_handle result; 
        unp.reserve_buffer(INITIAL_BUFFER_CAPACITY);
        std::string event = writer.GetEvent(i);
        size_t size = event.copy(unp.buffer(), event.length());
        unp.buffer_consumed(size);
                
        rapidjson::StringBuffer buffer(0, 1024*1024);
        rapidjson::Writer<rapidjson::StringBuffer> jsonWriter(buffer);
        buffer.Clear();
        jsonWriter.Reset(buffer);
        jsonWriter.StartArray();

        while(unp.next(result))
        {
            msgpack::object events(result.get());
            if (events.type != msgpack::type::object_type::ARRAY)
            {
                BOOST_FAIL("Top level object is not an array");
            }

            if (events.via.array.size != 2)
            {
                BOOST_FAIL("Top level array should have only 2 elements");
            }

            if (events.via.array.ptr[0].type != msgpack::type::object_type::STR)
            {
                BOOST_FAIL("Expecting first object of top level array to be string.");
            }
            jsonWriter.String(events.via.array.ptr[0].via.str.ptr, events.via.array.ptr[0].via.str.size, true);

            msgpack::object arrayObject = events.via.array.ptr[1];
            
            if (arrayObject.type != msgpack::type::object_type::ARRAY)
            {
                BOOST_FAIL("First level object is not array");
            }

            if (arrayObject.via.array.size < 1)
            {
                BOOST_FAIL("First level array size is less than 1");
            }

            jsonWriter.StartArray();
            msgpack::object innerObj_2 = arrayObject.via.array.ptr[0];
            if (innerObj_2.type != msgpack::type::object_type::ARRAY)
            {
                BOOST_FAIL("Second level object is not array");
            }

            if (innerObj_2.via.array.size != 2)
            {
                BOOST_FAIL("Second level array size is not 2");
            }

            msgpack::object innerObj_3_0 = innerObj_2.via.array.ptr[0];
            msgpack::object innerObj_3_1 = innerObj_2.via.array.ptr[1];

            if (innerObj_3_0.type != msgpack::type::object_type::POSITIVE_INTEGER)
            {
                BOOST_FAIL("Inner object is not a date time");
            }
            jsonWriter.String("TIMESTAMP");
            
            if (innerObj_3_1.type != msgpack::type::object_type::MAP)
            {
                BOOST_FAIL("Inner object is not a map");
            }

            jsonWriter.StartObject();
            msgpack::object_map & map = innerObj_3_1.via.map;
            std::map<std::string, std::string> stdmap;
            for (unsigned long i = 0; i < map.size; i++)
            {
                msgpack::object_kv & kv = map.ptr[i];
                if ((kv.key.type == msgpack::type::object_type::STR) &&
                    (kv.val.type == msgpack::type::object_type::STR))
                {
                    stdmap[std::string(kv.key.via.str.ptr, kv.key.via.str.size)] = std::string(kv.val.via.str.ptr, kv.val.via.str.size);
                }
            }
            for (auto itr = stdmap.begin(); itr != stdmap.end(); ++itr) {
                jsonWriter.Key(itr->first.c_str());
                jsonWriter.String(itr->second.c_str());
            }
            jsonWriter.EndObject();
            jsonWriter.EndArray();
        }

        jsonWriter.EndArray();
        _buf.assign(reinterpret_cast<const char*>(buffer.GetString()), buffer.GetSize());
        jsonEvents.emplace_back(_buf);
    }

    BOOST_REQUIRE_EQUAL(jsonEvents.size(), fluent_test_events.size());

    for (int i = 0; i < fluent_test_events.size(); ++i) {
        BOOST_REQUIRE_EQUAL(jsonEvents[i], fluent_test_events[i]);
    }
    
}


BOOST_AUTO_TEST_CASE( other_fields_test ) {
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
    config.FilterFieldNameSet = TestConfigInclusiveFieldNameSet;
    config.AlwaysFilterFieldNameSet = TestConfigFilterFieldNameSet;
    config.AdditionalFieldsMap = TestConfigAdditionalFieldsMap;
    config.HostnameValue = TestConfigHostnameValue;
    config.FieldFilterInclusiveMode = true;
    config.OtherFieldsMode = true;

    FluentEventWriter fluent_writer(config, "LINUX_AUDITD_BLOB");

    for (size_t i = 0; i < queue->GetEventCount(); ++i) {
        fluent_writer.WriteEvent(queue->GetEvent(i), &writer);
    }

    std::string _buf;
    std::vector<std::string> jsonEvents;

    for (int i = 0; i < writer.GetEventCount(); ++i) {
        msgpack::unpacker unp;
        msgpack::object_handle result;
        unp.reserve_buffer(INITIAL_BUFFER_CAPACITY);
        std::string event = writer.GetEvent(i);
        size_t size = event.copy(unp.buffer(), event.length());
        unp.buffer_consumed(size);

        rapidjson::StringBuffer buffer(0, 1024*1024);
        rapidjson::Writer<rapidjson::StringBuffer> jsonWriter(buffer);
        buffer.Clear();
        jsonWriter.Reset(buffer);
        jsonWriter.StartArray();

        while(unp.next(result))
        {
            msgpack::object events(result.get());
            if (events.type != msgpack::type::object_type::ARRAY)
            {
                BOOST_FAIL("Top level object is not an array");
            }

            if (events.via.array.size != 2)
            {
                BOOST_FAIL("Top level array should have only 2 elements");
            }

            if (events.via.array.ptr[0].type != msgpack::type::object_type::STR)
            {
                BOOST_FAIL("Expecting first object of top level array to be string.");
            }
            jsonWriter.String(events.via.array.ptr[0].via.str.ptr, events.via.array.ptr[0].via.str.size, true);

            msgpack::object arrayObject = events.via.array.ptr[1];

            if (arrayObject.type != msgpack::type::object_type::ARRAY)
            {
                BOOST_FAIL("First level object is not array");
            }

            if (arrayObject.via.array.size < 1)
            {
                BOOST_FAIL("First level array size is less than 1");
            }

            jsonWriter.StartArray();
            msgpack::object innerObj_2 = arrayObject.via.array.ptr[0];
            if (innerObj_2.type != msgpack::type::object_type::ARRAY)
            {
                BOOST_FAIL("Second level object is not array");
            }

            if (innerObj_2.via.array.size != 2)
            {
                BOOST_FAIL("Second level array size is not 2");
            }

            msgpack::object innerObj_3_0 = innerObj_2.via.array.ptr[0];
            msgpack::object innerObj_3_1 = innerObj_2.via.array.ptr[1];

            if (innerObj_3_0.type != msgpack::type::object_type::POSITIVE_INTEGER)
            {
                BOOST_FAIL("Inner object is not a date time");
            }
            jsonWriter.String("TIMESTAMP");

            if (innerObj_3_1.type != msgpack::type::object_type::MAP)
            {
                BOOST_FAIL("Inner object is not a map");
            }

            jsonWriter.StartObject();
            msgpack::object_map & map = innerObj_3_1.via.map;
            std::map<std::string, std::string> stdmap;
            for (unsigned long i = 0; i < map.size; i++)
            {
                msgpack::object_kv & kv = map.ptr[i];
                if ((kv.key.type == msgpack::type::object_type::STR) &&
                (kv.val.type == msgpack::type::object_type::STR))
                {
                    stdmap[std::string(kv.key.via.str.ptr, kv.key.via.str.size)] = std::string(kv.val.via.str.ptr, kv.val.via.str.size);
                }
            }
            for (auto itr = stdmap.begin(); itr != stdmap.end(); ++itr) {
                jsonWriter.Key(itr->first.c_str());
                jsonWriter.String(itr->second.c_str());
            }
            jsonWriter.EndObject();
            jsonWriter.EndArray();
        }

        jsonWriter.EndArray();
        _buf.assign(reinterpret_cast<const char*>(buffer.GetString()), buffer.GetSize());
        jsonEvents.emplace_back(_buf);
    }

    BOOST_REQUIRE_EQUAL(jsonEvents.size(), fluent_other_field_test_events.size());

    for (int i = 0; i < fluent_other_field_test_events.size(); ++i) {
        BOOST_REQUIRE_EQUAL(jsonEvents[i], fluent_other_field_test_events[i]);
    }

}
