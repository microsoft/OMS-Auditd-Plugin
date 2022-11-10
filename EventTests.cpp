/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "Event.h"
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "EventTests"
#include <boost/test/unit_test.hpp>

#include "PriorityQueue.h"
#include "EventQueue.h"
#include "TempDir.h"



BOOST_AUTO_TEST_CASE( test )
{
    TempDir dir("/tmp/EventTests.");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 16*1024,8, 0, 100, 0);
    auto event_queue = std::make_shared<EventQueue>(queue);

    auto cursor_handle = queue->OpenCursor("event_test");

    EventBuilder builder(event_queue, DefaultPrioritizer::Create(0));

    bool ret = builder.BeginEvent(1, 3, 4, 2);
    if (!ret) {
        BOOST_FAIL("BeginEvent failed: " + std::to_string(ret));
    }
    ret = builder.BeginRecord(1, "test1", "raw record text1", 3);
    if (!ret) {
        BOOST_FAIL("BeginRecord failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field1", "raw1", "interp1", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field2", "2", "user2", field_type_t::UID);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field3", "raw3", "interp3", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.EndRecord();
    if (!ret) {
        BOOST_FAIL("EndRecord failed: " + std::to_string(ret));
    }
    ret = builder.BeginRecord(2, "test2", "raw record text2", 2);
    if (!ret) {
        BOOST_FAIL("BeginRecord failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field1", "raw1", nullptr, field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field2", "raw2", "interp2", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.EndRecord();
    if (!ret) {
        BOOST_FAIL("EndRecord failed: " + std::to_string(ret));
    }
    builder.AddEventFlags(5);
    builder.SetEventPid(12);
    ret = builder.EndEvent();
    if (ret != 1) {
        BOOST_FAIL("EndEvent failed: " + std::to_string(ret));
    }

    auto rval = queue->Get(cursor_handle, 0);
    if (!rval.first) {
        BOOST_FAIL("Queue didn't have any data in it!");
    }

    Event event(rval.first->Data(), rval.first->Size());

    BOOST_CHECK_EQUAL(event.Seconds(), 1);
    BOOST_CHECK_EQUAL(event.Milliseconds(), 3);
    BOOST_CHECK_EQUAL(event.Serial(), 4);
    BOOST_CHECK_EQUAL(event.NumRecords(), 2);
    BOOST_CHECK_EQUAL(event.Flags(), 5);
    BOOST_CHECK_EQUAL(event.Pid(), 12);

    auto rec = event.begin();
    BOOST_CHECK_EQUAL(rec.RecordType(), 1);
    BOOST_CHECK_EQUAL(rec.RecordTypeName(), "test1");
    BOOST_CHECK_EQUAL(rec.RecordTypeNameSize(), strlen("test1"));
    BOOST_CHECK_EQUAL(rec.RecordText(), "raw record text1");
    BOOST_CHECK_EQUAL(rec.RecordTextSize(), strlen("raw record text1"));
    BOOST_CHECK_EQUAL(rec.NumFields(), 3);

    BOOST_CHECK_EQUAL(rec, event.RecordAt(0));

    auto field = rec.begin();
    BOOST_CHECK_EQUAL(field.FieldName(), "field1");
    BOOST_CHECK_EQUAL(field.FieldNameSize(), strlen("field1"));
    BOOST_CHECK_EQUAL(field.RawValue(), "raw1");
    BOOST_CHECK_EQUAL(field.RawValueSize(), strlen("raw1"));
    BOOST_CHECK_EQUAL(field.InterpValue(), "interp1");
    BOOST_CHECK_EQUAL(field.InterpValueSize(), strlen("interp1"));
    BOOST_CHECK_EQUAL(static_cast<uint16_t>(field.FieldType()), static_cast<uint16_t>(field_type_t::UNCLASSIFIED));

    BOOST_CHECK_EQUAL(field, rec.FieldAt(0));

    field += 1;
    BOOST_CHECK_EQUAL(field.FieldName(), "field2");
    BOOST_CHECK_EQUAL(field.FieldNameSize(), strlen("field2"));
    BOOST_CHECK_EQUAL(field.RawValue(), "2");
    BOOST_CHECK_EQUAL(field.RawValueSize(), strlen("2"));
    BOOST_CHECK_EQUAL(field.InterpValue(), "user2");
    BOOST_CHECK_EQUAL(field.InterpValueSize(), strlen("user2"));
    BOOST_CHECK_EQUAL(static_cast<uint16_t>(field.FieldType()), static_cast<uint16_t>(field_type_t::UID));

    BOOST_CHECK_EQUAL(field, rec.FieldAt(1));

    field += 1;
    BOOST_CHECK_EQUAL(field.FieldName(), "field3");
    BOOST_CHECK_EQUAL(field.FieldNameSize(), strlen("field3"));
    BOOST_CHECK_EQUAL(field.RawValue(), "raw3");
    BOOST_CHECK_EQUAL(field.RawValueSize(), strlen("raw3"));
    BOOST_CHECK_EQUAL(field.InterpValue(), "interp3");
    BOOST_CHECK_EQUAL(field.InterpValueSize(), strlen("interp3"));
    BOOST_CHECK_EQUAL(static_cast<uint16_t>(field.FieldType()), static_cast<uint16_t>(field_type_t::UNCLASSIFIED));

    BOOST_CHECK_EQUAL(field, rec.FieldAt(2));

    field += 1;
    BOOST_CHECK_EQUAL(field, rec.end());

    rec += 1;
    BOOST_CHECK_EQUAL(rec.RecordType(), 2);
    BOOST_CHECK_EQUAL(rec.RecordTypeName(), "test2");
    BOOST_CHECK_EQUAL(rec.RecordTypeNameSize(), strlen("test2"));
    BOOST_CHECK_EQUAL(rec.RecordText(), "raw record text2");
    BOOST_CHECK_EQUAL(rec.RecordTextSize(), strlen("raw record text2"));
    BOOST_CHECK_EQUAL(rec.NumFields(), 2);

    BOOST_CHECK_EQUAL(rec, event.RecordAt(1));

    field = rec.begin();
    BOOST_CHECK_EQUAL(field.FieldName(), "field1");
    BOOST_CHECK_EQUAL(field.FieldNameSize(), strlen("field1"));
    BOOST_CHECK_EQUAL(field.RawValue(), "raw1");
    BOOST_CHECK_EQUAL(field.RawValueSize(), strlen("raw1"));
    BOOST_CHECK_EQUAL(reinterpret_cast<int64_t>(field.InterpValuePtr()), 0);
    BOOST_CHECK_EQUAL(field.InterpValueSize(), 0);
    BOOST_CHECK_EQUAL(static_cast<uint16_t>(field.FieldType()), static_cast<uint16_t>(field_type_t::UNCLASSIFIED));

    BOOST_CHECK_EQUAL(field, rec.FieldAt(0));

    field += 1;
    BOOST_CHECK_EQUAL(field.FieldName(), "field2");
    BOOST_CHECK_EQUAL(field.FieldNameSize(), strlen("field2"));
    BOOST_CHECK_EQUAL(field.RawValue(), "raw2");
    BOOST_CHECK_EQUAL(field.RawValueSize(), strlen("raw2"));
    BOOST_CHECK_EQUAL(field.InterpValue(), "interp2");
    BOOST_CHECK_EQUAL(field.InterpValueSize(), strlen("interp2"));

    BOOST_CHECK_EQUAL(field, rec.FieldAt(1));

    field += 1;
    BOOST_CHECK_EQUAL(field, rec.end());

    rec += 1;
    BOOST_CHECK_EQUAL(rec, event.end());

    ret = builder.BeginEvent(1, 3, 4, 1);
    if (!ret) {
        BOOST_FAIL("BeginEvent failed: " + std::to_string(ret));
    }
    ret = builder.BeginRecord(1, "test1", "raw text", 6);
    if (!ret) {
        BOOST_FAIL("BeginRecord failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field3", "raw3", "interp3", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field6", "raw6", "interp6", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field1", "raw1", "interp1", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field4", "raw4", "interp4", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field5", "raw5", "interp5", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.AddField("field2", "raw2", "interp2", field_type_t::UNCLASSIFIED);
    if (!ret) {
        BOOST_FAIL("AddField failed: " + std::to_string(ret));
    }
    ret = builder.EndRecord();
    if (!ret) {
        BOOST_FAIL("EndRecord failed: " + std::to_string(ret));
    }
    ret = builder.EndEvent();
    if (ret != 1) {
        BOOST_FAIL("EndEvent failed: " + std::to_string(ret));
    }

    rval = queue->Get(cursor_handle, 0);
    if (!rval.first) {
        BOOST_FAIL("Queue didn't have any data in it!");
    }

    event = Event(rval.first->Data(), rval.first->Size());

    BOOST_CHECK_EQUAL(event.Pid(), -1);

    rec = event.RecordAt(0);

    BOOST_CHECK_EQUAL(rec.FieldAt(0), rec.FieldByName("field3"));
    BOOST_CHECK_EQUAL(rec.FieldAt(1), rec.FieldByName("field6"));
    BOOST_CHECK_EQUAL(rec.FieldAt(2), rec.FieldByName("field1"));
    BOOST_CHECK_EQUAL(rec.FieldAt(3), rec.FieldByName("field4"));
    BOOST_CHECK_EQUAL(rec.FieldAt(4), rec.FieldByName("field5"));
    BOOST_CHECK_EQUAL(rec.FieldAt(5), rec.FieldByName("field2"));


    int x = 0;
    for (auto field : rec) {
        BOOST_CHECK_EQUAL(rec.FieldAt(x), field);
        x++;
    }
    BOOST_CHECK_EQUAL(x, rec.NumFields());
}
