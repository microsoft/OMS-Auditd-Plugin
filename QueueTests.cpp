/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include "Queue.h"
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "QueueTests"
#include <boost/test/unit_test.hpp>

#include "TempFile.h"
#include <stdexcept>
#include <array>
#include <iostream>
#include <thread>
#include <atomic>

#define FILE_HEADER_SIZE 512
#define ITEM_HEADER_SIZE 3*sizeof(uint64_t)

BOOST_AUTO_TEST_CASE( queue_empty_reopen ) {
    TempFile file("/tmp/QueueTests.");

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

        queue.Open();
    }
    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

        queue.Open();
    }
}

BOOST_AUTO_TEST_CASE( queue_put_empty ) {
    TempFile file("/tmp/QueueTests.");

    int maxItemBeforeWrap = ((Queue::MIN_QUEUE_SIZE-FILE_HEADER_SIZE-ITEM_HEADER_SIZE) / (ITEM_HEADER_SIZE+1024));

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

        queue.Open();

        std::array<char, 1024> data_in;
        data_in.fill('\0');

        int item_id_in = 0;
        int item_id_out = 0;

        for (int i = 0; i < maxItemBeforeWrap; i++, item_id_in++) {
            data_in[0] = static_cast<char>(item_id_in);
            auto ret = queue.Put(data_in.data(), data_in.size());
            if (ret != 1) {
                BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
            }
        }

        queue.Save();

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;

        for (int i = 0; i < maxItemBeforeWrap; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }

        queue.Close(false);
    }

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);
        queue.Open();

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;
        int item_id_out = 0;
        for (int i = 0; i < maxItemBeforeWrap; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }
    }
}

BOOST_AUTO_TEST_CASE( queue_put_wrap ) {
    TempFile file("/tmp/QueueTests.");

    int maxItemBeforeWrap = ((Queue::MIN_QUEUE_SIZE-FILE_HEADER_SIZE-ITEM_HEADER_SIZE) / (ITEM_HEADER_SIZE+1024));
    int itemsAfterWrap = maxItemBeforeWrap-1; // One item gets deleted to make room for the Head marker.

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

        queue.Open();

        std::array<char, 1024> data_in;
        data_in.fill('\0');

        int item_id_in = 0;

        // This should overwrite 2 items from the tail
        for (int i = 0; i < maxItemBeforeWrap+2; i++, item_id_in++) {
            data_in[0] = static_cast<char>(item_id_in);
            auto ret = queue.Put(data_in.data(), data_in.size());
            if (ret != 1) {
                BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
            }
        }

        queue.Save();

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;
        int item_id_out = 3; // The first 3 items where overwritten

        for (int i = 0; i < itemsAfterWrap; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }

        queue.Close(false);
    }

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);
        queue.Open();

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;
        int item_id_out = 3; // The first 3 items where overwritten
        for (int i = 0; i < itemsAfterWrap; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }
    }
}

BOOST_AUTO_TEST_CASE( queue_close_before_commit ) {
    TempFile file("/tmp/QueueTests.");

    int maxItemBeforeWrap = ((Queue::MIN_QUEUE_SIZE-FILE_HEADER_SIZE-ITEM_HEADER_SIZE) / (ITEM_HEADER_SIZE+1024));

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

        queue.Open();

        std::array<char, 1024> data_in;
        data_in.fill('\0');

        int item_id_in = 0;
        int item_id_out = 0;

        for (int i = 0; i < maxItemBeforeWrap-1; i++, item_id_in++) {
            data_in[0] = static_cast<char>(item_id_in);
            auto ret = queue.Put(data_in.data(), data_in.size());
            if (ret != 1) {
                BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
            }
        }

        void *ptr;
        auto ret = queue.Allocate(&ptr, 1024);
        if (ret != 1) {
            BOOST_FAIL("Queue::Allocate didn't return 1. Instead it returned: " + std::to_string(ret));
        }

        queue.Save();

        data_in[0] = static_cast<char>(item_id_in);
        item_id_in++;
        memcpy(ptr, data_in.data(), 1024);

        ret = queue.Commit();
        if (ret != 1) {
            BOOST_FAIL("Queue::Commit didn't return 1. Instead it returned: " + std::to_string(ret));
        }

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;

        for (int i = 0; i < maxItemBeforeWrap-1; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }

        queue.Close(false);
    }

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);
        queue.Open();

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;
        int item_id_out = 0;
        for (int i = 0; i < maxItemBeforeWrap-1; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }

        size_t size = data_out.size();
        auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
        if (ret != 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
    }
}

BOOST_AUTO_TEST_CASE( queue_close_before_commit_wrap ) {
    TempFile file("/tmp/QueueTests.");

    int maxItemBeforeWrap = ((Queue::MIN_QUEUE_SIZE-FILE_HEADER_SIZE-ITEM_HEADER_SIZE) / (ITEM_HEADER_SIZE+1024));

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

        queue.Open();

        std::array<char, 1024> data_in;
        data_in.fill('\0');

        int item_id_in = 0;

        for (int i = 0; i < maxItemBeforeWrap-1; i++, item_id_in++) {
            data_in[0] = static_cast<char>(item_id_in);
            auto ret = queue.Put(data_in.data(), data_in.size());
            if (ret != 1) {
                BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
            }
        }

        void *ptr;
        auto ret = queue.Allocate(&ptr, 1024);
        if (ret != 1) {
            BOOST_FAIL("Queue::Allocate didn't return 1. Instead it returned: " + std::to_string(ret));
        }
        static_cast<char*>(ptr)[0] = static_cast<char>(item_id_in);

        for (int i = 1; i <= 1024; i++) {
            auto ret = queue.Allocate(&ptr, 1024+i);
            if (ret != 1) {
                BOOST_FAIL("Queue::Allocate didn't return 1. Instead it returned: " + std::to_string(ret));
            }
        }

        BOOST_REQUIRE_EQUAL(static_cast<uint8_t*>(ptr)[0], static_cast<uint8_t>(item_id_in));

        queue.Save();

        item_id_in++;

        ret = queue.Commit();
        if (ret != 1) {
            BOOST_FAIL("Queue::Commit didn't return 1. Instead it returned: " + std::to_string(ret));
        }

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;
        int item_id_out = 3;
        for (int i = 0; i < maxItemBeforeWrap-4; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }

        std::array<char, 2048> data_out2;
        size_t size = data_out2.size();
        ret = queue.Get(cursor, data_out2.data(), &size, &cursor, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
        BOOST_REQUIRE_EQUAL(data_out2.size(), size);
        BOOST_REQUIRE_EQUAL(data_out2[0], item_id_out);

        queue.Close(false);
    }

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);
        queue.Open();

        std::array<char, 1024> data_out;
        QueueCursor cursor = QueueCursor::TAIL;
        int item_id_out = 3;
        for (int i = 0; i < maxItemBeforeWrap-4; i++, item_id_out++) {
            size_t size = data_out.size();
            auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
            }
            BOOST_REQUIRE_EQUAL(data_out.size(), size);
            BOOST_REQUIRE_EQUAL(data_out[0], item_id_out);
        }

        size_t size = data_out.size();
        auto ret = queue.Get(cursor, data_out.data(), &size, &cursor, 1);
        if (ret != 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
    }
}
