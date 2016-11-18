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

/*
 *  TESTS:
 *      Put
 *      Put Wrap
 *      Put Overwrite, Put Overwrite Wrap
 *          Nothing to overwrite
 *          Overwrite Read but not checkpointed data
 *          Overwrite unread data
 *
 *      Get
 *      Get Wrap
 *      Get Auto checkpoint
 *      Get Auto checkpoint Wrap
 *      Peek
 *      TryGet
 *      TryGet Wrap
 *      TryGet Auto Checkpoint
 *      TryGet Auto Checkpoint Wrap
 *
 */

BOOST_AUTO_TEST_CASE( basic_queue )
{
    TempFile file("/tmp/QueueTests.");

    Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

    queue.Open();

    std::array<char, 1024> data_in;
    data_in.fill('\0');

    for (int i = 0; i < 62; i++) {
        data_in[0] = i;
        auto ret = queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(i), false, 0);
        if (ret != 1) {
            BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
        }
    }

    queue.Save();

    std::array<char, 1024> data_out;

    uint64_t last_id = 0;
    for (int i = 0; i < 32; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
        BOOST_CHECK_EQUAL(data_in.size(), size);
        BOOST_CHECK_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        last_id = ret;
    }

    queue.Save();

    data_in[0] = 1;
    auto put_ret = queue.Put(data_in.data(), data_in.size(), queue_msg_type_t::EVENT, false, 0);
    if (put_ret != 0) {
        BOOST_FAIL("Queue::Put didn't return 0 on full queue. Instead it returned: " + std::to_string(put_ret));
    }

    queue.Checkpoint(last_id);

    for (int i = 62; i < 69; i++) {
        data_in[0] = i;
        if (queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(i), false, 0) != 1) {
            BOOST_FAIL("Queue::Put failed");
        }
    }

    queue.Save();

    for (int i = 32; i < 62; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
        BOOST_CHECK_EQUAL(data_in.size(), size);
        BOOST_CHECK_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        last_id = ret;
    }

    queue.Save();
    queue.Checkpoint(last_id);

    for (int i = 62; i < 69; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
        BOOST_CHECK_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        last_id = ret;
    }

    queue.Checkpoint(last_id);
    queue.Save();

    size_t size = data_out.size();
    queue_msg_type_t msg_type;
    auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
    if (ret != Queue::TIMEOUT) {
        BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
    }

    queue.Save();

    queue.Close();

    size = data_out.size();
    ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
    if (ret != Queue::CLOSED) {
        BOOST_FAIL("Queue::Get didn't return CLOSED");
    }
}

BOOST_AUTO_TEST_CASE( wrap_queue )
{
    TempFile file("/tmp/QueueTests.");

    Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

    queue.Open();

    std::array<char, 1024> data_in;
    data_in.fill('\0');
    std::array<char, 1024> data_out;

    for (int i = 0; i < 1024; i++) {
        if (queue.Put(data_in.data(), data_in.size(), queue_msg_type_t::EVENT, false, 0) != 1) {
            BOOST_FAIL("Queue::Put failed: " + std::to_string(i));
        }
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            if (ret == Queue::CLOSED) {
                return;
            }
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret) + ":" + std::to_string(i));
        }
        queue.Checkpoint(ret);
    }

    queue.Close();
}

BOOST_AUTO_TEST_CASE( allocate_wrap_queue )
{
    TempFile file("/tmp/QueueTests.");

    Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

    queue.Open();

    std::array<char, Queue::MIN_QUEUE_SIZE-1024> data_in;
    data_in.fill('\0');

    uint8_t* data;
    size_t size;
    queue_msg_type_t msg_type;

    if (queue.Put(data_in.data(), data_in.size(), queue_msg_type_t::EVENT, false, 0) != 1) {
        BOOST_FAIL("Queue::Put failed");
    }

    uint64_t id;
    auto ret = queue.ZeroCopyGet(1, false, [&id,&data_in](int64_t msg_id, void* ptr, size_t size, queue_msg_type_t msg_type) -> bool {
        id = msg_id;
        BOOST_CHECK_EQUAL(data_in.size(), size);
        BOOST_CHECK_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(queue_msg_type_t::EVENT));
        return true;
    });
    if (ret < 0) {
        if (ret == Queue::CLOSED) {
            return;
        }
        BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
    }
    queue.Checkpoint(id);

    if (queue.Allocate(reinterpret_cast<void**>(&data), 256, false, 0) != 1) {
        BOOST_FAIL("Queue::Allocate failed");
    }

    data[0] = 3;

    if (queue.Allocate(reinterpret_cast<void**>(&data), 2*1024, false, 0) != 1) {
        BOOST_FAIL("Queue::Allocate failed");
    }

    BOOST_CHECK_EQUAL(data[0], 3);

    if (queue.Commit(queue_msg_type_t::EVENT) != 1) {
        BOOST_FAIL("Queue::Commit failed");
    }

    queue.Close();
}

BOOST_AUTO_TEST_CASE( concurrent_queue )
{
    TempFile file("/tmp/QueueTests.");

    Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

    queue.Open();

    std::thread getter([&]() {
        std::array<char, 2048> data_out;
        for (int i = 0; i < 1024; i++) {
            size_t size = data_out.size();
            queue_msg_type_t msg_type;
            auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1000);
            if (ret <= 0) {
                throw std::runtime_error("Unexpected return from Queue::Get: " + std::to_string(ret) + ": " + std::to_string(i));
            }
            queue.Checkpoint(ret);
        }
        return;
    });

    std::array<char, 1024> data_in;
    data_in.fill('\0');

    for (int i = 0; i < 1024; i++) {
        auto ret = queue.Put(data_in.data(), data_in.size(), queue_msg_type_t::EVENT, false, -1);
        if (ret != 1) {
            BOOST_FAIL("Queue::Put failed: ret = " + std::to_string(ret) + ": " + std::to_string(i));
        }
    }

    getter.join();
    queue.Close();
}

BOOST_AUTO_TEST_CASE( reopen_queue )
{
    TempFile file("/tmp/QueueTests.");

    Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

    queue.Open();

    std::array<char, 1024> data_in;
    data_in.fill('\0');
    std::array<char, 1024> data_out;

    for (int i = 0; i < 32; i++) {
        data_in[0] = i;
        if (queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(i), false, 0) != 1) {
            BOOST_FAIL("Queue::Put failed: " + std::to_string(i));
        }
    }

    for (int i = 0; i < 24; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret) + ":" + std::to_string(i));
        }
        BOOST_REQUIRE_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        if (i < 16) {
            queue.Checkpoint(ret);
        }
    }

    queue.Close();

    queue.Open();

    for (int i = 16; i < 32; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret) + ":" + std::to_string(i));
        }
        BOOST_REQUIRE_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        queue.Checkpoint(ret);
    }

    size_t size = data_out.size();
    queue_msg_type_t msg_type;
    auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
    if (ret != 0) {
        BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
    }

    queue.Close();
}

BOOST_AUTO_TEST_CASE( resize_queue_larger )
{
    TempFile file("/tmp/QueueTests.");

    std::array<char, 1024> data_in;
    data_in.fill('\0');
    std::array<char, 1024> data_out;

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

        queue.Open();


        for (int i = 0; i < 32; i++) {
            data_in[0] = i;
            if (queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(i), false, 0) != 1) {
                BOOST_FAIL("Queue::Put failed: " + std::to_string(i));
            }
        }

        for (int i = 0; i < 24; i++) {
            size_t size = data_out.size();
            queue_msg_type_t msg_type;
            auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret) + ":" + std::to_string(i));
            }
            BOOST_REQUIRE_EQUAL(data_out[0], i);
            BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
            if (i < 16) {
                queue.Checkpoint(ret);
            }
        }

        queue.Close();
    }

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE*2);
        queue.Open();

        for (int i = 16; i < 32; i++) {
            size_t size = data_out.size();
            queue_msg_type_t msg_type;
            auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret) + ":" + std::to_string(i));
            }
            BOOST_REQUIRE_EQUAL(data_out[0], i);
            BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
            queue.Checkpoint(ret);
        }

        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret != 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }

        queue.Close();
    }
}

BOOST_AUTO_TEST_CASE( resize_queue_smaller )
{
    TempFile file("/tmp/QueueTests.");

    std::array<char, 1024> data_in;
    data_in.fill('\0');
    std::array<char, 1024> data_out;

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE*2);

        queue.Open();


        for (int i = 0; i < 120; i++) {
            data_in[0] = i;
            if (queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(i), false, 0) != 1) {
                BOOST_FAIL("Queue::Put failed: " + std::to_string(i));
            }
        }

        for (int i = 0; i < 100; i++) {
            size_t size = data_out.size();
            queue_msg_type_t msg_type;
            auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret) + ":" + std::to_string(i));
            }
            BOOST_REQUIRE_EQUAL(data_out[0], i);
            BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
            if (i < 62) {
                queue.Checkpoint(ret);
            }
        }

        queue.Close();
    }

    {
        Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);
        queue.Open();

        for (int i = 62; i < 120; i++) {
            size_t size = data_out.size();
            queue_msg_type_t msg_type;
            auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
            if (ret < 0) {
                BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret) + ":" + std::to_string(i));
            }
            BOOST_REQUIRE_EQUAL(data_out[0], i);
            BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
            queue.Checkpoint(ret);
        }

        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret != 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }

        queue.Close();
    }
}

BOOST_AUTO_TEST_CASE( overwrite_queue )
{
    TempFile file("/tmp/QueueTests.");

    Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

    queue.Open();

    std::array<char, 1024> data_in;
    data_in.fill('\0');

    std::array<char, 8192> data_in2;
    data_in.fill('\0');

    for (int i = 0; i < 62; i++) {
        data_in[0] = i;
        auto ret = queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(i), true, 0);
        if (ret != 1) {
            BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
        }
    }

    queue.Save();

    std::array<char, 8192> data_out;

    uint64_t last_id = 0;
    for (int i = 0; i < 32; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
        BOOST_CHECK_EQUAL(data_in.size(), size);
        BOOST_CHECK_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        last_id = ret;
    }

    queue.Save();

    data_in2[0] = 62;
    auto put_ret = queue.Put(data_in2.data(), data_in2.size(), static_cast<queue_msg_type_t>(62), true, 0);
    if (put_ret != 1) {
        BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(put_ret));
    }

    queue.Checkpoint(last_id);

    for (int i = 32; i < 62; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
        BOOST_CHECK_EQUAL(data_in.size(), size);
        BOOST_CHECK_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        last_id = ret;
    }

    queue.Save();

    for (int i = 63; i < 69; i++) {
        data_in[0] = i;
        if (queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(i), false, 0) != 1) {
            BOOST_FAIL("Queue::Put failed");
        }
    }

    queue.Checkpoint(last_id);

    for (int i = 62; i < 69; i++) {
        size_t size = data_out.size();
        queue_msg_type_t msg_type;
        auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
        if (ret < 0) {
            BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
        }
        BOOST_CHECK_EQUAL(data_out[0], i);
        BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(i));
        last_id = ret;
    }

    queue.Checkpoint(last_id);
    queue.Save();

    size_t size = data_out.size();
    queue_msg_type_t msg_type;
    auto ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
    if (ret != Queue::TIMEOUT) {
        BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(ret));
    }

    queue.Save();

    queue.Close();

    size = data_out.size();
    ret = queue.Get(data_out.data(), &size, &msg_type, false, 1);
    if (ret != Queue::CLOSED) {
        BOOST_FAIL("Queue::Get didn't return CLOSED");
    }
}

BOOST_AUTO_TEST_CASE( peek_tryget_queue )
{
    TempFile file("/tmp/QueueTests.");

    Queue queue(file.Path(), Queue::MIN_QUEUE_SIZE);

    queue.Open();

    std::array<char, 1024> data_in;
    std::array<char, 1024> data_out;
    data_in.fill('\0');

    data_in[0] = 1;
    auto ret = queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(1), true, 0);
    if (ret != 1) {
        BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
    }

    data_in[0] = 2;
    ret = queue.Put(data_in.data(), data_in.size(), static_cast<queue_msg_type_t>(2), true, 0);
    if (ret != 1) {
        BOOST_FAIL("Queue::Put didn't return 1. Instead it returned: " + std::to_string(ret));
    }

    size_t peek_size;
    queue_msg_type_t peek_msg_type;
    auto peek_id = queue.Peek(&peek_size, &peek_msg_type, 1);
    if (peek_id <= 0) {
        BOOST_FAIL("Unexpected Queue::Peek return value: " + std::to_string(peek_id));
    }
    BOOST_CHECK_EQUAL(peek_size, data_in.size());
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(peek_msg_type), static_cast<uint64_t>(1));

    size_t size = data_out.size();
    queue_msg_type_t msg_type;
    auto id = queue.Get(data_out.data(), &size, &msg_type, true, 1);
    if (id <= 0) {
        BOOST_FAIL("Unexpected Queue::Get return value: " + std::to_string(peek_id));
    }
    BOOST_CHECK_EQUAL(data_out[0], 1);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(msg_type), static_cast<uint64_t>(1));

    ret = queue.TryGet(peek_id, data_out.data(), peek_size, true);
    if (ret != 0) {
        BOOST_FAIL("Queue::TryGet didn't return 0. Instead it returned: " + std::to_string(ret));
    }

    peek_id = queue.Peek(&peek_size, &peek_msg_type, 1);
    if (peek_id <= 0) {
        BOOST_FAIL("Unexpected Queue::Peek return value: " + std::to_string(peek_id));
    }
    BOOST_CHECK_EQUAL(peek_size, data_in.size());
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(peek_msg_type), static_cast<uint64_t>(2));

    ret = queue.TryGet(peek_id, data_out.data(), peek_size, true);
    if (ret != 1) {
        BOOST_FAIL("Queue::TryGet didn't return 1. Instead it returned: " + std::to_string(ret));
    }
    BOOST_CHECK_EQUAL(data_out[0], 2);
}
