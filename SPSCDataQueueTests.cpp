/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "SPSCDataQueue.h"
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "SPSCDataQueueTests"
#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <array>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>

BOOST_AUTO_TEST_CASE( queue_basic ) {
    SPSCDataQueue queue(1024, 4);

    std::array<uint8_t, 256> data;
    data.fill(0);
    for (int i = 0; i < 200; ++i) {
        data[0] = static_cast<uint8_t>(i);
        auto in_ptr = queue.Allocate(data.size());
        BOOST_REQUIRE(in_ptr != nullptr);
        ::memcpy(in_ptr, data.data(), data.size());
        queue.Commit(data.size());

        uint8_t* out_ptr;
        auto ret = queue.Get(&out_ptr);
        BOOST_REQUIRE_EQUAL(ret, data.size());
        BOOST_REQUIRE_EQUAL(out_ptr[0], static_cast<uint8_t>(i));
        queue.Release();
    }
}

BOOST_AUTO_TEST_CASE( queue_concurrent ) {
    SPSCDataQueue queue(1024, 4);

    std::array<uint8_t, 256> data;
    data.fill(0);

    std::thread _thread([&queue,&data](){
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        for (int i = 0; i < 200; ++i) {
            data[0] = static_cast<uint8_t>(i);
            auto in_ptr = queue.Allocate(data.size());
            BOOST_REQUIRE(in_ptr != nullptr);
            ::memcpy(in_ptr, data.data(), data.size());
            queue.Commit(data.size());
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    for (int i = 0; i < 200; ++i) {
        uint8_t* out_ptr;
        auto ret = queue.Get(&out_ptr);
        BOOST_REQUIRE_EQUAL(ret, data.size());
        BOOST_REQUIRE_EQUAL(out_ptr[0], static_cast<uint8_t>(i));
        queue.Release();
    }
    _thread.join();
}

BOOST_AUTO_TEST_CASE( queue_stress_with_sleep ) {
    SPSCDataQueue queue(1024, 4);

    constexpr int DATA_SIZE = 256;
    constexpr int LOOP_COUNT = 10000;

    std::array<uint8_t, DATA_SIZE> data;
    data.fill(0);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(8, DATA_SIZE);
    uint64_t loss_bytes = 0;

    std::thread _thread([&queue,&data, &gen, &dis, &loss_bytes](){
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        for (int i = 0; i < LOOP_COUNT; ++i) {
            size_t dsize = dis(gen);
            reinterpret_cast<uint32_t*>(data.data())[0] = static_cast<uint32_t>(i);
            reinterpret_cast<uint32_t*>(data.data())[1] = static_cast<uint32_t>(dsize);
            uint64_t loss = 0;
            auto in_ptr = queue.Allocate(dsize, &loss);
            loss_bytes += loss;
            ::memcpy(in_ptr, data.data(), dsize);
            queue.Commit(dsize);
            std::this_thread::sleep_for(std::chrono::microseconds (1));
        }
    });

    uint64_t loss_count = 0;

    for (int i = 0; i < LOOP_COUNT; ++i) {
        uint32_t* out_ptr;
        auto ret = queue.Get(reinterpret_cast<uint8_t**>(&out_ptr));
        BOOST_REQUIRE_GT(ret, 0);
        if (out_ptr[0] != static_cast<uint32_t>(i)) {
            i = out_ptr[0];
            loss_count += 1;
        }
        BOOST_REQUIRE_EQUAL(out_ptr[0], static_cast<uint32_t>(i));
        BOOST_REQUIRE_EQUAL(ret, out_ptr[1]);
        queue.Release();
    }
    _thread.join();

    if (loss_count > 0) {
        BOOST_REQUIRE_GT(loss_bytes, 0);
    }
}

BOOST_AUTO_TEST_CASE( queue_close ) {
    SPSCDataQueue queue(1024, 4);

    std::array<uint8_t, 256> data;
    data.fill(0);

    for (int i = 0; i < 6; ++i) {
        data[0] = static_cast<uint8_t>(i);
        auto in_ptr = queue.Allocate(data.size());
        BOOST_REQUIRE(in_ptr != nullptr);
        ::memcpy(in_ptr, data.data(), data.size());
        queue.Commit(data.size());
    }

    queue.Close();

    data[0] = static_cast<uint8_t>(6);
    auto in_ptr = queue.Allocate(data.size());
    BOOST_REQUIRE(in_ptr == nullptr);

    for (int i = 0; i < 6; ++i) {
        uint8_t* out_ptr;
        auto ret = queue.Get(&out_ptr);
        BOOST_REQUIRE_EQUAL(ret, data.size());
        BOOST_REQUIRE_EQUAL(out_ptr[0], static_cast<uint8_t>(i));
        queue.Release();
    }

    uint8_t* out_ptr;
    auto ret = queue.Get(&out_ptr);
    BOOST_REQUIRE_EQUAL(ret, -1);
}
