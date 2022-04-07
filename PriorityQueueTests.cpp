/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "PriorityQueue.h"
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "PriorityQueueTests"
#include <boost/test/unit_test.hpp>

#include "TempDir.h"
#include "FileUtils.h"
#include <stdexcept>
#include <array>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <sys/stat.h>
#include <sys/statvfs.h>

BOOST_AUTO_TEST_CASE( queue_empty_reopen ) {
    TempDir dir("/tmp/PriorityQueueTests");

    {
        auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 0, 0, 0, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }
        queue->StartSaver(0);
        queue->Close();
    }
    {
        auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 0, 0, 0, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }
        queue->StartSaver(0);
        queue->Close();
    }
}

BOOST_AUTO_TEST_CASE( queue_simple ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 0, 0, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle = queue->OpenCursor("test");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (uint8_t i = 1; i <= 10; i++) {
        data[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }

        auto val = queue->Get(cursor_handle, 0);
        if (val.second) {
            BOOST_FAIL("cursor->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor->Get() returned nullptr!");
        }
        auto x = reinterpret_cast<uint8_t*>(val.first->Data())[0];
        BOOST_REQUIRE_EQUAL(i, x);
    }

    auto val = queue->Get(cursor_handle,0);
    if (val.second) {
        BOOST_FAIL("cursor->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    queue->Close();

    val = queue->Get(cursor_handle,0);
    if (!val.second) {
        BOOST_FAIL("cursor->Get() returned closed!=true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    PriorityQueueStats stats;
    queue->GetStats(stats);

    BOOST_CHECK_EQUAL(stats._total._num_items_added, 10);
    BOOST_CHECK_EQUAL(stats._total._bytes_fs, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_mem, 10*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_written, 0);
}

BOOST_AUTO_TEST_CASE( queue_oversided_item ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 1024*1024, 16, 0, 0, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle = queue->OpenCursor("test");

    std::array<uint8_t, PriorityQueue::MAX_ITEM_SIZE+1> data;
    data.fill(0);

    data[0] = 1;
    if (queue->Put(0, data.data(), data.size()) != -1) {
        BOOST_FAIL("queue->Put() failed to reject oversided item!");
    }

    if (queue->Put(0, data.data(), data.size()-1) != 1) {
        BOOST_FAIL("queue->Put() failed add item!");
    }
}

BOOST_AUTO_TEST_CASE( queue_cursor_rollback ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 0, 0, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle = queue->OpenCursor("test");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (uint8_t i = 1; i <= 10; i++) {
        data[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    for (uint8_t i = 1; i <= 10; i++) {
        auto val = queue->Get(cursor_handle,0, false);
        if (val.second) {
            BOOST_FAIL("cursor->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor->Get() returned nullptr!");
        }
        auto x = reinterpret_cast<uint8_t*>(val.first->Data())[0];
        BOOST_REQUIRE_EQUAL(i, x);
    }

    queue->Rollback(cursor_handle);

    for (uint8_t i = 1; i <= 10; i++) {
        auto val = queue->Get(cursor_handle,0);
        if (val.second) {
            BOOST_FAIL("cursor->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor->Get() returned nullptr!");
        }
        auto x = reinterpret_cast<uint8_t*>(val.first->Data())[0];
        BOOST_REQUIRE_EQUAL(i, x);
    }

    auto val = queue->Get(cursor_handle,0);
    if (val.second) {
        BOOST_FAIL("cursor->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    queue->Close();

    val = queue->Get(cursor_handle,0);
    if (!val.second) {
        BOOST_FAIL("cursor->Get() returned closed!=true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    PriorityQueueStats stats;
    queue->GetStats(stats);

    BOOST_CHECK_EQUAL(stats._total._num_items_added, 10);
    BOOST_CHECK_EQUAL(stats._total._bytes_fs, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_mem, 10*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_unsaved, QueueFile::Overhead(4)*2 + 8*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_written, 0);
}

BOOST_AUTO_TEST_CASE( queue_simple_multi_cursor ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 0, 0, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle1 = queue->OpenCursor("test1");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (uint8_t i = 1; i < 6; i++) {
        data[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    auto cursor_handle2 = queue->OpenCursor("test2");

    for (uint8_t i = 6; i <= 10; i++) {
        data[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    for (uint8_t i = 1; i <= 10; i++) {
        auto val = queue->Get(cursor_handle1,0);
        if (val.second) {
            BOOST_FAIL("cursor1->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor1->Get() returned nullptr!");
        }
        auto x = reinterpret_cast<uint8_t*>(val.first->Data())[0];
        BOOST_REQUIRE_EQUAL(i, x);
    }

    for (uint8_t i = 6; i <= 10; i++) {
        auto val = queue->Get(cursor_handle2,0);
        if (val.second) {
            BOOST_FAIL("cursor2->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor2->Get() returned nullptr!");
        }
        auto x = reinterpret_cast<uint8_t*>(val.first->Data())[0];
        BOOST_REQUIRE_EQUAL(i, x);
    }

    auto val = queue->Get(cursor_handle1,0);
    if (val.second) {
        BOOST_FAIL("cursor1->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor1->Get() did not return nullptr!");
    }

    val = queue->Get(cursor_handle2,0);
    if (val.second) {
        BOOST_FAIL("cursor2->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor2->Get() did not return nullptr!");
    }

    queue->Close();

    val = queue->Get(cursor_handle1,0);
    if (!val.second) {
        BOOST_FAIL("cursor1->Get() returned closed!=true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor1->Get() did not return nullptr!");
    }

    val = queue->Get(cursor_handle2,0);
    if (!val.second) {
        BOOST_FAIL("cursor2->Get() returned closed!=true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor2->Get() did not return nullptr!");
    }

    PriorityQueueStats stats;
    queue->GetStats(stats);

    BOOST_CHECK_EQUAL(stats._total._num_items_added, 10);
    BOOST_CHECK_EQUAL(stats._total._bytes_fs, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_mem, 10*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_unsaved, QueueFile::Overhead(4)*2 + 8*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_written, 0);
}

BOOST_AUTO_TEST_CASE( queue_simple_multi_cursor_reopen ) {
    TempDir dir("/tmp/PriorityQueueTests");

    {
        auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 4096 * 1024, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }

        queue->StartSaver(0);

        auto cursor_handle1 = queue->OpenCursor("test1");

        std::array<uint8_t, 1024> data;
        data.fill(0);

        for (uint8_t i = 1; i < 6; i++) {
            data[0] = i;
            if (queue->Put(0, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }
        }

        auto cursor_handle2 = queue->OpenCursor("test2");

        for (uint8_t i = 6; i <= 10; i++) {
            data[0] = i;
            if (queue->Put(0, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }
        }

        queue->Close();

        PriorityQueueStats stats;
        queue->GetStats(stats);

        constexpr long file_total = QueueFile::Overhead(4)*2 + QueueFile::Overhead(2) + 10*1024;

        BOOST_CHECK_EQUAL(stats._total._num_items_added, 10);
        BOOST_CHECK_EQUAL(stats._total._bytes_fs, file_total);
        BOOST_CHECK_EQUAL(stats._total._bytes_mem, 0);
        BOOST_CHECK_EQUAL(stats._total._bytes_unsaved, 0);
        BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 0);
        BOOST_CHECK_EQUAL(stats._total._bytes_written, file_total);
    }

    {
        auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 4096 * 1024, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }

        queue->StartSaver(0);

        auto cursor_handle1 = queue->OpenCursor("test1");
        auto cursor_handle2 = queue->OpenCursor("test2");

        for (uint8_t i = 1; i <= 10; i++) {
            auto val = queue->Get(cursor_handle1,0);
            if (val.second) {
                BOOST_FAIL("cursor1->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor1->Get() returned nullptr!");
            }
            auto x = reinterpret_cast<uint8_t *>(val.first->Data())[0];
            BOOST_REQUIRE_EQUAL(i, x);
        }

        for (uint8_t i = 6; i <= 10; i++) {
            auto val = queue->Get(cursor_handle2,0);
            if (val.second) {
                BOOST_FAIL("cursor2->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor2->Get() returned nullptr!");
            }
            auto x = reinterpret_cast<uint8_t *>(val.first->Data())[0];
            BOOST_REQUIRE_EQUAL(i, x);
        }

        auto val = queue->Get(cursor_handle1,0);
        if (val.second) {
            BOOST_FAIL("cursor1->Get() returned closed==true!");
        }
        if (val.first) {
            BOOST_FAIL("cursor1->Get() did not return nullptr!");
        }

        val = queue->Get(cursor_handle2,0);
        if (val.second) {
            BOOST_FAIL("cursor2->Get() returned closed==true!");
        }
        if (val.first) {
            BOOST_FAIL("cursor2->Get() did not return nullptr!");
        }

        queue->Close();

        val = queue->Get(cursor_handle1,0);
        if (!val.second) {
            BOOST_FAIL("cursor1->Get() returned closed!=true!");
        }
        if (val.first) {
            BOOST_FAIL("cursor1->Get() did not return nullptr!");
        }

        val = queue->Get(cursor_handle2,0);
        if (!val.second) {
            BOOST_FAIL("cursor2->Get() returned closed!=true!");
        }
        if (val.first) {
            BOOST_FAIL("cursor2->Get() did not return nullptr!");
        }

        PriorityQueueStats stats;
        queue->GetStats(stats);

        BOOST_CHECK_EQUAL(stats._total._num_items_added, 0);
        BOOST_CHECK_EQUAL(stats._total._bytes_fs, 0);
        BOOST_CHECK_EQUAL(stats._total._bytes_mem, 0);
        BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 0);
        BOOST_CHECK_EQUAL(stats._total._bytes_written, 0);
    }
}

BOOST_AUTO_TEST_CASE( queue_simple_priority ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 4096*1024, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle = queue->OpenCursor("test");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    // First is msg id, second is priority
    std::vector<std::pair<int,int>> input_pairs({
        {1,10},
        {2,9},
        {3,8},
        {4,7},
        {5,6},
        {6,5},
        {7,4},
        {8,3},
        {9,2},
        {10,1},
        {11,0},
        {12,0},
    });

    std::vector<int> expected_output({
        11,
        12,
        10,
        9,
        8,
        7,
        6,
        5,
        1,
        2,
        3,
        4,
    });

    for (auto& in: input_pairs) {
        data[0] = in.first;
        if (queue->Put(in.second, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    for (auto expected: expected_output) {
        auto val = queue->Get(cursor_handle,0);
        if (val.second) {
            BOOST_FAIL("cursor->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor->Get() returned nullptr!");
        }
        auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
        BOOST_REQUIRE_EQUAL(expected, actual);
    }

    auto val = queue->Get(cursor_handle,0);
    if (val.second) {
        BOOST_FAIL("cursor->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    queue->Close();

    val = queue->Get(cursor_handle,0);
    if (!val.second) {
        BOOST_FAIL("cursor->Get() returned closed!=true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }
}

BOOST_AUTO_TEST_CASE( queue_simple_priority2 ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 4096*1024, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle = queue->OpenCursor("test");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (uint8_t p = 0; p < 8; p++) {
        for (uint8_t i = 0; i < 2; i++) {
            auto expected = (p*2)+i;
            data[0] = expected;
            if (queue->Put(p, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }

            auto val = queue->Get(cursor_handle,0);
            if (val.second) {
                BOOST_FAIL("cursor->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor->Get() returned nullptr!");
            }
            auto actual = reinterpret_cast<uint8_t *>(val.first->Data())[0];
            BOOST_REQUIRE_EQUAL(expected, actual);
        }
    }

    auto val = queue->Get(cursor_handle,0);
    if (val.second) {
        BOOST_FAIL("cursor->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    queue->Close();

    val = queue->Get(cursor_handle,0);
    if (!val.second) {
        BOOST_FAIL("cursor->Get() returned closed!=true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }
}

BOOST_AUTO_TEST_CASE( queue_max_unsaved_files ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4096, 16, 4096*1024, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle = queue->OpenCursor("test");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    // First is msg id, second is priority
    std::vector<std::pair<int,int>> input_pairs({
        {71,7},
        {72,7},
        {73,7},
        {74,7},
        {75,7},
        {76,7},
        {77,7},
        {78,7},
        {79,7},

        {61,6},
        {62,6},
        {63,6},
        {64,6},
        {65,6},
        {66,6},
        {67,6},
        {68,6},
        {69,6},

        {51,5},
        {52,5},
        {53,5},
        {54,5},
        {55,5},
        {56,5},
        {57,5},
        {58,5},
        {59,5},

        {41,4},
        {42,4},
        {43,4},
        {44,4},
        {45,4},
        {46,4},
        {47,4},
        {48,4},
        {49,4},

        {31,3},
        {32,3},
        {33,3},
        {34,3},
        {35,3},
        {36,3},
        {37,3},
        {38,3},
        {39,3},

        {21,2},
        {22,2},
        {23,2},
        {24,2},
        {25,2},
        {26,2},
        {27,2},
        {28,2},
        {29,2},

        {11,1},
        {12,1},
        {13,1},
        {14,1},
        {15,1},
        {16,1},
        {17,1},
        {18,1},
        {19,1},

        {1,0},
        {2,0},
        {3,0},
        {4,0},
        {5,0},
        {6,0},
        {7,0},
        {8,0},
        {9,0},
    });

    std::vector<std::pair<int,int>> input2_pairs({
        {100,0},
        {101,0},
        {102,0},
        {103,0},

        {104,0},
        {105,0},
        {106,0},
        {107,0},

        {108,0},
        {109,0},
        {110,0},
        {111,0},
    });

    std::vector<int> expected_output({
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        100,
        101,
        102,
        103,
        104,
        105,
        106,
        107,
        108,
        109,
        110,
        111,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        29,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        //61,
        //62,
        //63,
        //64,
        65,
        66,
        67,
        68,
        69,

        //71,
        //72,
        //73,
        //74,

        //75,
        //76,
        //77,
        //78,

        79,
    });

    // This first set of inputs should reach the max mem limit
    for (auto& in: input_pairs) {
        data[0] = in.first;
        if (queue->Put(in.second, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    PriorityQueueStats stats;
    queue->GetStats(stats);

    long file_size = QueueFile::Overhead(4)*16 + 64*1024;

    BOOST_CHECK_EQUAL(stats._total._num_items_added, 72);
    BOOST_CHECK_EQUAL(stats._total._bytes_fs, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_mem, 72*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_unsaved, file_size);
    BOOST_CHECK_EQUAL(stats._total._bytes_written, 0);

    // This set of inputs should exceed the max mem limits
    for (auto& in: input2_pairs) {
        data[0] = in.first;
        if (queue->Put(in.second, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->GetStats(stats);

    BOOST_CHECK_EQUAL(stats._total._num_items_added, 84);
    BOOST_CHECK_EQUAL(stats._total._bytes_fs, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_mem, 72*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 12*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_unsaved, file_size);
    BOOST_CHECK_EQUAL(stats._total._bytes_written, 0);

    for (auto expected: expected_output) {
        auto val = queue->Get(cursor_handle,0);
        if (val.second) {
            BOOST_FAIL("cursor->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor->Get() returned nullptr!");
        }
        auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
        BOOST_REQUIRE_EQUAL(expected, actual);
    }

    auto val = queue->Get(cursor_handle,0);
    if (val.second) {
        BOOST_FAIL("cursor->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    queue->Close();

    val = queue->Get(cursor_handle,0);
    if (!val.second) {
        BOOST_FAIL("cursor->Get() returned closed!=true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }

    queue->GetStats(stats);

    BOOST_CHECK_EQUAL(stats._total._num_items_added, 84);
    BOOST_CHECK_EQUAL(stats._total._bytes_fs, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_mem, 72*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 12*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_unsaved, file_size);
    BOOST_CHECK_EQUAL(stats._total._bytes_written, 0);
}

long get_queue_data_size(const std::string& dir, int num_priority) {
    size_t queue_size = 0;
    for (int p = 0; p < num_priority; p++) {
        auto pdir = dir + "/" + std::to_string(p);
        if (PathExists(pdir)) {
            auto files = GetDirList(pdir);
            for (auto& name : files) {
                auto path = pdir + "/" + name;
                struct stat st;
                if (stat(path.c_str(), &st) != 0) {
                    Logger::Error("stat(%s) failed: %s", path.c_str(), std::strerror(errno));
                    return -1;
                }
                queue_size += st.st_size;
            }
        }
    }
    return queue_size;
}

BOOST_AUTO_TEST_CASE( queue_multi_cursor_fs_loss ) {
    TempDir dir("/tmp/PriorityQueueTests");


    // First is msg id, second is priority
    std::vector<std::pair<int, int>> input_pairs({
        {1,  0},
        {2,  0},
        {3,  0},
        {4,  0},
        {5,  0},
        {6,  0},
        {7,  0},
        {8,  0},

        {11, 1},
        {12, 1},
        {13, 1},
        {14, 1},
        {15, 1},
        {16, 1},
        {17, 1},
        {18, 1},

        {21, 2},
        {22, 2},
        {23, 2},
        {24, 2},
        {25, 2},
        {26, 2},
        {27, 2},
        {28, 2},

        {31, 3},
        {32, 3},
        {33, 3},
        {34, 3},
        {35, 3},
        {36, 3},
        {37, 3},
        {38, 3},

        {41, 4},
        {42, 4},
        {43, 4},
        {44, 4},
        {45, 4},
        {46, 4},
        {47, 4},
        {48, 4},

        {51, 5},
        {52, 5},
        {53, 5},
        {54, 5},
        {55, 5},
        {56, 5},
        {57, 5},
        {58, 5},

        {61, 6},
        {62, 6},
        {63, 6},
        {64, 6},
        {65, 6},
        {66, 6},
        {67, 6},
        {68, 6},

        {71, 7},
        {72, 7},
        {73, 7},
        {74, 7},
        {75, 7},
        {76, 7},
        {77, 7},
        {78, 7},
    });

    std::vector<int> expected_output1_cursor1({
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
    });

    std::vector<int> expected_output2_cursor1({
        38,
    });

    std::vector<int> expected_output1_cursor2({
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
    });

    {
        auto queue = PriorityQueue::Open(dir.Path(), 8, 4096 * ((8 * 2) + 3), 4096, 4200 * 8, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }

        auto cursor_handle1 = queue->OpenCursor("test1");
        auto cursor_handle2 = queue->OpenCursor("test2");

        std::array<uint8_t, 1024> data;
        data.fill(0);

        // This first set of inputs should reach the max mem limit
        for (auto& in: input_pairs) {
            data[0] = in.first;
            if (queue->Put(in.second, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }
        }

        for (auto expected: expected_output1_cursor1) {
            auto val = queue->Get(cursor_handle1,0);
            if (val.second) {
                BOOST_FAIL("cursor1->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor1->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(expected, actual);
        }


        queue->Close();
        queue->Save(0, true);
    }

    {
        auto queue = PriorityQueue::Open(dir.Path(), 8, 4096 * ((8 * 2) + 3), 4096, 4200 * 8, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }

        auto cursor_handle1 = queue->OpenCursor("test1");
        auto cursor_handle2 = queue->OpenCursor("test2");


        for (auto expected: expected_output2_cursor1) {
            auto val = queue->Get(cursor_handle1,0);
            if (val.second) {
                BOOST_FAIL("cursor1->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor1->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(expected, actual);
        }

        for (auto expected: expected_output1_cursor2) {
            auto val = queue->Get(cursor_handle2,0);
            if (val.second) {
                BOOST_FAIL("cursor2->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor2->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(expected, actual);
        }

        queue->Close();
    }
}

BOOST_AUTO_TEST_CASE( queue_multi_cursor_concurrent ) {
    TempDir dir("/tmp/PriorityQueueTests");

    auto queue = PriorityQueue::Open(dir.Path(), 8, 1024*1024*128, 2*1024*1024, 1024*1024*128, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }
    queue->StartSaver(0);

    auto cursor_handle1 = queue->OpenCursor("test1");
    auto cursor_handle2 = queue->OpenCursor("test2");

    int max_id = 10000;

    auto get_fn = [max_id](std::shared_ptr<PriorityQueue>& queue, const std::shared_ptr<QueueCursorHandle>& cursor_handle, std::condition_variable* cond, std::atomic<int>* idx, std::atomic<int>* last) {
        int next_i = 1;
        for (auto item = queue->Get(cursor_handle, -1); item.first; item = queue->Get(cursor_handle, -1)) {
            auto i = reinterpret_cast<int*>(item.first->Data())[0];
            if (last->load() == 0) {
                if (i != next_i || i >= max_id) {
                    last->store(i);
                }
                next_i += 1;
                idx->store(i);
                cond->notify_one();
            }
        }
    };

    std::mutex mutex;
    std::condition_variable cond;
    std::atomic<int> cursor1_idx(0);
    std::atomic<int> cursor2_idx(0);
    std::atomic<int> cursor1_last(false);
    std::atomic<int> cursor2_last(false);

    std::thread _cursor1_thread(std::bind(get_fn, queue, cursor_handle1, &cond, &cursor1_idx, &cursor1_last));
    std::thread _cursor2_thread(std::bind(get_fn, queue, cursor_handle2, &cond, &cursor2_idx, &cursor2_last));

    std::array<uint8_t, 1024> data;
    data.fill(0);

    std::unique_lock<std::mutex> lock(mutex);
    for (int i = 1; i <= max_id; i++) {
        cond.wait(lock, [&i, &cursor1_idx, &cursor2_idx, &cursor1_last, &cursor2_last]() {
            bool c1_ready = cursor1_last.load() != 0 || cursor1_idx.load()+100 >= i;
            bool c2_ready = cursor2_last.load() != 0 || cursor2_idx.load()+100 >= i;
            return c1_ready && c2_ready;
        });
        reinterpret_cast<int*>(data.data())[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    cond.wait(lock, [&cursor1_last, &cursor2_last]() {
        return cursor1_last.load() != 0 && cursor2_last.load() != 0;
    });

    queue->Close();

    _cursor1_thread.join();
    _cursor2_thread.join();

    BOOST_REQUIRE_EQUAL(max_id, cursor1_last.load());
    BOOST_REQUIRE_EQUAL(max_id, cursor2_last.load());
}

BOOST_AUTO_TEST_CASE( queue_fs_clean_multi_cursor ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr int num_items = (16*4)+4;
    constexpr int num_items_per_file = 4;
    constexpr size_t item_size = 1024;
    constexpr size_t max_file_data_size = item_size * num_items_per_file;
    constexpr size_t file_size = QueueFile::Overhead(num_items_per_file)+max_file_data_size;
    constexpr size_t max_fs_bytes = 16*file_size;

    auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, max_fs_bytes, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle1 = queue->OpenCursor("test1");
    auto cursor_handle2 = queue->OpenCursor("test2");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (int i = 0; i < num_items; i++) {
        reinterpret_cast<int*>(data.data())[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->Save(0);

    auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_EQUAL(queue_size, max_fs_bytes);

    for (int i = 0; i < num_items; i++) {
        auto val = queue->Get(cursor_handle1,0);
        if (val.second) {
            BOOST_FAIL("cursor1->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor1->Get() returned nullptr!");
        }
    }

    queue->Save(0);

    queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_EQUAL(queue_size, max_fs_bytes);

    for (int i = 0; i < num_items/2; i++) {
        auto val = queue->Get(cursor_handle2,0);
        if (val.second) {
            BOOST_FAIL("cursor2->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor2->Get() returned nullptr!");
        }
    }

    queue->Save(0);

    auto original_queue_size = queue_size;
    queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_EQUAL(queue_size, original_queue_size/2);

    for (int i = 0; i < num_items/2; i++) {
        auto val = queue->Get(cursor_handle2,0);
        if (val.second) {
            BOOST_FAIL("cursor2->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor2->Get() returned nullptr!");
        }
    }

    queue->Save(0);

    queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_EQUAL(queue_size, 0);

    queue->Close();
}

BOOST_AUTO_TEST_CASE( queue_fs_clean_remove_cursor ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr int num_items = (16*4)+4;
    constexpr int num_items_per_file = 4;
    constexpr size_t item_size = 1024;
    constexpr size_t max_file_data_size = item_size * num_items_per_file;
    constexpr size_t file_size = QueueFile::Overhead(num_items_per_file)+max_file_data_size;
    constexpr size_t max_fs_bytes = 16*file_size;

    auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, max_fs_bytes, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle1 = queue->OpenCursor("test1");
    auto cursor_handle2 = queue->OpenCursor("test2");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (int i = 0; i < num_items; i++) {
        reinterpret_cast<int*>(data.data())[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->Save(0);

    auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_EQUAL(queue_size, max_fs_bytes);

    for (int i = 0; i < num_items; i++) {
        auto val = queue->Get(cursor_handle1,0);
        if (val.second) {
            BOOST_FAIL("cursor1->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor1->Get() returned nullptr!");
        }
    }

    queue->Save(0);

    queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_EQUAL(queue_size, max_fs_bytes);

    queue->RemoveCursor("test2");

    queue->Save(0);

    queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_EQUAL(queue_size, 0);

    queue->Close();
}

BOOST_AUTO_TEST_CASE( queue_fs_clean_delete_cursor ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr int num_items = (16*4)+4;
    constexpr int num_items_per_file = 4;
    constexpr size_t item_size = 1024;
    constexpr size_t max_file_data_size = item_size * num_items_per_file;
    constexpr size_t file_size = QueueFile::Overhead(num_items_per_file)+max_file_data_size;
    constexpr size_t max_fs_bytes = 16*file_size;

    {
        auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, max_fs_bytes,100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }

        auto cursor_handle1 = queue->OpenCursor("test1");
        auto cursor_handle2 = queue->OpenCursor("test2");

        std::array<uint8_t, 1024> data;
        data.fill(0);

        for (int i = 0; i < num_items; i++) {
            reinterpret_cast<int *>(data.data())[0] = i;
            if (queue->Put(0, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }
        }

        queue->Save(0);

        auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
        if (queue_size < 0) {
            BOOST_FAIL("get_queue_data_size() failed!");
        }
        BOOST_REQUIRE_EQUAL(queue_size, max_fs_bytes);

        for (int i = 0; i < num_items; i++) {
            auto val = queue->Get(cursor_handle1,0);
            if (val.second) {
                BOOST_FAIL("cursor1->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor1->Get() returned nullptr!");
            }
        }

        queue->Save(0);

        queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
        if (queue_size < 0) {
            BOOST_FAIL("get_queue_data_size() failed!");
        }
        BOOST_REQUIRE_EQUAL(queue_size, max_fs_bytes);

        queue->Close();
    }

    if (unlink((dir.Path() + "/cursors/test2").c_str()) != 0) {
        BOOST_FAIL("Failed to remove cursor file");
    }

    {
        auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, max_fs_bytes,100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }

        queue->Save(0);

        auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
        if (queue_size < 0) {
            BOOST_FAIL("get_queue_data_size() failed!");
        }
        BOOST_REQUIRE_EQUAL(queue_size, 0);

        queue->Close();
    }
}

BOOST_AUTO_TEST_CASE( queue_max_fs_bytes ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr int num_items = 32;
    constexpr int num_items_dropped = 20;
    constexpr int num_items_per_file = 4;
    constexpr int num_written_files = 8;
    constexpr int num_saved_files = 3;
    constexpr size_t max_file_data_size = 4096;
    constexpr size_t max_fs_bytes = 1024*16;


    auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, max_fs_bytes, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle1 = queue->OpenCursor("test1");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (int i = 0; i < num_items; i++) {
        reinterpret_cast<int*>(data.data())[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->Close();
    queue->Save(0, true);

    auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_LE(queue_size, max_fs_bytes);


    PriorityQueueStats stats;
    queue->GetStats(stats);

    long file_size = QueueFile::Overhead(num_items_per_file)*num_saved_files + num_items_per_file*num_saved_files*1024;
    long unsaved_size = QueueFile::Overhead(num_items_per_file)*(num_written_files-num_saved_files) + num_items_dropped*1024;

    BOOST_CHECK_EQUAL(stats._total._num_items_added, num_items);
    BOOST_CHECK_EQUAL(stats._total._bytes_fs, file_size);
    BOOST_CHECK_EQUAL(stats._total._bytes_mem, num_items_dropped*1024);
    BOOST_CHECK_EQUAL(stats._total._bytes_dropped, 0);
    BOOST_CHECK_EQUAL(stats._total._bytes_unsaved, unsaved_size);
    BOOST_CHECK_EQUAL(stats._total._bytes_written, file_size);
}

BOOST_AUTO_TEST_CASE( queue_max_fs_pct ) {
    TempDir dir("/tmp/PriorityQueueTests");

    struct statvfs st;
    ::memset(&st, 0, sizeof(st));
    if (statvfs(dir.Path().c_str(), &st) != 0) {
        BOOST_FAIL("statvfs failed!");
    }

    // Total filesystem size
    double fs_size = static_cast<double>(st.f_blocks * st.f_frsize);

    constexpr int num_priorities = 8;
    constexpr int num_items = 32;
    constexpr size_t max_file_data_size = 4096;
    constexpr size_t max_fs_bytes = 1024*16;

    float max_fs_pct = static_cast<double>(max_fs_bytes) / fs_size;

    auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, 1024*1024, max_fs_pct, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle1 = queue->OpenCursor("test1");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (int i = 0; i < num_items; i++) {
        reinterpret_cast<int*>(data.data())[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->Save(0);

    auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    float fs_pct = static_cast<double>(queue_size) / fs_size;

    BOOST_REQUIRE_LE(fs_pct, max_fs_pct);

    queue->Close();
}

BOOST_AUTO_TEST_CASE( queue_min_fs_free_pct ) {
    TempDir dir("/tmp/PriorityQueueTests");

    struct statvfs st;
    ::memset(&st, 0, sizeof(st));
    if (statvfs(dir.Path().c_str(), &st) != 0) {
        BOOST_FAIL("statvfs failed!");
    }

    // Total filesystem size
    double fs_size = static_cast<double>(st.f_blocks * st.f_frsize);
    // Amount of free space
    double fs_free = static_cast<double>(st.f_bavail * st.f_bsize);
    // Percent of free space
    float pct_free = fs_free / fs_size;

    constexpr int num_priorities = 8;
    constexpr int num_items = 32;
    constexpr size_t max_file_data_size = 4096;
    constexpr size_t max_fs_bytes = 1024*16;

    float max_fs_pct = static_cast<double>(max_fs_bytes) / fs_size;
    float min_fs_free_pct = (pct_free-max_fs_pct)*100;

    auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, 1024*1024, 100, min_fs_free_pct);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle1 = queue->OpenCursor("test1");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (int i = 0; i < num_items; i++) {
        reinterpret_cast<int*>(data.data())[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->Save(0);

    auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_LE(queue_size, max_fs_bytes);

    queue->Close();
}

BOOST_AUTO_TEST_CASE( queue_save_delay ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr size_t max_file_data_size = 4096;

    auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_priorities, 1024*1024, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle1 = queue->OpenCursor("test1");

    std::array<uint8_t, 1024> data;
    data.fill(0);

    for (int i = 0; i < 9; i++) {
        reinterpret_cast<int*>(data.data())[0] = i;
        if (queue->Put(0, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    auto t = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);

    queue->Save(10000000);

    auto file_list = GetDirList(dir.Path() + "/data/0");
    BOOST_REQUIRE_EQUAL(file_list.size(), 1);

    std::this_thread::sleep_until(t);

    queue->Save(250);

    file_list = GetDirList(dir.Path() + "/data/0");
    BOOST_REQUIRE_EQUAL(file_list.size(), 2);

    queue->Close();
}

BOOST_AUTO_TEST_CASE( queue_cursor_commit ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr size_t max_file_data_size = 4096;

    {
        auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_priorities, 1024 * 1024, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }
        queue->StartSaver(60000);

        auto cursor_handle1 = queue->OpenCursor("test1");

        std::array<uint8_t, 1024> data;
        data.fill(0);

        for (int i = 0; i < 32; i++) {
            reinterpret_cast<int *>(data.data())[0] = i;
            if (queue->Put(0, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }
        }

        for (int i = 0; i < 16; i++) {
            auto val = queue->Get(cursor_handle1, 0, false);
            if (val.second) {
                BOOST_FAIL("cursor->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(i, actual);
            queue->Commit(cursor_handle1, val.first->Priority(), val.first->Sequence());
        }

        for (int i = 16; i < 32; i++) {
            auto val = queue->Get(cursor_handle1, 0, false);
            if (val.second) {
                BOOST_FAIL("cursor->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(i, actual);
        }
        queue->Close();
    }

    {
        auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_priorities, 1024 * 1024, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }
        queue->StartSaver(60000);

        auto cursor_handle1 = queue->OpenCursor("test1");

        for (int i = 16; i < 32; i++) {
            auto val = queue->Get(cursor_handle1, 0, false);
            if (val.second) {
                BOOST_FAIL("cursor->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(i, actual);
            queue->Commit(cursor_handle1, val.first->Priority(), val.first->Sequence());
        }
        queue->Close();
    }
}

BOOST_AUTO_TEST_CASE( queue_fs_force_clean ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr int num_items = 32;
    constexpr int num_items_per_file = 4;
    constexpr size_t item_size = 1024;
    constexpr size_t max_file_data_size = item_size * num_items_per_file;
    constexpr size_t file_size = QueueFile::Overhead(num_items_per_file)+max_file_data_size;
    constexpr size_t max_fs_bytes = 4 * file_size;

    auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_items/4, max_fs_bytes, 100, 0);
    if (!queue) {
        BOOST_FAIL("Failed to open queue");
    }

    auto cursor_handle = queue->OpenCursor("test");

    std::array<uint8_t, item_size> data;
    data.fill(0);

    // First is msg id, second is priority
    std::vector<std::pair<int,int>> input_pairs1({
        {1,0},
        {2,0},
        {3,0},
        {4,0},

        {5,0},
        {6,0},
        {7,0},
        {8,0},

        {9,0},

        {71,7},
        {72,7},
        {73,7},
        {74,7},

        {75,7},
        {76,7},
        {77,7},
        {78,7},

        {79,7},
    });

    std::vector<std::pair<int,int>> input_pairs2({
        {10,0},
        {11,0},
        {12,0},

        {13,0},
        {14,0},
        {15,0},
        {16,0},

        {17,0},
        {18,0},
        {19,0},
        {20,0},

        {21,0},
        {22,0},
        {23,0},
        {24,0},

        {25,0},
    });

    std::vector<int> expected_output1({
        1,
        2,
        3,
    });

    std::vector<int> expected_output2({
        4,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        79,
    });

    for (auto& in: input_pairs1) {
        data[0] = in.first;
        if (queue->Put(in.second, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->Save(0);

    auto queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_LE(queue_size, max_fs_bytes);

    for (auto expected: expected_output1) {
        auto val = queue->Get(cursor_handle,0);
        if (val.second) {
            BOOST_FAIL("cursor->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor->Get() returned nullptr!");
        }
        auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
        BOOST_REQUIRE_EQUAL(expected, actual);
    }

    for (auto& in: input_pairs2) {
        data[0] = in.first;
        if (queue->Put(in.second, data.data(), data.size()) != 1) {
            BOOST_FAIL("queue->Put() failed!");
        }
    }

    queue->Save(0);

    queue_size = get_queue_data_size(dir.Path() + "/data", num_priorities);
    if (queue_size < 0) {
        BOOST_FAIL("get_queue_data_size() failed!");
    }
    BOOST_REQUIRE_LE(queue_size, max_fs_bytes);

    for (auto expected: expected_output2) {
        auto val = queue->Get(cursor_handle,0);
        if (val.second) {
            BOOST_FAIL("cursor->Get() returned closed==true!");
        }
        if (!val.first) {
            BOOST_FAIL("cursor->Get() returned nullptr!");
        }
        auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
        BOOST_REQUIRE_EQUAL(expected, actual);
    }

    auto val = queue->Get(cursor_handle,0);
    if (val.second) {
        BOOST_FAIL("cursor->Get() returned closed==true!");
    }
    if (val.first) {
        BOOST_FAIL("cursor->Get() did not return nullptr!");
    }


    queue->Close();
}

BOOST_AUTO_TEST_CASE( queue_empty_cursor_reset ) {
    TempDir dir("/tmp/PriorityQueueTests");

    constexpr int num_priorities = 8;
    constexpr size_t max_file_data_size = 4096;

    {
        auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_priorities, 1024 * 1024, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }
        queue->StartSaver(250);

        auto cursor_handle1 = queue->OpenCursor("test1");

        std::array<uint8_t, 1024> data;
        data.fill(0);

        for (int i = 0; i < 32; i++) {
            reinterpret_cast<int *>(data.data())[0] = i;
            if (queue->Put(0, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }
        }

        for (int i = 0; i < 32; i++) {
            auto val = queue->Get(cursor_handle1,0);
            if (val.second) {
                BOOST_FAIL("cursor->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(i, actual);
        }
        queue->Close();
    }

    {
        auto queue = PriorityQueue::Open(dir.Path(), num_priorities, max_file_data_size, num_priorities, 1024 * 1024, 100, 0);
        if (!queue) {
            BOOST_FAIL("Failed to open queue");
        }
        queue->StartSaver(250);

        auto cursor_handle1 = queue->OpenCursor("test1");

        std::array<uint8_t, 1024> data;
        data.fill(0);

        for (int i = 0; i < 32; i++) {
            reinterpret_cast<int *>(data.data())[0] = i;
            if (queue->Put(0, data.data(), data.size()) != 1) {
                BOOST_FAIL("queue->Put() failed!");
            }
        }

        for (int i = 0; i < 32; i++) {
            auto val = queue->Get(cursor_handle1,0);
            if (val.second) {
                BOOST_FAIL("cursor->Get() returned closed==true!");
            }
            if (!val.first) {
                BOOST_FAIL("cursor->Get() returned nullptr!");
            }
            auto actual = static_cast<int>(reinterpret_cast<uint8_t*>(val.first->Data())[0]);
            BOOST_REQUIRE_EQUAL(i, actual);
        }
        queue->Close();
    }
}
