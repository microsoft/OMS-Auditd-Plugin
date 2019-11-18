/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_QUEUE_H
#define AUOMS_QUEUE_H

#include <array>
#include <string>
#include <cstdint>
#include <mutex>
#include <condition_variable>
#include <functional>

class QueueCursor {
public:
    static const QueueCursor HEAD;
    static const QueueCursor TAIL;
    static const size_t DATA_SIZE = sizeof(uint64_t)*2;

    QueueCursor() { id = 0; index = 0; }
    QueueCursor(uint64_t id, uint64_t index) { this->id = id; this->index = index; }


    bool IsHead() { return id==HEAD.id && index==HEAD.index; }
    bool IsTail() { return id==TAIL.id && index==TAIL.index; }

    void to_data(std::array<uint8_t, DATA_SIZE>& data) const;
    void to_data(void* ptr, size_t size) const;
    void from_data(const std::array<uint8_t, DATA_SIZE>& data);

    bool operator==(const QueueCursor& other) const { return other.id==id && other.index==index; }

    uint64_t id;
    uint64_t index;
};

class Queue {
public:
    static constexpr uint64_t HEADER_MAGIC = 0x4555455551465542; // AUFQUEUE
    static constexpr uint64_t VERSION = 3;
    static constexpr size_t MIN_QUEUE_SIZE = 256*1024;
    static constexpr size_t MAX_ITEM_SIZE = 256*1024;
    static constexpr int OK = 1;
    static constexpr int TIMEOUT = 0;
    static constexpr int CLOSED = -1;
    static constexpr int BUFFER_TOO_SMALL = -2;
    static constexpr int INTERRUPTED = -3;
    static constexpr uint64_t ITEM = 1;
    static constexpr uint64_t WRAP = 2;
    static constexpr uint64_t HEAD = 3;
    static constexpr uint64_t UNCOMMITTED_PUT = 4;

    explicit Queue(size_t size);
    Queue(const std::string& path, size_t size);
    ~Queue();

    Queue(const Queue&) = delete;
    Queue(Queue&&) = default;
    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = default;

    void Open();
    void Close();
    void Close(bool save); // Only required for unit tests
    void Save();

    void Reset();

    void Interrupt();

    // Does not return until queue is closed.
    void Autosave(uint64_t min_save, int max_delay);

    // If overwrite is true, delete unread messages until enough space is available
    // Return 1 on success, return -1 if queue is closed.
    int Put(void* ptr, size_t size);

    // Return 1 on success, 0 on Timeout, -1 if queue closed, -2 if buffer is too small
    // On input size must be the buffer size, on output size will be the actual size of the item
    // If size is smaller than the item
    // If last is:
    //  QueueCursor::TAIL - Get the oldest item
    //  QueueCursor::HEAD - Wait the the next item to be added
    //  is invalid - Get the oldest item
    //  is valid - Get the item just after last
    // item_cursor is the cursor for the item returned.
    int Get(QueueCursor last, void* ptr, size_t* size, QueueCursor* item_cursor, int32_t milliseconds);

private:
    void save_locked(std::unique_lock<std::mutex>& lock);
    int allocate_locked(std::unique_lock<std::mutex>& lock, void** ptr, size_t size);
    int commit_locked();

    bool check_fit(size_t size);
    uint64_t unsaved_size();
    bool have_data(uint64_t *index);

    std::string _path;
    uint64_t _file_size;
    uint64_t _data_size;
    uint64_t _next_id;
    int _fd;
    char* _ptr;
    bool _closed;
    uint64_t _head; // Newest item
    uint64_t _tail; // Oldest item
    uint64_t _saved_size; // Amount currently saved
    bool _save_active; // Amount currently saved
    std::mutex _lock;
    std::condition_variable _cond;
    uint64_t _int_id;
};


#endif //AUOMS_QUEUE_H
