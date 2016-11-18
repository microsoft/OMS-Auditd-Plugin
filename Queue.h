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

#include <string>
#include <cstdint>
#include <mutex>
#include <condition_variable>
#include <functional>

enum class queue_msg_type_t:uint64_t {
    EVENT = 0x1,
    EVENTS_GAP = 0x2
};

class Queue {
public:
    static constexpr uint64_t HEADER_MAGIC = 0x4555455551465542; // AUFQUEUE
    static constexpr uint64_t VERSION = 1;
    static constexpr size_t MIN_QUEUE_SIZE = 64*1024;
    static constexpr int64_t TIMEOUT = 0;
    static constexpr int64_t CLOSED = -1;
    static constexpr int64_t WRAP = -2;
    static constexpr int64_t HEAD = -3;
    static constexpr int64_t BUFFER_TOO_SMALL = -4;
    static constexpr int64_t UNCOMMITTED_PUT = -5;

    explicit Queue(size_t size);
    Queue(const std::string& path, size_t size);
    ~Queue();

    Queue(const Queue&) = delete;
    Queue(Queue&&) = default;
    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = default;

    void Open();
    void Close();
    void Save();

    // Does not return until queue is closed.
    void Autosave(uint64_t min_save, int max_delay);

    // If overwrite is true, delete unread messages until enough space is available
    // Return 1 on success, return 0 on timeout, return -1 if queue is closed.
    int Put(void* ptr, size_t size, queue_msg_type_t msg_type, bool overwrite, int32_t milliseconds);

    // If overwrite is true, delete unread messages until enough space is available
    // Return 1 on success, return 0 on timeout, return -1 if queue is closed.
    int Allocate(void** ptr, size_t size, bool overwrite, int32_t milliseconds);

    // Return 1 on success, return -1 if queue is closed.
    int Commit(queue_msg_type_t msg_type);

    // Return 1 on success, return -1 if queue is closed.
    int Rollback();

    // Get the id and size of the next message
    // Return slot Id on success, 0 on Timeout, -1 if queue closed
    int64_t Peek(size_t* size, queue_msg_type_t* msg_type, int32_t milliseconds);

    // Try to get the message previously peeked
    // Return 1 on success, 0 on if msg has already been deleted, -1 if queue closed
    int TryGet(int64_t msg_id, void* ptr, size_t size, bool auto_checkpoint);

    // Return slot Id on success, 0 on Timeout, -1 if queue closed
    int64_t Get(void* ptr, size_t* size, queue_msg_type_t* msg_type, bool auto_checkpoint, int32_t milliseconds);

    // Return 1 on success, -1 if queue is closed, and 0 if timeout, or fn returned false
    int ZeroCopyGet(int32_t milliseconds, bool auto_checkpoint,
                    std::function<bool(int64_t msg_id, void* ptr, size_t size, queue_msg_type_t msg_type)> fn);

    void Checkpoint(uint64_t id);
    void Revert();

private:
    void save_locked(std::unique_lock<std::mutex>& lock);
    int allocate_locked(std::unique_lock<std::mutex>& lock, void** ptr, size_t size, bool overwrite, int32_t milliseconds);
    int commit_locked(queue_msg_type_t msg_type);

    bool check_fit(size_t size);
    uint64_t unsaved_size();
    bool have_data();

    std::string _path;
    uint64_t _size;
    int64_t _next_id;
    int _fd;
    char* _ptr;
    bool _closed;
    uint64_t _widx; // Next write point
    uint64_t _ridx; // First non-checkpointed
    uint64_t _index; // Next get point
    int64_t _saved_size; // Amount currently saved
    std::mutex _lock;
    std::condition_variable _cond;
};


#endif //AUOMS_QUEUE_H
