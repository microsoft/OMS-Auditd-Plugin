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
#include "Logger.h"

#include <cassert>
#include <cstring>
#include <chrono>
#include <system_error>

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <signal.h>
}

const QueueCursor QueueCursor::HEAD = QueueCursor(0xFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFF);
const QueueCursor QueueCursor::TAIL = QueueCursor(0, 0xFFFFFFFFFFFFFF);

void QueueCursor::to_data(std::array<uint8_t, DATA_SIZE>& data) const {
    uint64_t* ptr = reinterpret_cast<uint64_t*>(data.data());
    ptr[0] = id;
    ptr[1] = index;
}

void QueueCursor::to_data(void* ptr, size_t size) const {
    assert(ptr != nullptr);
    assert(size >= DATA_SIZE);

    reinterpret_cast<uint64_t*>(ptr)[0] = id;
    reinterpret_cast<uint64_t*>(ptr)[1] = index;
}

void QueueCursor::from_data(const std::array<uint8_t, DATA_SIZE>& data) {
    const uint64_t* ptr = reinterpret_cast<const uint64_t*>(data.data());
    id = ptr[0];
    index = ptr[1];
}


struct BlockHeader {
    uint64_t size;
    uint64_t id;
    uint64_t state;
};

#define FILE_DATA_OFFSET 512
struct FileHeader {
    uint64_t magic;
    uint64_t version;
    uint64_t size;
    uint64_t head;
    uint64_t tail;
    uint64_t next_id;
};

struct _region {
    char* data;
    size_t index;
    size_t size;
};

void _pread(int fd, void* ptr, size_t size, off_t offset)
{
    while (size > 0) {
        auto nr = pread(fd, ptr, size, offset);
        if (nr < 0) {
            if (errno != EINTR) {
                throw std::system_error(errno, std::system_category(), "read()");
            }
        } else if (nr == 0) {
            throw std::runtime_error("EOF");
        } else {
            ptr = reinterpret_cast<char*>(ptr)+nr;
            size -= nr;
            offset += nr;
        }
    }
}

void _pwrite(int fd, void* ptr, size_t size, off_t offset)
{
    while (size > 0) {
        auto nw = pwrite(fd, ptr, size, offset);
        if (nw < 0) {
            if (errno != EINTR) {
                throw std::system_error(errno, std::system_category(), "write()");
            }
        } else {
            ptr = reinterpret_cast<char*>(ptr)+nw;
            size -= nw;
            offset += nw;
        }
    }
}

Queue::Queue(size_t size):
        _path(), _file_size(size), _fd(-1), _next_id(1), _closed(true), _save_active(false), _int_id(0)
{
    if (_file_size < MIN_QUEUE_SIZE) {
        _file_size = MIN_QUEUE_SIZE;
    }
    _data_size = _file_size-FILE_DATA_OFFSET;
    _ptr = new char[_data_size];

    memset(_ptr, 0, _data_size);

    _tail = _head = _saved_size = 0;
}

Queue::Queue(const std::string& path, size_t size):
        _path(path), _file_size(size), _fd(-1), _next_id(1), _closed(true), _save_active(false), _int_id(0)
{
    if (_file_size < MIN_QUEUE_SIZE) {
        _file_size = MIN_QUEUE_SIZE;
    }
    _data_size = _file_size-FILE_DATA_OFFSET;
    _ptr = new char[_data_size];
    memset(_ptr, 0, _data_size);
}

Queue::~Queue()
{
    if (_fd > -1) {
        close(_fd);
    }
    delete[] _ptr;
}

void Queue::Open()
{
    std::unique_lock<std::mutex> lock(_lock);

    if (!_closed) {
        return;
    }

    if (_path.empty()) {
        _closed = true;
        return;
    }

    _tail = _head = _saved_size = 0;

    _fd = open(_path.c_str(), O_RDWR|O_CREAT|O_SYNC, 0600);
    if (_fd < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to open queue file");
    }

    // SIGINT and SIGTERM are blocked at this point
    // Unblock them so that the process can be terminated if it hangs while trying to lock the queue file
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &set, nullptr);
    // Obtain an exclusive lock on the queue file.
    if (flock(_fd, LOCK_EX) != 0) {
        throw std::system_error(errno, std::system_category(), "Failed to lock queue file");
    }
    // Re-block the signals
    sigprocmask(SIG_BLOCK, &set, nullptr);

    struct stat st;
    if (fstat(_fd, &st) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to fstat queue file");
    }

    bool new_file = false;
    if (st.st_size == 0) {
        new_file = true;
    }

    if (st.st_size < FILE_DATA_OFFSET) {
        if (ftruncate(_fd, FILE_DATA_OFFSET) != 0) {
            throw std::system_error(errno, std::system_category(), "ftruncate failed");
        }
    }

    struct _region regions[2];
    int nregions = 0;

    FileHeader hdr;
    if (!new_file) {
        _pread(_fd, &hdr, sizeof(FileHeader), 0);

        if (hdr.magic != HEADER_MAGIC) {
            Logger::Warn("File exists and is not a valid queue file: %s", _path.c_str());
            throw std::runtime_error("File exists and is not a valid queue file: " + _path);
        }

        if (hdr.version != VERSION) {
            Logger::Warn(
                    "Queue file version mismatch, discarding existing contents: Expected version %ld, found version %ld",
                    VERSION, hdr.version);
            hdr.version = VERSION;
            hdr.size = _file_size;
            hdr.tail = 0;
            hdr.head = 0;
            hdr.next_id = 1;
        }

        if (hdr.size != _file_size) {
            Logger::Warn("Queue::Open: Requested queue size (%ld) does not match existing queue size (%ld). Ignoring requested file size and using actual file size.", _file_size, hdr.size);
            _file_size = hdr.size;
            _data_size = _file_size-FILE_DATA_OFFSET;
            delete[] _ptr;
            _ptr = new char[_data_size];
            memset(_ptr, 0, _data_size);
        }
    } else {
        hdr.magic = HEADER_MAGIC;
        hdr.version = VERSION;
        hdr.size = _file_size;
        hdr.tail = 0;
        hdr.head = 0;
        hdr.next_id = 1;

        // The size of the save file has changed.
        if (ftruncate(_fd, _file_size) != 0) {
            throw std::system_error(errno, std::system_category(), "ftruncate failed");
        }
        // Update header with new size
        _pwrite(_fd, &hdr, sizeof(FileHeader), 0);
        // Make sure all the file blocks are allocated on disk.
        _pwrite(_fd, _ptr, _data_size, FILE_DATA_OFFSET);
    }

    _next_id = hdr.next_id;

    if (hdr.tail == hdr.head) {
        _closed = false;
        return;
    } else if (hdr.tail < hdr.head) {
        regions[0].data = _ptr+hdr.tail;
        regions[0].size = hdr.head - hdr.tail;
        regions[0].index = hdr.tail + FILE_DATA_OFFSET;
        nregions = 1;
    } else {
        regions[0].data = _ptr;
        regions[0].size = hdr.head;
        regions[0].index = FILE_DATA_OFFSET;
        regions[1].data = _ptr+hdr.tail;
        regions[1].size = hdr.size - FILE_DATA_OFFSET - hdr.tail;
        regions[1].index = hdr.tail + FILE_DATA_OFFSET;
        nregions = 2;
    }

    for ( int i = 0; i < nregions; i++) {
        _pread(_fd, regions[i].data, regions[i].size, regions[i].index);
        _saved_size += regions[i].size;
    }
    _tail = hdr.tail;
    _head = hdr.head;

    // There might have been an uncommitted block.
    BlockHeader* bhdr = reinterpret_cast<BlockHeader*>(_ptr+_head);
    bhdr->size = 0;
    bhdr->id = 0;
    bhdr->state = HEAD;

    _closed = false;
}

void Queue::Close() {
    Close(true);
}

void Queue::Close(bool save)
{
    std::unique_lock<std::mutex> lock(_lock);
    _closed = true;

    if (_path.empty()) {
        return;
    }

    if (save) {
        save_locked(lock);
    }

    // Wait for any active save to complete
    _cond.wait(lock, [this]() { return !_save_active; });

    close(_fd);
    _fd = -1;

    _cond.notify_all();
}

void Queue::Save() {
    std::unique_lock<std::mutex> lock(_lock);

    if (_path.empty()) {
        return;
    }

    if (_closed) {
        return;
    }

    save_locked(lock);
}

void Queue::Interrupt() {
    std::unique_lock<std::mutex> lock(_lock);
    _int_id++;
    _cond.notify_all();
}

// Assumes queue is locked
void Queue::save_locked(std::unique_lock<std::mutex>& lock)
{
    if (_fd < 0) {
        throw std::runtime_error("Queue::Save: Queue not opened");
    }

    if (_save_active) {
        return;
    }

    _save_active = true;

    FileHeader before;
    FileHeader after;

    before.magic = HEADER_MAGIC;
    before.version = VERSION;
    before.size = _file_size;
    before.tail = _tail;
    before.next_id = _next_id;

    after.magic = HEADER_MAGIC;
    after.version = VERSION;
    after.size = _file_size;
    after.next_id = _next_id;
    after.tail = _tail;
    after.head = _head;

    struct _region regions[2];
    int nregions = 0;

    if (_tail <= _head) {
        /* [----<tail>====<head>----] */
        if (_head-_tail > _saved_size) {
            regions[0].index = _tail + _saved_size + FILE_DATA_OFFSET;
            regions[0].size = _head-_tail - _saved_size;
            regions[0].data = _ptr + _tail + _saved_size;
            nregions = 1;
        }
        before.head = _tail + _saved_size;
    } else {
        /* [====<head>----<tail>====] */
        uint64_t tail_size = _data_size-_tail;
        if (tail_size > _saved_size) {
            regions[0].index = _tail + _saved_size + FILE_DATA_OFFSET;
            regions[0].size = tail_size - _saved_size;
            regions[0].data = _ptr + _tail + _saved_size;
            nregions = 1;
            if (_head > 0) {
                regions[1].index = FILE_DATA_OFFSET;
                regions[1].size = _head;
                regions[1].data = _ptr;
                nregions = 2;
            }
            before.head = _tail + _saved_size;
        } else {
            uint64_t head_save_size = _saved_size - tail_size;
            if (head_save_size < _head) {
                regions[0].index = head_save_size + FILE_DATA_OFFSET;
                regions[0].size = _head - head_save_size;
                regions[0].data = _ptr + head_save_size;
                nregions = 1;
            }
            before.head = head_save_size;
        }
    }

    lock.unlock();

    int64_t save_size = 0;

    if (nregions > 0) {
        _pwrite(_fd, &before, sizeof(FileHeader), 0);

        for (int i = 0; i < nregions; i++) {
            _pwrite(_fd, regions[i].data, regions[i].size, regions[i].index);
            save_size += regions[i].size;
        }
    }

    _pwrite(_fd, &after, sizeof(FileHeader), 0);

    lock.lock();

    _saved_size += save_size;
    _save_active = false;

    _cond.notify_all();
}

// Assumes queue is locked
uint64_t Queue::unsaved_size()
{
    uint64_t queue_size = 0;
    if (_tail <= _head) {
        queue_size = _head - _tail;
    } else {
        queue_size = _head + (_data_size - _tail);
    }

    if (queue_size > _saved_size) {
        return queue_size - _saved_size;
    } else {
        return 0;
    }
}

void Queue::Reset() {
    std::unique_lock<std::mutex> lock(_lock);

    _head = 0;
    _tail = 0;
    _int_id++;

    FileHeader after;

    after.magic = HEADER_MAGIC;
    after.version = VERSION;
    after.size = _file_size;
    after.next_id = _next_id;
    after.tail = _tail;
    after.head = _head;

    _pwrite(_fd, &after, sizeof(FileHeader), 0);

    memset(_ptr, 0, _data_size);

    _saved_size = 0;

    _pwrite(_fd, _ptr+FILE_DATA_OFFSET, _data_size, FILE_DATA_OFFSET);

    _cond.notify_all();
}

void Queue::Autosave(uint64_t min_save, int max_delay)
{
    if (_path.empty()) {
        return;
    }
    std::unique_lock<std::mutex> lock(_lock);
    while (!_closed) {
        _cond.wait_for(lock, std::chrono::milliseconds(max_delay),
                       [this, min_save]() { return _closed || this->unsaved_size() >= min_save; });
        if (!_closed) {
            lock.unlock();
            Save();
            lock.lock();
        }
    }
}

// Assumes queue is locked
bool Queue::check_fit(size_t size)
{
    size_t block_size = sizeof(BlockHeader)+size;
    if (_tail <= _head) {
        /* [----<tail>====<head>----] */
        if (_data_size-_head < block_size+sizeof(BlockHeader)) {
            // Would wrap
            return block_size+sizeof(BlockHeader) < _tail;
        } else {
            return true;
        }
    } else {
        /* [====<head>----<tail>====] */
        return (_head+sizeof(BlockHeader)*2+block_size <= _tail);
    }
}

int Queue::allocate_locked(std::unique_lock<std::mutex>& lock, void** ptr, size_t size)
{
    assert(ptr != nullptr);

    if (size+sizeof(BlockHeader) > _data_size-sizeof(BlockHeader)) {
        throw std::runtime_error("Queue: message size exceeds queue size");
    }

    uint64_t orig_tail = _tail;

    while(!check_fit(size)) {
        BlockHeader* thdr = reinterpret_cast<BlockHeader*>(_ptr+_tail);
        _tail += thdr->size + sizeof(BlockHeader);
        thdr = reinterpret_cast<BlockHeader*>(_ptr+_tail);

        if (thdr->state == WRAP) {
            _tail = 0;
        }
    }

    uint64_t overwrite_size = 0;

    if (orig_tail <= _tail) {
        /* [----<tail>====<idx>----] */
        overwrite_size = _tail - orig_tail;
    } else {
        /* [====<idx>----<tail>====] */
        overwrite_size = _tail + (_data_size - orig_tail);
    }

    if (overwrite_size > 0) {
        if (_saved_size > overwrite_size) {
            _saved_size -= overwrite_size;
        } else {
            _saved_size = 0;
        }
    }

    size_t block_size = size+sizeof(BlockHeader);
    BlockHeader* hdr;
    if (_tail <= _head) {
        /* [----<tail>====<head>----] */
        if (_head+block_size+sizeof(BlockHeader) > _data_size) {
            hdr = reinterpret_cast<BlockHeader*>(_ptr+_head);
            if (hdr->state == UNCOMMITTED_PUT) {
                memcpy(_ptr+sizeof(BlockHeader), _ptr+_head+sizeof(BlockHeader), hdr->size);
            }
            hdr->size = 0;
            hdr->id = 0;
            hdr->state = WRAP;
            _head = 0;
        }
    }

    hdr = reinterpret_cast<BlockHeader*>(_ptr+_head);
    hdr->size = size;
    hdr->id = 0;
    hdr->state = UNCOMMITTED_PUT;
    *ptr = _ptr+_head+sizeof(BlockHeader);

    return 1;
}

int Queue::commit_locked()
{
    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+_head);
    size_t block_size = hdr->size+sizeof(BlockHeader);

    hdr->state = ITEM;
    hdr->id = _next_id;

    _head += block_size;
    _next_id++;

    hdr = reinterpret_cast<BlockHeader*>(_ptr+_head);
    hdr->size = 0;
    hdr->id = 0;
    hdr->state = HEAD;

    _cond.notify_all();

    return 1;
}

int Queue::Put(void* ptr, size_t size)
{
    assert(ptr != nullptr);
    if (size > MAX_ITEM_SIZE) {
        return BUFFER_TOO_SMALL;
    }

    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    void * data;
    auto ret = allocate_locked(lock, &data, size);

    if (ret != 1) {
        return ret;
    }

    memcpy(data, ptr, size);

    return commit_locked();
}

// Assumes queue is locked
bool Queue::have_data(uint64_t *index)
{
    assert(index != nullptr);
    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+(*index));
    if (hdr->state == WRAP) {
        *index = 0;
    }

    return this->_head != *index;
}

int Queue::Get(QueueCursor last, void*ptr, size_t* size, QueueCursor *item_cursor, int32_t milliseconds) {
    assert(ptr != nullptr);
    assert(size != nullptr);
    assert(item_cursor != nullptr);

    if (*size == 0) {
        return BUFFER_TOO_SMALL;
    }

    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    uint64_t index = last.index;

    if (last.IsHead()) {
        index = _head;
    } else if (last.IsTail() || index > _data_size-sizeof(BlockHeader)) {
        index = _tail;
    } else {
        if (last.id >= _next_id) {
            index = _head;
        } else if (last.id < reinterpret_cast<BlockHeader*>(_ptr+_tail)->id) {
            index = _tail;
        } else {
            BlockHeader *hdr = reinterpret_cast<BlockHeader *>(_ptr + index);
            if (hdr->id != last.id || hdr->state != ITEM) {
                index = _tail;
            } else {
                index += sizeof(BlockHeader) + hdr->size;
            }
        }
    }
    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+index);
    if (hdr->state == WRAP) {
        index = 0;
    }

    auto int_id = _int_id;
    if (milliseconds > 0) {
        if (!_cond.wait_for(lock, std::chrono::milliseconds(milliseconds),
                            [this,&index,&int_id]() { return _closed || have_data(&index) || _int_id != int_id; })) {
            return TIMEOUT;
        } else if (_closed) {
            return CLOSED;
        } else if (int_id != _int_id) {
            return INTERRUPTED;
        }
    } else if (milliseconds < 0) {
        _cond.wait(lock, [this,&index,&int_id]() { return _closed || have_data(&index) || _int_id != int_id; });
        if (_closed) {
            return CLOSED;
        } else if (int_id != _int_id) {
            return INTERRUPTED;
        }
    } else if (!have_data(&index)) {
        return TIMEOUT;
    }

    hdr = reinterpret_cast<BlockHeader*>(_ptr+index);

    if (hdr->size > *size) {
        return BUFFER_TOO_SMALL;
    }

    memcpy(ptr, _ptr+index+sizeof(BlockHeader), hdr->size);
    *size = hdr->size;
    item_cursor->id = hdr->id;
    item_cursor->index = index;

    return 1;
}
