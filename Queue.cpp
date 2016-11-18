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

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
}

struct BlockHeader {
    uint64_t size;
    queue_msg_type_t msg_type;
    int64_t id;
};

#define FILE_DATA_OFFSET 512
struct FileHeader {
    uint64_t magic;
    uint64_t version;
    uint64_t size;
    uint64_t widx;
    uint64_t ridx;
    int64_t next_id;
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
                throw std::system_error(errno, std::system_category());
            }
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
                throw std::system_error(errno, std::system_category());
            }
        } else {
            ptr = reinterpret_cast<char*>(ptr)+nw;
            size -= nw;
            offset += nw;
        }
    }
}

Queue::Queue(size_t size):
        _path(), _size(size), _fd(-1), _next_id(1), _closed(true)
{
    if (_size < MIN_QUEUE_SIZE) {
        _size = MIN_QUEUE_SIZE;
    }
    _ptr = new char[_size];

    _ridx = _widx = _index = _saved_size = 0;
}

Queue::Queue(const std::string& path, size_t size):
        _path(path), _size(size), _fd(-1), _next_id(1), _closed(true)
{
    if (_size < MIN_QUEUE_SIZE) {
        _size = MIN_QUEUE_SIZE;
    }
    _ptr = new char[_size];
}

Queue::~Queue()
{
    delete[] _ptr;
}

void Queue::Open()
{
    if (_path.empty()) {
        _closed = false;
        return;
    }

    _ridx = _widx = _index = _saved_size = 0;

    // TODO: Add mkdir

    _fd = open(_path.c_str(), O_RDWR|O_CREAT|O_SYNC, 0600);
    if (_fd < 0) {
        throw std::system_error(errno, std::system_category());
    }

    struct stat st;
    if (fstat(_fd, &st) < 0) {
        throw std::system_error(errno, std::system_category());
    }

    bool new_file = false;
    if (st.st_size == 0) {
        new_file = true;
    }

    if (st.st_size < FILE_DATA_OFFSET) {
        if (ftruncate(_fd, FILE_DATA_OFFSET) != 0) {
            throw std::system_error(errno, std::system_category());
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
                    "Queue file version mismatch, discarding existing contents: Expected version %d, found version %d",
                    VERSION, hdr.version);
            hdr.size = _size;
        }
    } else {
        hdr.size = 0;
        hdr.ridx = 0;
        hdr.widx = 0;
        hdr.next_id = 1;
    }

    _next_id = hdr.next_id;

    if (hdr.ridx == hdr.widx) {
        // There's no data in the save file.
        if (hdr.size != _size) {
            // The save file size needs to be changed
            if (ftruncate(_fd, _size) != 0) {
                throw std::system_error(errno, std::system_category());
            }
            // Save will update the size of the file in the header.
            _closed = false;
            Save();
        }
        _closed = false;
        return;
    }

    if (hdr.size > _size) {
        // The new queue size is smaller than the save file size
        // Make sure the data saved in the save file will fit in the new queue.
        if (hdr.ridx < hdr.widx) {
            if (hdr.widx-hdr.ridx > _size) {
                throw std::runtime_error("Queue::Open: Saved data size exceeds requested queue size");
            }
        } else {
            if (hdr.widx+(hdr.size-hdr.ridx) > _size) {
                throw std::runtime_error("Queue::Open: Saved data size exceeds requested queue size");
            }
        }
    }

    if (hdr.size != _size) {
        // The size of the save file has changed.
        // The data needs to be relocated.
        if (hdr.ridx < hdr.widx) {
            regions[0].data = _ptr;
            regions[0].size = hdr.widx - hdr.ridx;
            regions[0].index = hdr.ridx + FILE_DATA_OFFSET;
            nregions = 1;
        } else {
            regions[0].data = _ptr;
            regions[0].size = hdr.size - hdr.ridx;
            regions[0].index = hdr.ridx + FILE_DATA_OFFSET;
            regions[1].data = _ptr + regions[0].size;
            regions[1].size = hdr.widx;
            regions[1].index = FILE_DATA_OFFSET;
            nregions = 2;
        }
        for ( int i = 0; i < nregions; i++) {
            _pread(_fd, regions[i].data, regions[i].size, regions[i].index);
            _saved_size += regions[i].size;
        }
        _ridx = 0;
        _index = 0;
        _widx = _saved_size;
        if (ftruncate(_fd, _size) != 0) {
            throw std::system_error(errno, std::system_category());
        }
        _saved_size = 0;
        _closed = false;
        Save();
    } else {
        // The save file is the same size as the requested queue size
        // Load the data in it's current location.
        if (hdr.ridx < hdr.widx) {
            regions[0].data = _ptr+hdr.ridx;
            regions[0].size = hdr.widx - hdr.ridx;
            regions[0].index = hdr.ridx + FILE_DATA_OFFSET;
            nregions = 1;
        } else {
            regions[0].data = _ptr;
            regions[0].size = hdr.widx;
            regions[0].index = FILE_DATA_OFFSET;
            regions[1].data = _ptr+hdr.ridx;
            regions[1].size = hdr.size - hdr.ridx;
            regions[1].index = hdr.ridx + FILE_DATA_OFFSET;
            nregions = 2;
        }
        for ( int i = 0; i < nregions; i++) {
            _pread(_fd, regions[i].data, regions[i].size, regions[i].index);
            _saved_size += regions[i].size;
        }
        _ridx = hdr.ridx;
        _widx = hdr.widx;
        _index = _ridx;
    }

    // There might have been an uncommitted block.
    BlockHeader* bhdr = reinterpret_cast<BlockHeader*>(_ptr+_widx);
    bhdr->size = 0;
    bhdr->id = HEAD;

    _closed = false;
}

void Queue::Close()
{
    std::unique_lock<std::mutex> lock(_lock);
    _closed = true;

    if (_path.empty()) {
        return;
    }

    save_locked(lock);

    close(_fd);
    _fd = -1;
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

// Assumes queue is locked
void Queue::save_locked(std::unique_lock<std::mutex>& lock)
{
    if (_fd < 0) {
        throw std::runtime_error("Queue::Save: Queue not opened");
    }

    FileHeader before;
    FileHeader after;

    before.magic = HEADER_MAGIC;
    before.version = VERSION;
    before.size = _size;
    before.ridx = _ridx;
    before.next_id = _next_id;

    after.magic = HEADER_MAGIC;
    after.version = VERSION;
    after.size = _size;
    after.next_id = _next_id;
    after.ridx = _ridx;
    after.widx = _widx;

    struct _region regions[2];
    int nregions = 0;

    if (_saved_size < 0) {
        _saved_size = 0;
    }

    if (_ridx <= _widx) {
        /* [----<ridx>====<widx>----] */
        if (_widx-_ridx > _saved_size) {
            regions[0].index = _ridx + _saved_size + FILE_DATA_OFFSET;
            regions[0].size = _widx-_ridx - _saved_size;
            regions[0].data = _ptr + _ridx + _saved_size;
            nregions = 1;
        }
        before.widx = _ridx + _saved_size;
    } else {
        /* [====<widx>----<ridx>====] */
        uint64_t tail_size = _size-_ridx;
        if (tail_size > _saved_size) {
            regions[0].index = _ridx + _saved_size + FILE_DATA_OFFSET;
            regions[0].size = tail_size - _saved_size;
            regions[0].data = _ptr + _ridx + _saved_size;
            nregions = 1;
            if (_widx > 0) {
                regions[1].index = FILE_DATA_OFFSET;
                regions[1].size = _widx;
                regions[1].data = _ptr;
                nregions = 2;
            }
            before.widx = _ridx + _saved_size;
        } else {
            uint64_t head_save_size = _saved_size - tail_size;
            if (head_save_size < _widx) {
                regions[0].index = head_save_size + FILE_DATA_OFFSET;
                regions[0].size = _widx - head_save_size;
                regions[0].data = _ptr + head_save_size;
                nregions = 1;
            }
            before.widx = head_save_size;
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
}

// Assumes queue is locked
uint64_t Queue::unsaved_size()
{
    uint64_t queue_size = 0;
    if (_ridx <= _widx) {
        queue_size = _widx - _ridx;
    } else {
        queue_size = _widx + (_size - _ridx);
    }

    if (queue_size > _saved_size) {
        return queue_size - _saved_size;
    } else {
        return 0;
    }
}

// Assumes queue is locked
bool Queue::have_data()
{
    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+_index);
    if (hdr->id == WRAP) {
        _index = 0;
    }

    return this->_widx != this->_index;
}

// Assumes queue is locked
bool Queue::check_fit(size_t size)
{
    size_t block_size = sizeof(BlockHeader)+size;
    if (_ridx <= _widx) {
        /* [----<ridx>====<widx>----] */
        if (_size-_widx < block_size+sizeof(BlockHeader)) {
            return block_size+sizeof(BlockHeader) < _ridx;
        } else {
            return true;
        }
    } else {
        /* [====<widx>----<ridx>====] */
        return (_widx+sizeof(BlockHeader)+block_size <= _ridx);
    }
}

void Queue::Autosave(uint64_t min_save, int max_delay)
{
    if (_path.empty()) {
        return;
    }
    std::unique_lock<std::mutex> lock(_lock);
    while (!_closed) {
        if (!_cond.wait_for(lock, std::chrono::milliseconds(max_delay),
                            [this, min_save]() { return _closed || this->unsaved_size() >= min_save; })) {
            lock.unlock();
            Save();
            lock.lock();
        } else if (!_closed) {
            lock.unlock();
            Save();
            lock.lock();
        }
    }
}

int Queue::allocate_locked(std::unique_lock<std::mutex>& lock, void** ptr, size_t size, bool overwrite, int32_t milliseconds)
{
    assert(ptr != nullptr);

    if (size+sizeof(BlockHeader) > _size) {
        throw std::runtime_error("Queue: message size exceeds queue size");
    }

    if (overwrite) {
        uint64_t orig_ridx = _ridx;

        while(!check_fit(size)) {
            BlockHeader* rhdr = reinterpret_cast<BlockHeader*>(_ptr+_ridx);
            BlockHeader* ihdr = reinterpret_cast<BlockHeader*>(_ptr+_index);
            _ridx += rhdr->size + sizeof(BlockHeader);
            rhdr = reinterpret_cast<BlockHeader*>(_ptr+_ridx);

            if (rhdr->id == WRAP) {
                _ridx = 0;
                rhdr = reinterpret_cast<BlockHeader*>(_ptr);
            }

            if (ihdr->id != HEAD && ihdr->id < rhdr->id) {
                _index = _ridx;
            }
        }

        uint64_t overwrite_size = 0;

        if (orig_ridx <= _ridx) {
            /* [----<ridx>====<idx>----] */
            overwrite_size = _ridx - orig_ridx;
        } else {
            /* [====<idx>----<ridx>====] */
            overwrite_size = _ridx + (_size - orig_ridx);
        }

        if (overwrite_size > 0) {
            _saved_size -= overwrite_size;
        }
    } else {
        if (milliseconds > 0) {
            if (!_cond.wait_for(lock, std::chrono::milliseconds(milliseconds),
                                [this, size]() { return _closed || check_fit(size); })) {
                return TIMEOUT;
            } else if (_closed) {
                return CLOSED;
            }
        } else if (milliseconds < 0) {
            _cond.wait(lock, [this, size]() { return _closed || check_fit(size); });
            if (_closed) {
                return CLOSED;
            }
        } else if (!check_fit(size)) {
            return TIMEOUT;
        }
    }

    size_t block_size = size+sizeof(BlockHeader);
    BlockHeader* hdr;
    if (_ridx <= _widx) {
        /* [----<ridx>====<widx>----] */
        if (_widx+block_size+sizeof(BlockHeader) > _size) {
            hdr = reinterpret_cast<BlockHeader*>(_ptr+_widx);
            if (hdr->id == UNCOMMITTED_PUT) {
                if (hdr->size > size) {
                    hdr->size = size;
                }
                memcpy(_ptr+sizeof(BlockHeader), _ptr+_widx+sizeof(BlockHeader), hdr->size);
                BlockHeader* whdr = reinterpret_cast<BlockHeader*>(_ptr);
                whdr->size = size;
                whdr->id = UNCOMMITTED_PUT;
            }
            hdr->size = 0;
            hdr->id = WRAP;
            _widx = 0;
        }
    }

    hdr = reinterpret_cast<BlockHeader*>(_ptr+_widx);
    hdr->size = size;
    hdr->id = UNCOMMITTED_PUT;
    *ptr = _ptr+_widx+sizeof(BlockHeader);

    return 1;
}

int Queue::Allocate(void** ptr, size_t size, bool overwrite, int32_t milliseconds)
{
    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    return allocate_locked(lock, ptr, size, overwrite, milliseconds);
}

int Queue::commit_locked(queue_msg_type_t msg_type)
{
    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+_widx);
    size_t block_size = hdr->size+sizeof(BlockHeader);

    hdr->msg_type = msg_type;
    hdr->id = _next_id;

    _widx += block_size;
    _next_id++;

    hdr = reinterpret_cast<BlockHeader*>(_ptr+_widx);
    hdr->size = 0;
    hdr->id = HEAD;

    _cond.notify_all();

    return 1;
}

int Queue::Commit(queue_msg_type_t msg_type) {
    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    return commit_locked(msg_type);
}

int Queue::Rollback()
{
    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+_widx);
    hdr->size = 0;
    hdr->id = HEAD;

    return 1;
}

int Queue::Put(void* ptr, size_t size, queue_msg_type_t msg_type, bool overwrite, int32_t milliseconds)
{
    assert(ptr != nullptr);

    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    void * data;
    auto ret = allocate_locked(lock, &data, size, overwrite, milliseconds);

    if (ret != 1) {
        return ret;
    }

    memcpy(data, ptr, size);

    return commit_locked(msg_type);
}

// Get the id and size of the next message
// Return slot Id on success, 0 on Timeout, -1 if queue closed
int64_t Queue::Peek(size_t* size, queue_msg_type_t* msg_type, int32_t milliseconds)
{
    assert(size != nullptr);
    assert(msg_type != nullptr);

    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    if (milliseconds > 0) {
        if (!_cond.wait_for(lock, std::chrono::milliseconds(milliseconds),
                            [this]() { return _closed || have_data(); })) {
            return TIMEOUT;
        } else if (_closed) {
            return CLOSED;
        }
    } else if (milliseconds < 0) {
        _cond.wait(lock, [this]() { return _closed || have_data(); });
        if (_closed) {
            return CLOSED;
        }
    } else if (!have_data()) {
        return TIMEOUT;
    }

    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+_index);
    *size = hdr->size;
    *msg_type = hdr->msg_type;

    return hdr->id;
}

// Try to get the message previously peeked
// Return 1 on success, 0 on if msg has already been deleted, -1 if queue closed
int Queue::TryGet(int64_t msg_id, void* ptr, size_t size, bool auto_checkpoint)
{
    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+_index);
    if (hdr->id != msg_id) {
        return 0;
    }

    char* data = _ptr+_index+sizeof(BlockHeader);
    _index += sizeof(BlockHeader)+hdr->size;

    if (hdr->size > size) {
        return BUFFER_TOO_SMALL;
    }

    memcpy(ptr, data, hdr->size);

    // Make sure _index is wrapped before we return.
    if (reinterpret_cast<BlockHeader*>(_ptr+_index)->id == WRAP) {
        _index = 0;
    }

    if (auto_checkpoint) {
        uint64_t checkpoint_size = 0;

        if (_ridx <= _index) {
            /* [----<ridx>====<idx>----] */
            checkpoint_size = _index - _ridx;
        } else {
            /* [====<idx>----<ridx>====] */
            checkpoint_size = _index + (_size - _ridx);
        }

        _ridx = _index;

        if (checkpoint_size > 0) {
            _saved_size -= checkpoint_size;
        }
    }

    return 1;

}

int64_t Queue::Get(void*ptr, size_t* size, queue_msg_type_t* msg_type, bool auto_checkpoint, int32_t milliseconds)
{
    assert(ptr != nullptr);
    assert(size != nullptr);
    assert(msg_type != nullptr);

    if (*size == 0) {
        return BUFFER_TOO_SMALL;
    }

    bool bts = false;
    int64_t id;

    int ret = ZeroCopyGet(milliseconds, auto_checkpoint, [&bts,&id,ptr,size,msg_type](int64_t msg_id, void* zcptr, size_t zcsize, queue_msg_type_t zcmsg_type) -> bool {
        if (zcsize > *size) {
            bts = true;
            return false;
        }

        id = msg_id;
        memcpy(ptr, zcptr, zcsize);
        *msg_type = zcmsg_type;
        *size = zcsize;

        return true;
    });

    if (bts) {
        return BUFFER_TOO_SMALL;
    }

    if (ret != 1) {
        return ret;
    }

    return id;
}

int Queue::ZeroCopyGet(int32_t milliseconds, bool auto_checkpoint,
                       std::function<bool(int64_t msg_id, void* ptr, size_t size, queue_msg_type_t msg_type)> fn)
{
    assert(fn);

    std::unique_lock<std::mutex> lock(_lock);

    if (_closed) {
        return CLOSED;
    }

    if (milliseconds > 0) {
        if (!_cond.wait_for(lock, std::chrono::milliseconds(milliseconds),
                            [this]() { return _closed || have_data(); })) {
            return TIMEOUT;
        } else if (_closed) {
            return CLOSED;
        }
    } else if (milliseconds < 0) {
        _cond.wait(lock, [this]() { return _closed || have_data(); });
        if (_closed) {
            return CLOSED;
        }
    } else if (!have_data()) {
        return TIMEOUT;
    }

    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+_index);

    char* data = _ptr+_index+sizeof(BlockHeader);

    if (!fn(hdr->id, data, hdr->size, hdr->msg_type)) {
        return TIMEOUT;
    }

    _index += sizeof(BlockHeader)+hdr->size;

    // Make sure _index is wrapped before we return.
    if (reinterpret_cast<BlockHeader*>(_ptr+_index)->id == WRAP) {
        _index = 0;
    }

    if (auto_checkpoint) {
        uint64_t checkpoint_size = 0;

        if (_ridx <= _index) {
            /* [----<ridx>====<idx>----] */
            checkpoint_size = _index - _ridx;
        } else {
            /* [====<idx>----<ridx>====] */
            checkpoint_size = _index + (_size - _ridx);
        }

        _ridx = _index;

        if (checkpoint_size > 0) {
            _saved_size -= checkpoint_size;
        }
    }

    return 1;
}

void Queue::Checkpoint(uint64_t id)
{
    std::lock_guard<std::mutex> lock(_lock);

    if (_closed) {
        return;
    }

    uint64_t idx = _ridx;
    BlockHeader* hdr = reinterpret_cast<BlockHeader*>(_ptr+idx);
    if (hdr->id == WRAP) {
        idx = 0;
        hdr = reinterpret_cast<BlockHeader*>(_ptr+idx);
    }

    if (hdr->id > id || id >= _next_id) {
        throw std::runtime_error("Queue::Checkpoint: Invalid id");
    }

    while (hdr->id != HEAD && hdr->id != UNCOMMITTED_PUT && hdr->id < id) {
        if (hdr->id != WRAP) {
            idx += hdr->size + sizeof(BlockHeader);
        } else {
            idx = 0;
        }
        hdr = reinterpret_cast<BlockHeader*>(_ptr+idx);
    }

    if (hdr->id != id) {
        throw std::runtime_error("Queue::Checkpoint: Invalid id");
    }

    idx += hdr->size + sizeof(BlockHeader);
    hdr = reinterpret_cast<BlockHeader*>(_ptr+idx);
    if (hdr->id == WRAP) {
        idx = 0;
    }

    uint64_t checkpoint_size = 0;

    if (_ridx <= idx) {
        /* [----<ridx>====<idx>----] */
        checkpoint_size = idx - _ridx;
    } else {
        /* [====<idx>----<ridx>====] */
        checkpoint_size = idx + (_size - _ridx);
    }

    _ridx = idx;

    if (checkpoint_size > 0) {
        _saved_size -= checkpoint_size;
    }

    _cond.notify_all();
}

void Queue::Revert()
{
    std::lock_guard<std::mutex> lock(_lock);

    if (_closed) {
        return;
    }

    _index = _ridx;
}
