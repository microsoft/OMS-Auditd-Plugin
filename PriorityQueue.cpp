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

#include "FileUtils.h"

#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <climits>
#include <unordered_set>

/**********************************************************************************************************************
 ** QueueItem
 *********************************************************************************************************************/

/**********************************************************************************************************************
 ** QueueItemBucket
 *********************************************************************************************************************/

void QueueItemBucket::Put(std::shared_ptr<QueueItem> item) {
    std::unique_lock<std::mutex> lock(_mutex);

    _items.emplace(item->Sequence(), item);
    _size += item->Size();
    if (_min_seq == 0 || _min_seq > item->Sequence()) {
        _min_seq = item->Sequence();
    }
    if (_max_seq < item->Sequence()) {
        _max_seq = item->Sequence();
    }
}

std::shared_ptr<QueueItem> QueueItemBucket::Get(uint64_t seq) {
    std::unique_lock<std::mutex> lock(_mutex);

    auto itr = _items.lower_bound(seq);
    if (itr != _items.end()) {
        return itr->second;
    }
    return nullptr;
}

/**********************************************************************************************************************
 ** QueueFile
 *********************************************************************************************************************/

std::shared_ptr<QueueFile> QueueFile::Open(const std::string& path) {
    int fd = open(path.c_str(), O_CLOEXEC|O_RDONLY);
    if (fd < 0) {
        Logger::Error("QueueFile(%s): Failed to open: %s", path.c_str(), std::strerror(errno));
        return nullptr;
    }
    FileHeader header;

    int ret = read(fd, &header, sizeof(FileHeader));
    if (ret < 0 || ret != sizeof(FileHeader)) {
        if (ret < 0) {
            Logger::Error("QueueFile(%s): Failed to read header: %s", path.c_str(), std::strerror(errno));
        } else {
            Logger::Error("QueueFile(%s): Invalid or corrupted file", path.c_str());
        }
        close(fd);
        if (unlink(path.c_str()) != 0) {
            if (errno != ENOENT) {
                Logger::Error("QueueFile(%s)::Open: Failed to remove invalid file: %s", path.c_str(), std::strerror(errno));
            }
        }
        return nullptr;
    }
    close(fd);

    if (header._magic != MAGIC || header._version != FILE_VERSION) {
        Logger::Error("QueueFile(%s): Invalid or corrupted file", path.c_str());
        if (unlink(path.c_str()) != 0) {
            if (errno != ENOENT) {
                Logger::Error("QueueFile(%s)::Open: Failed to remove invalid file: %s", path.c_str(), std::strerror(errno));
            }
        }
        return nullptr;
    }

    return std::shared_ptr<QueueFile>(new QueueFile(path, header));
}

std::shared_ptr<QueueItemBucket> QueueFile::OpenBucket() {
    std::lock_guard<std::mutex> lock(_mutex);

    auto ptr = _bucket.lock();

    if (!ptr) {
        auto ptr = Read();
        _bucket = ptr;
        return ptr;
    }
    return ptr;
}

bool QueueFile::Save() {
    auto bucket = _bucket.lock();

    if (!bucket) {
        Logger::Warn("QueueFile(%s)::Save: bucket is missing: nothing to save", _path.c_str());
        return true;
    }

    int fd = open(_path.c_str(), O_CLOEXEC|O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (fd < 0) {
        Logger::Error("QueueFile(%s)::Save: Failed to open: %s", _path.c_str(), std::strerror(errno));
        return false;
    }

    auto& items = bucket->Items();
    std::vector<IndexEntry> index;
    index.reserve(items.size());

    uint32_t next_offset = sizeof(FileHeader)+(sizeof(IndexEntry)*items.size());
    for (auto& i : items) {
        index.emplace_back(i.second->Sequence(), next_offset, i.second->Size());
        next_offset += i.second->Size();
    }

    uint32_t file_size = sizeof(FileHeader)+(sizeof(IndexEntry)*items.size())+bucket->Size();

    FileHeader header(file_size, _priority, items.size(), bucket->MinSequence(), bucket->MaxSequence());
    struct iovec vec[2+header._num_items];
    vec[0].iov_base = &header;
    vec[0].iov_len = sizeof(header);
    vec[1].iov_base = &index[0];
    vec[1].iov_len = index.size() * sizeof(IndexEntry);
    int num_vec = 2;
    for (auto& i : items) {
        vec[num_vec].iov_base = i.second->Data();
        vec[num_vec].iov_len = i.second->Size();
        num_vec += 1;
    }
    int num_vec_written = 0;
    while (num_vec_written < num_vec) {
        int nvec = num_vec - num_vec_written;
        if (nvec > IOV_MAX) {
            nvec = IOV_MAX;
        }
        size_t wsize = 0;
        for (int i = num_vec_written; i < num_vec_written+nvec; i++) {
            wsize += vec[i].iov_len;
        }
        int ret = writev(fd, &vec[num_vec_written], nvec);
        if (ret < 0 || ret != wsize) {
            if (ret < 0) {
                Logger::Error("QueueFile(%s)::Save: Failed to write file: %s", _path.c_str(), std::strerror(errno));
            } else {
                Logger::Error("QueueFile(%s)::Save: Failed to write file: fewer bytes written (%d) than expected (%ld)", _path.c_str(), ret, wsize);
            }

            close(fd);

            if (unlink(_path.c_str()) != 0) {
                Logger::Error("QueueFile(%s)::Save: Failed to remove incomplete file: %s", _path.c_str(), std::strerror(errno));
            }
            return false;
        }
        num_vec_written += nvec;
    }
    close(fd);

    _saved = true;

    return true;
}

bool QueueFile::Remove() {
    if (unlink(_path.c_str()) != 0) {
        if (errno != ENOENT) {
            Logger::Error("QueueFile(%s)::Save: Failed to remove file: %s", _path.c_str(), std::strerror(errno));
            return false;
        }
    }
    return true;
}

std::shared_ptr<QueueItemBucket> QueueFile::Read() {
    std::vector<IndexEntry> index;
    std::map<uint64_t, std::shared_ptr<QueueItem>> items;

    int fd = open(_path.c_str(), O_CLOEXEC|O_RDONLY);
    if (fd < 0) {
        Logger::Error("QueueFile(%s)::Read: Failed to open: %s", _path.c_str(), std::strerror(errno));
        return nullptr;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        Logger::Error("QueueFile(%s)::Read: Failed to stat: %s", _path.c_str(), std::strerror(errno));
        close(fd);
        return nullptr;
    }

    // Read header
    FileHeader header;
    int ret = read(fd, &header, sizeof(FileHeader));
    if (ret != sizeof(FileHeader)) {
        if (ret < 0) {
            Logger::Error("QueueFile(%s)::Read: Failed to read header: %s", _path.c_str(), std::strerror(errno));
        } else {
            Logger::Error("QueueFile(%s)::Read: Invalid or corrupted file: Bad Header", _path.c_str());
        }
        close(fd);
        return nullptr;
    }

    // Verify header
    if (header._magic != MAGIC) {
        Logger::Error("QueueFile(%s)::Read: Invalid or corrupted file: Invalid magic: expected %16lX, found %16lX", _path.c_str(), MAGIC, header._magic);
        close(fd);
        return nullptr;
    }
    if (header._version != FILE_VERSION) {
        Logger::Error("QueueFile(%s)::Read: Invalid or corrupted file: Invalid version: expected %d, found %d", _path.c_str(), FILE_VERSION, header._version);
        close(fd);
        return nullptr;
    }
    if (header._file_size != st.st_size) {
        Logger::Error("QueueFile(%s)::Read: Invalid or corrupted file: File size (%ld) does not match header (%d)", _path.c_str(), st.st_size, header._file_size);
        close(fd);
        return nullptr;
    }

    // Read index
    index.resize(header._num_items);
    ret = read(fd, &index[0], sizeof(IndexEntry)*header._num_items);
    if (ret != sizeof(IndexEntry)*header._num_items) {
        if (ret < 0) {
            Logger::Error("QueueFile(%s)::Read: Failed to read index: %s", _path.c_str(), std::strerror(errno));
        } else {
            Logger::Error("QueueFile(%s)::Read: Invalid or corrupted file: Bad Index", _path.c_str());
        }
        close(fd);
        return nullptr;
    }

    // Prepare iovec for reading data
    struct iovec vec[header._num_items];
    int idx = 0;
    size_t num_bytes = 0;
    for (auto& i : index) {
        auto item = std::shared_ptr<QueueItem>(new QueueItem(_priority, i._seq, i._size));
        items.emplace(item->Sequence(), item);
        vec[idx].iov_len = i._size;
        vec[idx].iov_base = item->Data();
        num_bytes += i._size;
        idx += 1;
    }

    // Read data
    int num_vec_read = 0;
    while (num_vec_read < header._num_items) {
        int nvec = header._num_items - num_vec_read;
        if (nvec > IOV_MAX) {
            nvec = IOV_MAX;
        }
        size_t rsize = 0;
        for (int i = num_vec_read; i < num_vec_read+nvec; i++) {
            rsize += vec[i].iov_len;
        }
        int ret = readv(fd, &vec[num_vec_read], nvec);
        if (ret < 0 || ret != rsize) {
            if (ret < 0) {
                Logger::Error("QueueFile(%s)::Read: Failed to read file: %s", _path.c_str(), std::strerror(errno));
            } else {
                Logger::Error("QueueFile(%s)::Read: Failed to read file: fewer bytes read (%d) than expected (%ld)", _path.c_str(), ret, rsize);
            }

            close(fd);
            return nullptr;
        }
        num_vec_read += nvec;
    }

    close(fd);

    return std::make_shared<QueueItemBucket>(_priority, num_bytes, std::move(items));
}

/**********************************************************************************************************************
 ** QueueCursorFile
 *********************************************************************************************************************/

bool QueueCursorFile::Read() {
    int fd = ::open(_path.c_str(), O_CLOEXEC|O_RDONLY);
    if (fd < 0) {
        Logger::Error("QueueCursorFile(%s): Failed to open: %s", _path.c_str(), std::strerror(errno));
        return false;
    }

    // Read header
    FileHeader header;
    int ret = read(fd, &header, sizeof(FileHeader));
    if (ret != sizeof(FileHeader)) {
        if (ret < 0) {
            Logger::Error("QueueCursorFile(%s): Failed to read header: %s", _path.c_str(), std::strerror(errno));
        } else {
            Logger::Error("QueueCursorFile(%s): Invalid or corrupted file", _path.c_str());
        }
        close(fd);
        return false;
    }

    // Verify header
    if (header._magic != MAGIC || header._version != FILE_VERSION) {
        Logger::Error("QueueCursorFile(%s): Invalid or corrupted file", _path.c_str());
        return false;
    }

    _cursors.resize(header._num_priorities);

    // Read index
    ret = read(fd, &_cursors[0], sizeof(uint64_t)*_cursors.size());
    if (ret != sizeof(uint64_t)*_cursors.size()) {
        if (ret < 0) {
            Logger::Error("QueueCursorFile(%s): Failed to read cursor: %s", _path.c_str(), std::strerror(errno));
        } else {
            Logger::Error("QueueCursorFile(%s): Invalid or corrupted file", _path.c_str());
        }
        close(fd);
        return false;
    }

    return true;
}

// This assumed cursor is locked
bool QueueCursorFile::Write() const {
    int fd = ::open(_path.c_str(), O_CLOEXEC|O_CREAT|O_TRUNC|O_WRONLY, 0664);
    if (fd < 0) {
        Logger::Error("QueueCursorFile(%s): Failed to open: %s", _path.c_str(), std::strerror(errno));
        return false;
    }

    FileHeader header(_cursors.size());
    struct iovec vec[2];
    vec[0].iov_base = &header;
    vec[0].iov_len = sizeof(header);
    vec[1].iov_base = const_cast<uint64_t*>(&_cursors[0]);
    vec[1].iov_len = _cursors.size() * sizeof(uint64_t);
    uint32_t idx = 2;
    int ret = writev(fd, vec, 2);
    if (ret != sizeof(FileHeader)+(_cursors.size()*sizeof(uint64_t))) {
        Logger::Error("QueueCursorFile(%s): Failed to write cursor: %s", _path.c_str(), std::strerror(errno));

        close(fd);

        if (unlink(_path.c_str()) != 0) {
            Logger::Error("QueueCursorFile(%s): Failed to remove incomplete file: %s", _path.c_str(), std::strerror(errno));
        }
        return false;
    }
    close(fd);

    return true;
}

bool QueueCursorFile::Remove() const {
    if (unlink(_path.c_str()) != 0) {
        if (errno != ENOENT) {
            Logger::Error("QueueCursorFile: Failed to remove cursor file '%s': %s", _path.c_str(),
                          std::strerror(errno));
            return false;
        }
    }
    return true;
}

/**********************************************************************************************************************
 ** QueueCursor
 *********************************************************************************************************************/

QueueCursor::QueueCursor(const std::string& path, const std::vector<uint64_t>& max_seq)
    : _path(path), _need_save(false), _saved(false), _cursors(max_seq), _committed(max_seq), _buckets(max_seq.size())
{}

void QueueCursor::init_from_file(const QueueCursorFile& file, const std::vector<uint64_t>& max_seq) {
    std::vector<uint64_t> cursors;
    file.Get(cursors);
    std::fill(_cursors.begin(), _cursors.end(), 0);
    std::copy_n(cursors.begin(), std::min(_cursors.size(), cursors.size()), _cursors.begin());

    // The _max_seq might be less than the cursor. This can happen if the queue is empty.
    for (int p = 0; p < _cursors.size(); ++p) {
        if (_cursors[p] > max_seq[p]) {
            _cursors[p] = max_seq[p];
        }
    }

    _committed = _cursors;
    _need_save = false;
    _saved = true;
}

std::pair<std::shared_ptr<QueueItem>,bool> QueueCursor::get(std::unique_lock<std::mutex>& lock, PriorityQueue* queue, bool& closed, long timeout, bool auto_commit) {
start:
    while(!closed && !data_available(queue->_max_seq)) {
        if (timeout < 0) {
            _cond.wait(lock);
        } else if (timeout == 0) {
            return std::make_pair<std::shared_ptr<QueueItem>,bool>(nullptr, false);
        } else {
            if (_cond.wait_for(lock, std::chrono::milliseconds(timeout)) == std::cv_status::timeout) {
                return std::make_pair<std::shared_ptr<QueueItem>,bool>(nullptr, false);
            }
        }
    }

    if (closed) {
        return std::make_pair<std::shared_ptr<QueueItem>,bool>(nullptr, true);
    }

    std::shared_ptr<QueueItem> item;

    for (uint32_t p = 0; p < _cursors.size(); ++p) {
        if (_cursors[p] < queue->_max_seq[p]) {
            if (!_buckets[p]) {
                _buckets[p] = queue->get_next_bucket(lock, p, _cursors[p]);
            }
            item = _buckets[p]->Get(_cursors[p]+1);
            if (!item) {
                _buckets[p] = queue->get_next_bucket(lock, p, _cursors[p]);
                item = _buckets[p]->Get(_cursors[p]+1);
            }
            if (!item) {
                Logger::Error("QueueCursor: unexpected empty bucket (%d, %ld)", p, _cursors[p]);
                _cursors[p] = queue->_max_seq[p];
                continue;
            }
            _cursors[p] = item->Sequence();
            break;
        }
    }

    if (!item) {
        Logger::Error("QueueCursor: data available was true, but no data found!");
        goto start;
    }

    if (auto_commit) {
        _need_save = true;
        _committed[item->Priority()] = item->Sequence();
    }

    return std::make_pair(item, false);
}

void QueueCursor::rollback() {
    for (uint32_t p = 0; p < _committed.size(); p++) {
        if (_cursors[p] != _committed[p]) {
            _cursors[p] = _committed[p];
            if (_buckets[p]) {
                _buckets[p].reset();
            }
        }
    }
}

void QueueCursor::commit(uint32_t priority, uint64_t seq) {
    if (priority >= _committed.size()) {
        return;
    }

    if (_committed[priority] < seq) {
        _committed[priority] = seq;
        _need_save = true;
    }
}

void QueueCursor::get_min_seq(std::vector<uint64_t>& min_seq) {
    for (uint32_t p = 0; p < _committed.size(); ++p) {
        if (min_seq[p] > _committed[p]) {
            min_seq[p] = _committed[p];
        }
    }
}

bool QueueCursor::data_available(const std::vector<uint64_t>& max_seq) {
    for (uint32_t p = 0; p < _cursors.size(); ++p) {
        if (_cursors[p] < max_seq[p]) {
            return true;
        }
    }
    return false;
}

void QueueCursor::notify(int priority, uint64_t seq) {
    if (_cursors[priority] < seq) {
        _cond.notify_all();
    }
}

/**********************************************************************************************************************
 ** PriorityQueue
 *********************************************************************************************************************/

PriorityQueue::PriorityQueue(const std::string& dir, uint32_t num_priorities, size_t max_file_data_size, size_t max_unsaved_files, uint64_t max_fs_bytes, double max_fs_pct, double min_fs_free_pct)
    : _dir(dir), _data_dir(dir+"/data"), _cursors_dir(dir+"/cursors"), _num_priorities(num_priorities),
      _max_file_data_size(max_file_data_size), _max_unsaved_files(max_unsaved_files), _max_fs_consumed_bytes(max_fs_bytes), _max_fs_consumed_pct(max_fs_pct), _min_fs_free_pct(min_fs_free_pct),
      _closed(false), _next_seq(1), _next_cursor_id(1),
      _min_seq(num_priorities, 0xFFFFFFFFFFFFFFFF), _max_seq(num_priorities, 0), _max_file_seq(num_priorities, 0), _current_buckets(num_priorities), _files(num_priorities), _unsaved(num_priorities), _cursors(), _cursor_handles(),
      _last_save_warning(), _stats(num_priorities)
{
    for (uint32_t i = 0; i < num_priorities; i++) {
        _current_buckets[i] = std::make_shared<QueueItemBucket>(i);
    }
    if (max_file_data_size == 0) {
        _max_file_data_size = MAX_ITEM_SIZE;
    }
    if (max_unsaved_files < num_priorities) {
        _max_unsaved_files = num_priorities;
    }
    if (max_fs_bytes == 0) {
        _max_fs_consumed_bytes = 0xFFFFFFFFFFFFFFFF;
    }
    if (max_fs_pct <= 0 || max_fs_pct > 100) {
        _max_fs_consumed_pct = 100;
    }
    if (min_fs_free_pct < 0) {
        _min_fs_free_pct = 0;
    } else if (min_fs_free_pct > 100) {
        _min_fs_free_pct = 100;
    }
}

std::shared_ptr<PriorityQueue> PriorityQueue::Open(const std::string& dir, uint32_t max_priority, size_t max_file_size, size_t max_unsaved_files, uint64_t max_fs_bytes, double max_fs_pct, double min_fs_free_pct) {
    auto queue = std::shared_ptr<PriorityQueue>(new PriorityQueue(dir, max_priority, max_file_size, max_unsaved_files, max_fs_bytes, max_fs_pct, min_fs_free_pct));
    if (queue->open()) {
        return queue;
    }
    return nullptr;
}

void PriorityQueue::Close() {
    std::unique_lock<std::mutex> lock(_mutex);

    if (_closed) {
        return;
    }
    _closed = true;

    for (auto &c : _cursor_handles) {
        c.second->close();
    }

    _saver_cond.notify_all();

    std::thread saver_thread = std::move(_saver_thread);

    lock.unlock();

    if (saver_thread.joinable()) {
        saver_thread.join();
    }
}

std::shared_ptr<QueueCursorHandle> PriorityQueue::OpenCursor(const std::string& name) {
    std::unique_lock<std::mutex> lock(_mutex);
    if (_closed) {
        return nullptr;
    }

    auto max_seq = _max_seq;

    std::shared_ptr<QueueCursor> cursor;

    auto itr = _cursors.find(name);
    if (itr != _cursors.end()) {
        cursor = itr->second;
    } else {
        cursor = std::shared_ptr<QueueCursor>(new QueueCursor(_cursors_dir + "/" + name, max_seq));
        _cursors.emplace(name, cursor);
    }

    auto handle = std::shared_ptr<QueueCursorHandle>(new QueueCursorHandle(cursor, _next_cursor_id));
    _next_cursor_id += 1;

    _cursor_handles.emplace(std::make_pair(handle->_id, handle));

    return handle;
}

void PriorityQueue::RemoveCursor(const std::string& name) {
    std::unique_lock<std::mutex> lock(_mutex);

    std::shared_ptr<QueueCursor> cursor;

    auto itr = _cursors.find(name);
    if (itr != _cursors.end()) {
        cursor = itr->second;
        _cursors.erase(itr);
    }

    if (cursor) {
        // Locate, close, and remove and cursor handles associated with cursor.
        std::vector<uint64_t> ids;
        for (auto& e: _cursor_handles) {
            if (e.second->_cursor->_path == cursor->_path) {
                ids.push_back(e.second->_id);
                e.second->close();
            }
        }
        for (auto id: ids) {
            _cursor_handles.erase(id);
        }

        QueueCursorFile file(cursor->_path);

        lock.unlock();

        file.Remove();
    }
}

std::pair<std::shared_ptr<QueueItem>,bool> PriorityQueue::Get(const std::shared_ptr<QueueCursorHandle>& cursor_handle, long timeout, bool auto_commit) {
    std::unique_lock<std::mutex> lock(_mutex);

    return cursor_handle->_cursor->get(lock, this, cursor_handle->_closed, timeout, auto_commit);
}

void PriorityQueue::Rollback(const std::shared_ptr<QueueCursorHandle>& cursor_handle) {
    std::unique_lock<std::mutex> lock(_mutex);
    cursor_handle->_cursor->rollback();
}

void PriorityQueue::Commit(const std::shared_ptr<QueueCursorHandle>& cursor_handle, uint32_t priority, uint64_t seq) {
    std::unique_lock<std::mutex> lock(_mutex);
    cursor_handle->_cursor->commit(priority, seq);
}

void PriorityQueue::Close(const std::shared_ptr<QueueCursorHandle>& cursor_handle) {
    std::unique_lock<std::mutex> lock(_mutex);

    cursor_handle->close();
    _cursor_handles.erase(cursor_handle->_id);
}

int PriorityQueue::Put(uint32_t priority, const void* data, size_t size) {
    std::unique_lock<std::mutex> lock(_mutex);

    if (size > MAX_ITEM_SIZE) {
        return -1;
    }

    if (_closed) {
        return 0;
    }

    if (priority >= _num_priorities) {
        priority = _num_priorities-1;
    }

    auto item = std::shared_ptr<QueueItem>(new QueueItem(priority, _next_seq, size));
    item->SetData(data, size);
    _next_seq += 1;

    std::shared_ptr<QueueItemBucket> bucket = _current_buckets[priority];

    if (bucket->Size()+item->Size() > _max_file_data_size) {
        bucket = cycle_bucket(priority);
    }

    bucket->Put(item);

    _max_seq[priority] = item->Sequence();

    _stats._priority_stats[priority]._num_items_added += 1;

    std::vector<std::shared_ptr<QueueCursor>> cursors;
    cursors.reserve(_cursors.size());
    for (auto& c : _cursors) {
        cursors.emplace_back(c.second);
    }

    for (auto& c : cursors) {
        c->notify(priority, item->Sequence());
    }

    return 1;
}

void PriorityQueue::Save(long save_delay, bool final_save) {
    std::unique_lock<std::mutex> lock(_mutex);
    save(lock, save_delay, final_save);
}

void PriorityQueue::Saver(long save_delay) {
    std::unique_lock<std::mutex> lock(_mutex);

    do {
        _saver_cond.wait_for(lock, std::chrono::milliseconds(save_delay), [this,save_delay]() { return _closed; });
        save(lock, save_delay, false);
    } while (!_closed);
    // Final save
    save(lock, 0, true);
}

void PriorityQueue::StartSaver(long save_delay) {
    std::unique_lock<std::mutex> lock(_mutex);

    std::thread saver_thread([this, save_delay](){ this->Saver(save_delay); });
    _saver_thread = std::move(saver_thread);
}

bool PriorityQueue::open() {
    std::unique_lock<std::mutex> lock(_mutex);

    if (!PathExists(_dir)) {
        if (mkdir(_dir.c_str(), 0755) != 0) {
            Logger::Error("Failed to create dir '%s': %s", _dir.c_str(), std::strerror(errno));
            return false;
        }
    }

    if (!PathExists(_data_dir)) {
        if (mkdir(_data_dir.c_str(), 0755) != 0) {
            Logger::Error("Failed to create dir '%s': %s", _data_dir.c_str(), std::strerror(errno));
            return false;
        }
    } else if (!IsDir(_data_dir)) {
        Logger::Error("Path '%s' is not a directory: %s", _data_dir.c_str(), std::strerror(errno));
        return false;
    }

    if (!PathExists(_cursors_dir)) {
        if (mkdir(_cursors_dir.c_str(), 0755) != 0) {
            Logger::Error("Failed to create dir '%s': %s", _cursors_dir.c_str(), std::strerror(errno));
            return false;
        }
    } else if (!IsDir(_cursors_dir)) {
        Logger::Error("Path '%s' is not a directory: %s", _cursors_dir.c_str(), std::strerror(errno));
        return false;
    }

    // Read all queue file headers
    for (uint32_t p = 0; p < _num_priorities; ++p) {
        std::string pdir = _data_dir + "/" + std::to_string(p);

        if (!PathExists(pdir)) {
            if (mkdir(pdir.c_str(), 0755) != 0) {
                Logger::Error("Failed to create dir '%s': %s", pdir.c_str(), std::strerror(errno));
                return false;
            }
        } else if (!IsDir(pdir)) {
            Logger::Error("Path '%s' is not a directory: %s", pdir.c_str(), std::strerror(errno));
            return false;
        }

        try {
            auto fv = GetDirList(pdir);
            for (auto& f : fv) {
                auto file = QueueFile::Open(pdir + "/" + f);
                if (file) {
                    _files[file->Priority()].emplace(file->Sequence(), file);
                }
            }
        } catch (std::exception& ex) {
            Logger::Error("PriorityQueue: Failed to read queue dir '%s': %s", pdir.c_str(), ex.what());
            return false;
        }
    }

    // Calculate _max_seq and _max_file_seq
    for (auto& p : _files) {
        auto itr = p.rbegin();
        if (itr != p.rend()) {
            _max_seq[itr->second->Priority()] = itr->second->Sequence();
            _max_file_seq[itr->second->Priority()] = itr->second->Sequence();
        }
    }

    // Make _next_seq 1 higher than all existing seq
    for (auto s : _max_file_seq) {
        if (s > _next_seq) {
            _next_seq = s;
        }
    }
    _next_seq += 1;

    // Read cursors
    try {
        auto fv = GetDirList(_cursors_dir);
        for (auto& f : fv) {
            QueueCursorFile cfile(_cursors_dir + "/" + f);
            if (cfile.Read()) {
                auto cursor = std::shared_ptr<QueueCursor>(new QueueCursor(cfile.Path(), _max_seq));
                cursor->init_from_file(cfile, _max_seq);
                _cursors.emplace(f, cursor);
            }
        }
    } catch (std::exception& ex) {
        Logger::Error("PriorityQueue: Failed to read cursors dir '%s': %s", _cursors_dir.c_str(), ex.what());
        return false;
    }

    update_min_seq();

    return true;
}

std::shared_ptr<QueueItemBucket> PriorityQueue::cycle_bucket(uint32_t priority) {
    std::shared_ptr<QueueItemBucket> bucket = _current_buckets[priority];

    auto file = std::make_shared<QueueFile>(_data_dir, bucket);
    _files[priority].emplace(file->Sequence(), file);
    _unsaved[priority].emplace(file->Sequence(), _UnsavedEntry(file, bucket));
    _max_file_seq[priority] = bucket->MaxSequence();

    bucket = std::make_shared<QueueItemBucket>(priority);
    _current_buckets[priority] = bucket;

    _saver_cond.notify_one();

    size_t num_unsaved = 0;
    for (auto& p : _unsaved) {
        num_unsaved += p.size();
    }

    // Remove unsaved items starting with the oldest and lowest priority
    if (num_unsaved > _max_unsaved_files) {
        clean_unsaved();

        for (auto pitr = _unsaved.rbegin(); num_unsaved > _max_unsaved_files && pitr != _unsaved.rend(); ++pitr) {
            auto fitr = pitr->begin();
            while (fitr != pitr->end() && num_unsaved > _max_unsaved_files) {
                auto file = fitr->second._file;
                auto bucket = fitr->second._bucket;
                num_unsaved -= 1;
                Logger::Warn(
                        "PriorityQueue: Unsaved items (priority = %d, sequence [%ld to %ld]) where removed due to memory limit being exceeded",
                        file->Priority(), bucket->MinSequence(), bucket->MaxSequence());
                _stats._priority_stats[bucket->Priority()]._bytes_dropped += bucket->Size();
                _files[file->Priority()].erase(file->Sequence());
                pitr->erase(fitr);
                fitr = pitr->begin();
            }
        }
    }

    return bucket;
}

/*
 * Return the bucket with the item that follows immediately after last_seq
 */
std::shared_ptr<QueueItemBucket> PriorityQueue::get_next_bucket(std::unique_lock<std::mutex>& lock, uint32_t priority, uint64_t last_seq) {
    // Look in _files if last_seq is <= the max file seq.
    if (last_seq <= _max_file_seq[priority]) {
        auto& m = _files[priority];
        // Look for the file/bucket with a seq
        auto itr = m.lower_bound(last_seq+1);
        if (itr != m.end()) {
            auto file = itr->second;
            lock.unlock();
            auto bucket = file->OpenBucket();
            lock.lock();
            if (bucket) {
                return bucket;
            }
        }
    }

    // The cursor has switched to a new bucket, so notify the saver because there might be a file that can be removed.
    _saver_cond.notify_one();

    return _current_buckets[priority];
}

// Only call while _mutex is locked
void PriorityQueue::update_min_seq() {
    std::vector<uint64_t> min_seq(_num_priorities, 0xFFFFFFFFFFFFFFFF);

    // Get the minimum sequence across all cursors for each priority
    for (auto &c : _cursors) {
        c.second->get_min_seq(min_seq);
    }

    // Update global minimum sequence
    _min_seq = min_seq;
}

// This is only called as part of close/shutdown process
void PriorityQueue::flush_current_buckets() {
    for (int p = 0; p < _num_priorities; ++p) {
        if (_current_buckets[p]->Size() > 0) {
            _current_buckets[p] = cycle_bucket(p);
        }
    }
}

void PriorityQueue::clean_unsaved() {
    update_min_seq();

    std::vector<std::shared_ptr<QueueFile>> unsaved_to_remove;

    // Find unsaved that are no longer needed
    for (int32_t p = _files.size()-1; p >= 0; --p) {
        auto min_seq = _min_seq[p];
        auto &pf = _files[p];
        for (auto& f : pf) {
            if (!f.second->Saved() && f.first <= min_seq) {
                _unsaved[p].erase(f.second->Sequence());
                unsaved_to_remove.emplace_back(f.second);
            }
        }
    }

    // Remove unsaved that are not needed
    for (auto& f : unsaved_to_remove) {
        _files[f->Priority()].erase(f->Sequence());
    }
}

// Only call while locked
bool PriorityQueue::save_needed(long save_delay) {
    // Set min_age to now if closed
    if (_closed) {
        for (auto& p : _unsaved) {
            if (!p.empty()) {
                return true;
            }
        }
    } else {
        auto now = std::chrono::steady_clock::now();
        auto min_age = now - std::chrono::milliseconds(save_delay);

        for (auto& p : _unsaved) {
            if (!p.empty()) {
                if (p.size() > 1 || p.rbegin()->second._ts <= min_age) {
                    return true;
                }
            }
        }
    }

    for (auto &e : _cursors) {
        if (e.second->_need_save) {
            return true;
        }
    }

    return false;
}

// Only call while locked
bool PriorityQueue::save(std::unique_lock<std::mutex>& lock, long save_delay, bool final_save) {
    update_min_seq();

    if (final_save) {
        // Flush non-empty current_buckets into unsaved
        flush_current_buckets();
    }

    struct statvfs st;
    ::memset(&st, 0, sizeof(st));

    uint64_t fs_bytes_allowed = 0;
    if (save_needed(save_delay)) {
        // Unlock while getting fs stats
        lock.unlock();

        if (statvfs(_data_dir.c_str(), &st) != 0) {
            Logger::Error("PriorityQueue::save(): statvfs(%s) failed: %s", _data_dir.c_str(),
                          std::strerror(errno));
            st.f_blocks = 0;
        }

        // Relock
        lock.lock();

        if (st.f_blocks > 0) {
            // Total filesystem size
            double fs_size = static_cast<double>(st.f_blocks) * static_cast<double>(st.f_frsize);
            // Amount of free space
            double fs_free = static_cast<double>(st.f_bavail) * static_cast<double>(st.f_bsize);
            // Percent of free space
            double pct_free = fs_free / fs_size;
            // Percent of fs that can be used (based on _min_fs_free_pct);
            double pct_free_avail = 0;
            if (pct_free > (_min_fs_free_pct/100)) {
                pct_free_avail = pct_free - (_min_fs_free_pct/100);
            }

            // Max space that can be used based on _max_fs_consumed_pct
            uint64_t max_allowed_fs = 0;
            // It is theoretically possible for fs_size to exceed the limits of uint64_t
            if (static_cast<double>(_max_fs_consumed_bytes) < fs_size * (_max_fs_consumed_pct / 100)) {
                max_allowed_fs = _max_fs_consumed_bytes;
            } else {
                max_allowed_fs = static_cast<uint64_t>(fs_size * (_max_fs_consumed_pct / 100));
            }
            // Max space that can be used based on _min_fs_free_pct
            uint64_t max_allowed_free = 0;
            // It is theoretically possible for fs_size to exceed the limits of uint64_t
            if (static_cast<double>(_max_fs_consumed_bytes) < fs_size * (pct_free_avail / 100)) {
                max_allowed_free = _max_fs_consumed_bytes;
            } else {
                max_allowed_free = static_cast<uint64_t>(fs_size * (pct_free_avail / 100));
            }
            // Minimum of all possible fs limits
            fs_bytes_allowed = std::min(max_allowed_fs, max_allowed_free);

            _stats._fs_size = fs_size;
            _stats._fs_free = fs_free;
            _stats._fs_allowed_bytes = fs_bytes_allowed;
        }
    }

    std::vector<std::shared_ptr<QueueFile>> to_remove;
    std::vector<std::shared_ptr<QueueFile>> can_remove;
    std::vector<std::shared_ptr<QueueFile>> unsaved_to_remove;

    uint64_t bytes_saved = 0;
    bool have_saved_data = false;
    // Find files that are no longer needed and count total bytes saved (excluding those that will be deleted)
    // Also fill in can_remove with items in the order they can be removed to make space for higher priority data
    for (int32_t p = _files.size()-1; p >= 0; --p) {
        auto min_seq = _min_seq[p];
        auto &pf = _files[p];
        for (auto& f : pf) {
            if (f.second->Saved()) {
                bytes_saved += f.second->FileSize();
                if (f.first <= min_seq) {
                    to_remove.emplace_back(f.second);
                } else {
                    have_saved_data = true;
                    can_remove.emplace_back(f.second);
                }
            } else {
                if (f.first <= min_seq) {
                    _unsaved[p].erase(f.second->Sequence());
                    unsaved_to_remove.emplace_back(f.second);
                }
            }
        }
    }

    // Remove unsaved files that are not needed
    for (auto& f : unsaved_to_remove) {
        _files[f->Priority()].erase(f->Sequence());
    }

    std::vector<_UnsavedEntry> to_save;

    auto now = std::chrono::steady_clock::now();
    auto min_age = now - std::chrono::milliseconds(save_delay);

    // Set min_age to now if closed
    if (_closed) {
        min_age = now;
    }

    // Get the list of buckets that can be saved, in the order they need to be saved.
    for (auto& p : _unsaved) {
        uint64_t last_seq = 0xFFFFFFFFFFFFFFFF;
        if (!p.empty()) {
            last_seq = p.rbegin()->first;
        }

        for (auto& f: p) {
            // If the entry is not the last or it is older than min_age then include in to_save
            if (f.first != last_seq || f.second._ts <= min_age) {
                to_save.emplace_back(f.second);
            }
        }
    }

    // Get cursors to save
    std::vector<QueueCursorFile> cursors_to_save;
    std::vector<QueueCursorFile> cursors_to_remove;
    if (have_saved_data || !to_save.empty()) {
        // Only save the cursors if there are files saved to disk
        for (auto &e : _cursors) {
            if (e.second->_need_save || !(e.second->_saved)) {
                cursors_to_save.emplace_back(e.second->_path, e.second->_committed);
                e.second->_need_save = false;
                e.second->_saved = true;
            }
        }
    } else {
        // Remove cursor files if there is no data saved to disk
        for (auto &e : _cursors) {
            if (e.second->_saved) {
                cursors_to_remove.emplace_back(e.second->_path);
                e.second->_saved = false;
            }
        }
    }

    // Unlock before doing IO
    lock.unlock();

    std::vector<std::shared_ptr<QueueFile>> removed;
    std::vector<std::shared_ptr<QueueFile>> saved;

    // Remove files that are not needed
    for (auto& f : to_remove) {
        if (f->Remove()) {
            removed.emplace_back(f);
            bytes_saved -= f->FileSize();
        }
    }

    int ridx = 0;
    int sidx = 0;
    uint64_t bytes_removed = 0;
    uint64_t cannot_save_bytes = 0;
    bool save_failed = false;

    // Iterate through to_save
    // for each bucket to save, if the save would exceed the quote, remove from can_remove until below quota
    for (; sidx < to_save.size(); ++sidx) {
        auto& ue = to_save[sidx];
        if (bytes_saved + ue._file->FileSize() > fs_bytes_allowed) {
            // Loop through can_remove, but stop at first higher priority file.
            while (ridx < can_remove.size() && bytes_saved + ue._file->FileSize() > fs_bytes_allowed && can_remove[ridx]->Priority() >= ue._file->Priority()) {
                auto& remove_target = can_remove[ridx];
                if (remove_target->Remove()) {
                    removed.emplace_back(remove_target);
                    bytes_saved -= remove_target->FileSize();
                    bytes_removed += remove_target->FileSize();
                    ridx += 1;
                    _stats._priority_stats[remove_target->Priority()]._bytes_dropped += remove_target->DataSize();
                } else {
                    // Remove failed, do not proceed
                    save_failed = true;
                    break;
                }
            }
        }
        if (bytes_saved + ue._file->FileSize() > fs_bytes_allowed) {
            // Either remove failed, or non enough lower priority data could be removed to make room for this file.
            break;
        } else {
            if (ue._file->Save()) {
                saved.emplace_back(ue._file);
                bytes_saved += ue._file->FileSize();
                _stats._priority_stats[ue._file->Priority()]._bytes_written += ue._file->FileSize();
            } else {
                // Save failed, do not proceed
                break;
            }
        }
    }

    // Tally up unsaved bytes count
    for (; sidx < to_save.size(); ++sidx) {
        cannot_save_bytes += to_save[sidx]._file->FileSize();
    }

    // Save (or remove) cursors
    for (auto &cfile : cursors_to_remove) {
        cfile.Remove();
    }
    for (auto &cfile : cursors_to_save) {
        cfile.Write();
    }

    // Relock before removing items from _unsaved;
    lock.lock();

    // erase from _files and _unsaved the files that where removed.
    for (auto& f : removed) {
        _files[f->Priority()].erase(f->Sequence());
        _unsaved[f->Priority()].erase(f->Sequence());
    }

    // erase from _unsaved the files that where saved.
    for (auto& f : saved) {
        _unsaved[f->Priority()].erase(f->Sequence());
    }

    if (bytes_removed > 0) {
        Logger::Warn("PriorityQueue: Removed (%ld) bytes of unconsumed lower priority data to make room for new higher priority data", bytes_removed);
    }

    if (cannot_save_bytes > 0) {
        if (now - _last_save_warning > std::chrono::milliseconds(MIN_SAVE_WARNING_GAP_MS)) {
            _last_save_warning = now;
            if (save_failed) {
                Logger::Warn("PriorityQueue: Errors encountered while saving data, (%ld) bytes left unsaved", cannot_save_bytes);
            } else {
                Logger::Warn("PriorityQueue: File System quota (%ld) would be exceeded, (%ld) bytes left unsaved", fs_bytes_allowed, cannot_save_bytes);
            }
        }
    }

    return cannot_save_bytes == 0;
}

void PriorityQueue::GetStats(PriorityQueueStats& stats) {
    std::unique_lock<std::mutex> lock(_mutex);

    // Collect stats
    for (int32_t p = 0; p < _files.size(); ++p) {
        auto &pf = _files[p];
        auto& stat = _stats._priority_stats[p];

        stat.Reset();

        for (auto& f : pf) {
            stat._bytes_mem += f.second->BucketSize();
            if (f.second->Saved()) {
                stat._bytes_fs += f.second->FileSize();
            } else {
                stat._bytes_unsaved += f.second->FileSize();
            }
        }
    }

    for (auto& c : _current_buckets) {
        auto& stat = _stats._priority_stats[c->Priority()];
        stat._bytes_mem += c->Size();
    }

    _stats.UpdateTotals();

    stats = _stats;
}
