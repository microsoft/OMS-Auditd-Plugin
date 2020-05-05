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
    if (fd <= 0) {
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
        return nullptr;
    }
    close(fd);

    if (header._magic != MAGIC || header._version != FILE_VERSION) {
        Logger::Error("QueueFile(%s): Invalid or corrupted file", path.c_str());
        return nullptr;
    }

    return std::shared_ptr<QueueFile>(new QueueFile(path, header));
}

std::shared_ptr<QueueItemBucket> QueueFile::OpenBucket() {
    std::lock_guard<std::mutex> lock(_mutex);

    auto ptr = _bucket.lock();

    if (!ptr) {
        return Read();
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
    if (fd <= 0) {
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
            Logger::Error("QueueFile(%s)::Save: Failed to remove incomplete file: %s", _path.c_str(), std::strerror(errno));
            return false;
        }
    }
    return true;
}

std::shared_ptr<QueueItemBucket> QueueFile::Read() {
    std::vector<IndexEntry> index;
    std::map<uint64_t, std::shared_ptr<QueueItem>> items;

    int fd = open(_path.c_str(), O_CLOEXEC|O_RDONLY);
    if (fd <= 0) {
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
 ** QueueCursor
 *********************************************************************************************************************/

QueueCursor::QueueCursor(PriorityQueue* queue, const std::string& path, const std::vector<uint64_t>& max_seq)
    : _queue(queue), _path(path), _closed(false), _data_available(false), _need_save(true), _last_write_status(true), _last_save(std::chrono::steady_clock::now()),
    _cursors(max_seq), _committed(max_seq), _max_seq(max_seq), _buckets(queue->_num_priorities)
{}

void QueueCursor::Close() {
    std::unique_lock<std::mutex> lock(_mutex);
    _closed = true;

    if (_need_save) {
        write_cursor_file(lock);
    }

    _cond.notify_all();
}

std::pair<std::shared_ptr<QueueItem>,bool> QueueCursor::Get(long timeout, bool auto_commit) {
    std::unique_lock<std::mutex> lock(_mutex);

    // Calculate wake_time based on timeout
    // timeout < 0 == wait forever == std::chrono::steady_clock::time_point::max()
    // timeout == 0 == don't wait == std::chrono::steady_clock::time_point::min()
    // timeout > 0 == wait == std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout)

    auto wake_time = std::chrono::steady_clock::time_point::min();
    if (timeout > 0) {
        wake_time = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    } else if (timeout < 0) {
        wake_time = std::chrono::steady_clock::time_point::max();
    }

start:
    while(!_closed && !data_available()) {
        // check_save_cursor maybe saves the cursor and return > 0 if save is needed in return milliseconds
        auto check_ret = check_save_cursor(lock);
        if (check_ret.second) {
            // A save was performed so the status of (!_closed && !data_available()) may have changed
            continue;
        }
        auto save_wake_time = std::chrono::steady_clock::time_point::min();
        if (check_ret.first > 0) {
            save_wake_time = std::chrono::steady_clock::now() + std::chrono::milliseconds(check_ret.first);
        }

        // Figure out which wake time to use
        auto cond_wake_time = wake_time;
        if (wake_time < save_wake_time) {
            cond_wake_time = save_wake_time;
        }

        if (cond_wake_time == std::chrono::steady_clock::time_point::max()) {
            _cond.wait(lock);
        } else if (cond_wake_time == std::chrono::steady_clock::time_point::min()) {
            return std::make_pair<std::shared_ptr<QueueItem>,bool>(nullptr, false);
        } else {
            if (_cond.wait_until(lock, cond_wake_time) == std::cv_status::timeout) {
                // If we are timed out due to save_wait_time, then restart the loop
                if (save_wake_time > std::chrono::steady_clock::time_point::min() &&  save_wake_time < wake_time) {
                    continue;
                }
                return std::make_pair<std::shared_ptr<QueueItem>,bool>(nullptr, false);
            }
        }
    }

    if (_closed) {
        return std::make_pair<std::shared_ptr<QueueItem>,bool>(nullptr, true);
    }

    std::shared_ptr<QueueItem> item;

    for (uint32_t p = 0; p < _cursors.size(); ++p) {
        if (_cursors[p] < _max_seq[p]) {
            if (!_buckets[p]) {
                _buckets[p] = _queue->get_next_bucket(p, _cursors[p]);
            }
            item = _buckets[p]->Get(_cursors[p]+1);
            if (!item) {
                _buckets[p] = _queue->get_next_bucket(p, _cursors[p]);
                item = _buckets[p]->Get(_cursors[p]+1);
            }
            if (!item) {
                Logger::Error("QueueCursor: unexpected empty bucket (%d, %ld)", p, _cursors[p]);
                _cursors[p] = _max_seq[p];
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
        _committed[item->Priority()] = item->Sequence();
        _need_save = true;
    }

    return std::make_pair(item, false);
}

void QueueCursor::Commit(uint32_t priority, uint64_t seq) {
    std::unique_lock<std::mutex> lock(_mutex);

    if (priority >= _committed.size()) {
        return;
    }

    if (_committed[priority] < seq) {
        _committed[priority] = seq;
        _need_save = true;
        check_save_cursor(lock);
    }
}

void QueueCursor::open() {
    std::unique_lock<std::mutex> lock(_mutex);
    _closed = false;
}

void QueueCursor::get_min_seq(std::vector<uint64_t>& min_seq) {
    for (uint32_t p = 0; p < _committed.size(); ++p) {
        if (min_seq[p] > _committed[p]) {
            min_seq[p] = _committed[p];
        }
    }
}

bool QueueCursor::data_available() {
    for (uint32_t p = 0; p < _cursors.size(); ++p) {
        if (_cursors[p] < _max_seq[p]) {
            return true;
        }
    }
    return false;
}

std::pair<long,bool> QueueCursor::check_save_cursor(std::unique_lock<std::mutex>& lock) {
    bool do_save = false;
    long save_lag = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - _last_save).count();

    if (!_last_write_status) {
        if (save_lag < SAVE_RETRY_WAIT_MS) {
            return std::make_pair(SAVE_RETRY_WAIT_MS - save_lag, false);
        }
        do_save = true;
    } else if (_need_save) {
        if (save_lag < SAVE_DELAY_MS) {
            return std::make_pair(SAVE_DELAY_MS - save_lag, false);
        }
        do_save = true;
    }

    if (do_save) {
        _last_write_status = write_cursor_file(lock);
        if (_last_write_status) {
            return std::make_pair(0, true);
        }
        return std::make_pair(SAVE_RETRY_WAIT_MS, true);
    }

    return std::make_pair(0, false);
}

void QueueCursor::notify(int priority, uint64_t seq) {
    std::lock_guard<std::mutex> lock(_mutex);
    _max_seq[priority] = seq;

    if (_cursors[priority] < seq) {
        _cond.notify_all();
    }
}

bool QueueCursor::read_cursor_file() {
    int fd = ::open(_path.c_str(), O_CLOEXEC|O_RDONLY);
    if (fd <= 0) {
        Logger::Error("QueueCursor(%s): Failed to open: %s", _path.c_str(), std::strerror(errno));
        return false;
    }

    // Read header
    FileHeader header;
    int ret = read(fd, &header, sizeof(FileHeader));
    if (ret != sizeof(FileHeader)) {
        if (ret < 0) {
            Logger::Error("QueueCursor(%s): Failed to read header: %s", _path.c_str(), std::strerror(errno));
        } else {
            Logger::Error("QueueCursor(%s): Invalid or corrupted file", _path.c_str());
        }
        close(fd);
        return false;
    }

    // Verify header
    if (header._magic != MAGIC || header._version != FILE_VERSION) {
        Logger::Error("QueueCursor(%s): Invalid or corrupted file", _path.c_str());
        return false;
    }

    auto np = header._num_priorities;
    if (np > _queue->_num_priorities) {
        np = _queue->_num_priorities;
    }

    // Read index
    ret = read(fd, &_cursors[0], sizeof(uint64_t)*np);
    if (ret != sizeof(uint64_t)*np) {
        if (ret < 0) {
            Logger::Error("QueueCursor(%s): Failed to read cursor: %s", _path.c_str(), std::strerror(errno));
        } else {
            Logger::Error("QueueCursor(%s): Invalid or corrupted file", _path.c_str());
        }
        close(fd);
        return false;
    }

    // The _max_seq might be less than the cursor. This can happen if the queue is empty.
    for (int p = 0; p < _cursors.size(); ++p) {
        if (_cursors[p] > _max_seq[p]) {
            _cursors[p] = _max_seq[p];
        }
    }

    _committed = _cursors;

    return true;
}

// This assumed cursor is locked
bool QueueCursor::write_cursor_file(std::unique_lock<std::mutex>& lock) {
    std::vector<uint64_t> cursors(_committed.size());
    for (int i = 0; i < _committed.size(); ++i) {
        cursors[i] = _committed[i];
    }

    lock.unlock();

    int fd = ::open(_path.c_str(), O_CLOEXEC|O_CREAT|O_TRUNC|O_WRONLY, 0664);
    if (fd <= 0) {
        Logger::Error("QueueCursor(%s): Failed to open: %s", _path.c_str(), std::strerror(errno));
        lock.lock();
        return false;
    }

    FileHeader header(cursors.size());
    struct iovec vec[2];
    vec[0].iov_base = &header;
    vec[0].iov_len = sizeof(header);
    vec[1].iov_base = &cursors[0];
    vec[1].iov_len = cursors.size() * sizeof(uint64_t);
    uint32_t idx = 2;
    int ret = writev(fd, vec, 2);
    if (ret != sizeof(FileHeader)+(cursors.size()*sizeof(uint64_t))) {
        Logger::Error("QueueCursor(%s): Failed to write cursor: %s", _path.c_str(), std::strerror(errno));

        close(fd);

        if (unlink(_path.c_str()) != 0) {
            Logger::Error("QueueCursor(%s): Failed to remove incomplete file: %s", _path.c_str(), std::strerror(errno));
        }
        lock.lock();
        return false;
    }
    close(fd);

    lock.lock();

    _need_save = false;
    _last_save = std::chrono::steady_clock::now();

    return true;
}

bool QueueCursor::remove_cursor_file() {
    if (unlink(_path.c_str()) != 0) {
        Logger::Error("QueueCursor: Failed to remove cursor file '%s': %s", _path.c_str(), std::strerror(errno));
        return false;
    }
    return true;
}
/**********************************************************************************************************************
 ** PriorityQueue
 *********************************************************************************************************************/

PriorityQueue::PriorityQueue(const std::string& dir, uint32_t num_priorities, size_t max_file_data_size, size_t max_unsaved_files, uint64_t max_fs_bytes, double max_fs_pct, double min_fs_free_pct)
    : _dir(dir), _data_dir(dir+"/data"), _cursors_dir(dir+"/cursors"), _num_priorities(num_priorities),
      _max_file_data_size(max_file_data_size), _max_unsaved_files(max_unsaved_files), _max_fs_consumed_bytes(max_fs_bytes), _max_fs_consumed_pct(max_fs_pct), _min_fs_free_pct(min_fs_free_pct),
      _closed(false), _next_seq(1),
      _min_seq(num_priorities, 0xFFFFFFFFFFFFFFFF), _max_seq(num_priorities, 0), _max_file_seq(num_priorities, 0), _current_buckets(num_priorities), _files(num_priorities), _unsaved(num_priorities), _cursors(),
      _last_save_warning()
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
    std::unique_lock<std::mutex> cursors_lock(_cursors_mutex);

    if (_closed) {
        return;
    }
    _closed = true;

    for (auto& c : _cursors) {
        c.second->Close();
    }

    for (int p = 0; p < _num_priorities; ++p) {
        if (_current_buckets[p]->Size() > 0) {
            _current_buckets[p] = cycle_bucket(p);
        }
    }

    _saver_cond.notify_all();

    std::thread saver_thread = std::move(_saver_thread);

    lock.unlock();

    if (saver_thread.joinable()) {
        saver_thread.join();
    }
}

std::shared_ptr<QueueCursor> PriorityQueue::OpenCursor(const std::string& name) {
    std::unique_lock<std::mutex> lock(_mutex);
    if (_closed) {
        return nullptr;
    }

    auto max_seq = _max_seq;
    lock.unlock();

    std::unique_lock<std::mutex> cursors_lock(_cursors_mutex);

    auto itr = _cursors.find(name);
    if (itr != _cursors.end()) {
        itr->second->open();
        return itr->second;
    }

    auto c = std::shared_ptr<QueueCursor>(new QueueCursor(this, _cursors_dir + "/" + name, max_seq));
    _cursors.emplace(name, c);

    return c;
}

void PriorityQueue::RemoveCursor(const std::string& name) {
    std::unique_lock<std::mutex> lock(_mutex);
    if (_closed) {
        return;
    }
    lock.unlock();

    std::lock_guard<std::mutex> cursors_lock(_cursors_mutex);

    auto itr = _cursors.find(name);
    if (itr != _cursors.end()) {
        auto c = itr->second;
        _cursors.erase(itr);
        c->Close();
        c->remove_cursor_file();
    }
}

bool PriorityQueue::Put(uint32_t priority, const void* data, size_t size) {
    std::unique_lock<std::mutex> lock(_mutex);

    if (_closed) {
        return false;
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

    std::unique_lock<std::mutex> cursors_lock(_cursors_mutex);
    lock.unlock();

    for (auto& c : _cursors) {
        c.second->notify(priority, item->Sequence());
    }

    return true;
}

void PriorityQueue::Save(long save_delay) {
    std::unique_lock<std::mutex> lock(_mutex);
    save(lock, save_delay);
}

void PriorityQueue::Saver(long save_delay) {
    std::unique_lock<std::mutex> lock(_mutex);

    bool save_success = true;
    do {
        if (_next_save_needed.time_since_epoch().count() > 0) {
            _saver_cond.wait_until(lock, _next_save_needed, [this,save_delay]() { return _closed || save_needed(save_delay); });
        } else if(save_success) {
            _saver_cond.wait(lock, [this,save_delay]() { return _closed || save_needed(save_delay); });
        } else {
            _saver_cond.wait_for(lock, std::chrono::seconds(1), [this,save_delay]() { return _closed; });
        }
        save_success = save(lock, save_delay);
    } while (!_closed);

    save(lock, save_delay);
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
            auto c = std::shared_ptr<QueueCursor>(new QueueCursor(this, _cursors_dir + "/" + f, _max_seq));
            if (c->read_cursor_file()) {
                _cursors.emplace(f, c);
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
    for (auto pitr = _unsaved.rbegin(); num_unsaved > _max_unsaved_files && pitr != _unsaved.rend(); ++pitr) {
        auto fitr = pitr->begin();
        while (fitr != pitr->end() && num_unsaved > _max_unsaved_files) {
            auto file = fitr->second._file;
            auto bucket = fitr->second._bucket;
            num_unsaved -= 1;
            Logger::Warn("PriorityQueue: Unsaved items (priority = %d, sequence [%ld to %ld]) where removed due to memory limit being exceeded",
                         file->Priority(), bucket->MinSequence(), bucket->MaxSequence());
            _files[file->Priority()].erase(file->Sequence());
            pitr->erase(fitr);
            fitr = pitr->begin();
        }
    }

    return bucket;
}

/*
 * Return the bucket with the item that follows immediately after last_seq
 */
std::shared_ptr<QueueItemBucket> PriorityQueue::get_next_bucket(uint32_t priority, uint64_t last_seq) {
    std::unique_lock<std::mutex> lock(_mutex);

    // Look in _files if last_seq is <= the max file seq.
    if (last_seq <= _max_file_seq[priority]) {
        auto& m = _files[priority];
        // Look for the file/bucket with a seq
        auto itr = m.lower_bound(last_seq+1);
        if (itr != m.end()) {
            auto file = itr->second;
            lock.unlock();
            auto bucket = file->OpenBucket();
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
    for (auto& c : _cursors) {
        c.second->get_min_seq(min_seq);
    }

    // Update global minimum sequence
    _min_seq = min_seq;
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
    return false;
}

// Only call while locked
bool PriorityQueue::save(std::unique_lock<std::mutex>& lock, long save_delay) {
    update_min_seq();

    struct statvfs st;
    ::memset(&st, 0, sizeof(st));

    uint64_t fs_bytes_allowed = 0;
    if (save_needed(save_delay)) {
        // Unlock while getting fs stats
        lock.unlock();

        if (statvfs(_data_dir.c_str(), &st) != 0) {
            Logger::Error("PriorityQueue::write_unsaved(): statvfs(%s) failed: %s", _data_dir.c_str(),
                          std::strerror(errno));
        }

        // Relock
        lock.lock();

        if (st.f_blocks > 0) {
            // Total filesystem size
            double fs_size = static_cast<double>(st.f_blocks * st.f_frsize);
            // Amount of free space
            double fs_free = static_cast<double>(st.f_bavail * st.f_bsize);
            // Percent of free space
            double pct_free = fs_free / fs_size;
            // Percent of fs that can be used (based on _min_fs_free_pct);
            double pct_free_avail = 0;
            if (pct_free > (_min_fs_free_pct/100)) {
                pct_free_avail = pct_free - (_min_fs_free_pct/100);
            }

            // Max space that can be used based on _max_fs_consumed_pct
            uint64_t max_allowed_fs = static_cast<uint64_t>(fs_size * (_max_fs_consumed_pct / 100));
            // Max space that can be used based on _min_fs_free_pct
            uint64_t max_allowed_free = static_cast<uint64_t>(fs_size * (pct_free_avail / 100));
            // Minimum of all possible fs limits
            fs_bytes_allowed = std::min(std::min(max_allowed_fs, max_allowed_free), _max_fs_consumed_bytes);
        }
    }

    std::vector<std::shared_ptr<QueueFile>> to_remove;
    std::vector<std::shared_ptr<QueueFile>> can_remove;

    uint64_t bytes_saved = 0;
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
                    can_remove.emplace_back(f.second);
                }
            } else {
                if (f.first <= min_seq) {
                    _unsaved[p].erase(f.second->Sequence());
                }
            }
        }
    }

    std::vector<_UnsavedEntry> to_save;

    auto now = std::chrono::steady_clock::now();
    auto next_save = now;
    auto min_age = now - std::chrono::milliseconds(save_delay);

    // Set min_age to now if closed
    if (_closed) {
        min_age = now;
    }

    int num_delayed = 0;

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
            } else {
                num_delayed += 1;
                if (f.second._ts < next_save) {
                    next_save = f.second._ts;
                }
            }
        }
    }

    if (num_delayed > 0) {
        _next_save_needed = next_save + std::chrono::milliseconds(save_delay);
    } else {
        _next_save_needed = std::chrono::steady_clock::time_point();
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

    // Populate to_save and to_remove;
    int ridx = 0;
    int sidx = 0;
    uint64_t bytes_removed = 0;
    uint64_t cannot_save_bytes = 0;

    // Iterate through to_save
    // for each bucket to save, if the save would exceed the quote, remove from can_remove until below quota
    for (; sidx < to_save.size(); ++sidx) {
        auto& ue = to_save[sidx];
        if (bytes_saved + ue._file->FileSize() > fs_bytes_allowed) {
            while (ridx < can_remove.size() && bytes_saved + ue._file->FileSize() > fs_bytes_allowed && can_remove[ridx]->Priority() >= ue._file->Priority()) {
                if (can_remove[ridx]->Remove()) {
                    removed.emplace_back(can_remove[ridx]);
                    bytes_saved -= can_remove[ridx]->FileSize();
                    bytes_removed += can_remove[ridx]->FileSize();
                    ridx += 1;
                } else {
                    break;
                }
            }
        }
        if (bytes_saved + ue._file->FileSize() > fs_bytes_allowed) {
            break;
        } else {
            if (ue._file->Save()) {
                saved.emplace_back(ue._file);
                bytes_saved += ue._file->FileSize();
            } else {
                break;
            }
        }
    }

    // Tally up unsaved bytes count
    for (; sidx < to_save.size(); ++sidx) {
        cannot_save_bytes += to_save[sidx]._file->FileSize();
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
        Logger::Warn("PriorityQueue: Removed (%ld) bytes of unconsumed lower priority data to make from for new higher priority data", bytes_removed);
    }

    if (cannot_save_bytes > 0) {
        if (now - _last_save_warning > std::chrono::milliseconds(MIN_SAVE_WARNING_GAP_MS)) {
            _last_save_warning = now;
            Logger::Warn("PriorityQueue: File System quota (%ld) would be exceeded (%ld) bytes left unsaved", fs_bytes_allowed, cannot_save_bytes);
        }
    }

    return cannot_save_bytes == 0;
}
