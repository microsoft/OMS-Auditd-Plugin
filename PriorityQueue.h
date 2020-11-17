/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_PRIORITYQUEUE_H
#define AUOMS_PRIORITYQUEUE_H

#include "Logger.h"

#include <cstddef>
#include <string>
#include <stdexcept>
#include <memory>
#include <vector>
#include <cstring>
#include <map>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <list>
#include <deque>
#include <thread>
#include <atomic>

/*
 *
 */

class QueueFile;
class PriorityQueue;

class QueueItem {
public:
    ~QueueItem() {
        delete[] _data;
    }

    inline uint32_t Priority() { return _priority; }
    inline uint64_t Sequence() { return _seq; }
    inline void* Data() { return _data; }
    inline size_t Size() { return _size; }

private:
    friend QueueFile;
    friend PriorityQueue;

    QueueItem(uint32_t priority, uint64_t seq, size_t size): _priority(priority), _seq(seq), _data(nullptr), _size(size) {
        _data = new uint8_t[_size];
    }

    void SetData(const void* data, size_t size) {
        auto n = std::min(size, _size);
        ::memcpy(_data, data, n);
    }

    uint32_t _priority;
    uint64_t _seq;
    uint8_t* _data;
    size_t _size;
};

class QueueItemBucket {
public:
    explicit QueueItemBucket(uint32_t priority): _min_seq(0), _max_seq(0), _priority(priority), _size(0), _items() {}
    QueueItemBucket(uint32_t priority, size_t size, std::map<uint64_t, std::shared_ptr<QueueItem>> items): _priority(priority), _size(size), _items(std::move(items)) {
        if (!_items.empty()) {
            _min_seq = _items.begin()->second->Sequence();
            _max_seq = _items.rbegin()->second->Sequence();
        }
    }

    void Put(std::shared_ptr<QueueItem> item);

    std::shared_ptr<QueueItem> Get(uint64_t seq);

    inline size_t Size() const { return _size; }
    inline uint32_t Priority() const { return _priority; }
    inline uint64_t MinSequence() const { return _min_seq; }
    inline uint64_t MaxSequence() const { return _max_seq; }

    inline const std::map<uint64_t, std::shared_ptr<QueueItem>>& Items() const { return _items; }

private:
    std::mutex _mutex;

    uint64_t _min_seq;
    uint64_t _max_seq;
    uint32_t _priority;
    uint32_t _size;
    std::map<uint64_t, std::shared_ptr<QueueItem>> _items;
};

class QueueFile {
public:
    static std::shared_ptr<QueueFile> Open(const std::string& path);
    static constexpr size_t Overhead(int num_items) {
        return sizeof(FileHeader) + sizeof(IndexEntry)*num_items;
    }

    QueueFile(const std::string& dir, const std::shared_ptr<QueueItemBucket>& bucket) {
        _priority = bucket->Priority();
        _file_seq = bucket->MaxSequence();
        _path = dir + "/" + std::to_string(_priority) + "/" + std::to_string(_file_seq);
        _bucket = bucket;
        _num_items = bucket->Items().size();
        _first_seq = bucket->MinSequence();
        _last_seq = bucket->MaxSequence();
        _file_size = Overhead(_num_items) + bucket->Size();
        _saved = false;
    }

    inline uint32_t Priority() const { return _priority; }
    inline uint64_t Sequence() const { return _file_seq; }
    inline size_t FileSize() const { return _file_size; }
    inline size_t DataSize() const { return _file_size-Overhead(_num_items); }
    inline bool Saved() const { return _saved; }

    std::shared_ptr<QueueItemBucket> OpenBucket();

    size_t BucketSize() const {
        auto ptr = _bucket.lock();

        if (!ptr) {
            return 0;
        }
        return ptr->Size();
    }


    bool Save();
    bool Remove();

private:
    static constexpr uint64_t MAGIC = 0x5155455546494C45;
    static constexpr uint32_t FILE_VERSION = 0x00000001;

    class FileHeader {
    public:
        FileHeader(): _magic(0), _version(0), _file_size(0), _priority(0), _num_items(0), _first_seq(0), _last_seq(0) {}
        explicit FileHeader(uint32_t file_size, uint32_t priority, uint32_t num_items, uint64_t first_seq, uint64_t last_seq): _magic(MAGIC), _version(FILE_VERSION), _file_size(file_size), _priority(priority), _num_items(num_items), _first_seq(first_seq), _last_seq(last_seq) {}

        uint64_t _magic;
        uint32_t _version;
        uint32_t _file_size;
        uint32_t _priority;
        uint32_t _num_items;
        uint64_t _first_seq;
        uint64_t _last_seq;
    };

    class IndexEntry {
    public:
        IndexEntry(): _seq(0), _offset(0), _size(0) {}
        IndexEntry(uint64_t seq, uint32_t offset, uint32_t size): _seq(seq), _offset(offset), _size(size) {}

        uint64_t _seq;
        uint32_t _offset;
        uint32_t _size;
    };

    QueueFile(const std::string& path, FileHeader& header):
        _path(path), _file_seq(header._last_seq), _priority(header._priority), _file_size(header._file_size), _num_items(header._num_items), _first_seq(header._first_seq), _last_seq(header._last_seq), _saved(true) {}

    std::shared_ptr<QueueItemBucket> Read();

    std::mutex _mutex;

    std::string _path;
    uint64_t _file_seq;
    uint32_t _priority;
    size_t _file_size;
    uint32_t _num_items;
    uint64_t _first_seq;
    uint64_t _last_seq;
    bool _saved;

    std::weak_ptr<QueueItemBucket> _bucket;
};

class QueueCursorFile {
public:
    explicit QueueCursorFile(const std::string& path): _path(path) {}
    explicit QueueCursorFile(const std::string& path, const std::vector<uint64_t>& cursors): _path(path), _cursors(cursors) {}

    inline std::string Path() {
        return _path;
    }

    inline void Get(std::vector<uint64_t>& cursors) const {
        cursors = _cursors;
    }

    inline void Set(const std::vector<uint64_t>& cursors) {
        _cursors = cursors;
    }

    bool Read();
    bool Write() const;
    bool Remove() const;

private:
    static constexpr uint64_t MAGIC = 0x4355525346494C45;
    static constexpr uint32_t FILE_VERSION = 0x00000001;

    class FileHeader {
    public:
        FileHeader(): _magic(0), _version(0), _num_priorities(0) {}
        explicit FileHeader(uint32_t num_priorities): _magic(MAGIC), _version(FILE_VERSION), _num_priorities(num_priorities) {}

        uint64_t _magic;
        uint32_t _version;
        uint32_t _num_priorities;
    };

    std::string _path;

    bool _saved;

    std::vector<uint64_t> _cursors;
};

class QueueCursorHandle;

class QueueCursor {
private:
    friend PriorityQueue;
    friend QueueCursorHandle;

    static constexpr uint64_t MAGIC = 0x4355525346494C45;
    static constexpr uint32_t FILE_VERSION = 0x00000001;

    class FileHeader {
    public:
        FileHeader(): _magic(0), _version(0), _num_priorities(0) {}
        explicit FileHeader(uint32_t num_priorities): _magic(MAGIC), _version(FILE_VERSION), _num_priorities(num_priorities) {}

        uint64_t _magic;
        uint32_t _version;
        uint32_t _num_priorities;
    };

    QueueCursor(const std::string& path, const std::vector<uint64_t>& max_seq);

    void init_from_file(const QueueCursorFile& file, const std::vector<uint64_t>& max_seq);

    std::pair<std::shared_ptr<QueueItem>,bool> get(std::unique_lock<std::mutex>& lock, PriorityQueue* queue, bool& closed, long timeout, bool auto_commit = true);
    void rollback();
    void commit(uint32_t priority, uint64_t seq);

    void get_min_seq(std::vector<uint64_t>& min_seq);
    bool data_available(const std::vector<uint64_t>& max_seq);

    void notify(int priority, uint64_t seq);

    std::condition_variable _cond;

    std::string _path;

    bool _need_save;
    bool _saved;

    // The last consumed seq for each priority
    std::vector<uint64_t> _cursors;

    // The last committed seq for each priority
    std::vector<uint64_t> _committed;

    // The current bucket for each priority
    std::vector<std::shared_ptr<QueueItemBucket>> _buckets;
};

class QueueCursorHandle {
private:
    friend PriorityQueue;
    friend QueueCursor;

    QueueCursorHandle(const std::shared_ptr<QueueCursor>& cursor, uint64_t id): _cursor(cursor), _id(id), _closed(false) {}

    void close() {
        if (!_closed) {
            _closed = true;
            _cursor->_cond.notify_all();
        }
    }

    std::shared_ptr<QueueCursor> _cursor;
    uint64_t _id;
    bool _closed;
};

class PriorityQueueStats {
public:
    PriorityQueueStats(): _priority_stats(), _fs_size(0), _fs_free(0), _fs_allowed_bytes(0) {}
    explicit PriorityQueueStats(int num_priority): _priority_stats(num_priority), _fs_size(0), _fs_free(0), _fs_allowed_bytes(0) {}

    class Stats {
    public:
        Stats(): _num_items_added(0), _bytes_fs(0), _bytes_mem(0), _bytes_unsaved(0), _bytes_dropped(0), _bytes_written(0) {}

        void Reset(bool all = false) {
            _bytes_fs = 0;
            _bytes_mem = 0;
            _bytes_unsaved = 0;
            if (all) {
                _num_items_added = 0;
                _bytes_dropped = 0;
                _bytes_written = 0;
            }
        }

        uint64_t _num_items_added;
        uint64_t _bytes_fs;
        uint64_t _bytes_mem;
        uint64_t _bytes_unsaved;
        uint64_t _bytes_dropped;
        uint64_t _bytes_written;
    };

    void UpdateTotals() {
        _total.Reset(true);

        for (auto& p: _priority_stats) {
            _total._num_items_added += p._num_items_added;
            _total._bytes_fs += p._bytes_fs;
            _total._bytes_mem += p._bytes_mem;
            _total._bytes_unsaved += p._bytes_unsaved;
            _total._bytes_dropped += p._bytes_dropped;
            _total._bytes_written += p._bytes_written;
        }
    }

    std::vector<Stats> _priority_stats;

    Stats _total;

    double _fs_size;
    double _fs_free;
    uint64_t _fs_allowed_bytes;
};

class PriorityQueue {
public:
    static constexpr size_t MAX_ITEM_SIZE = 1024*256;

    static std::shared_ptr<PriorityQueue> Open(const std::string& dir, uint32_t num_priorities, size_t max_file_data_size, size_t max_unsaved_files, uint64_t max_fs_bytes, double max_fs_pct, double min_fs_free_pct);

    uint32_t NumPriorities() { return _num_priorities; }

    void Close();

    std::shared_ptr<QueueCursorHandle> OpenCursor(const std::string& name);
    void RemoveCursor(const std::string& name);

    std::pair<std::shared_ptr<QueueItem>,bool> Get(const std::shared_ptr<QueueCursorHandle>& cursor_handle, long timeout, bool auto_commit = true);
    void Rollback(const std::shared_ptr<QueueCursorHandle>& cursor_handle);
    void Commit(const std::shared_ptr<QueueCursorHandle>& cursor_handle, uint32_t priority, uint64_t seq);
    void Close(const std::shared_ptr<QueueCursorHandle>& cursor_handle);

    // Return 1 on success, 0 on queue closed, and -1 if item too large
    int Put(uint32_t priority, const void* data, size_t size);

    void Save(long save_delay, bool final_save = false);
    void Saver(long save_delay);
    void StartSaver(long save_delay);

    void GetStats(PriorityQueueStats& stats);
private:
    friend QueueCursor;

    class _UnsavedEntry {
    public:
        _UnsavedEntry(const std::shared_ptr<QueueFile>& file, const std::shared_ptr<QueueItemBucket>& bucket)
            : _ts(std::chrono::steady_clock::now()), _file(file), _bucket(bucket)
        {}
        std::chrono::steady_clock::time_point _ts;
        std::shared_ptr<QueueFile> _file;
        std::shared_ptr<QueueItemBucket> _bucket;
    };

    static constexpr long MIN_SAVE_WARNING_GAP_MS = 60000;

    PriorityQueue(const std::string& dir, uint32_t num_priorities, size_t max_file_data_size, size_t max_unsaved_files, uint64_t max_fs_bytes, double max_fs_pct, double min_fs_free_pct);

    bool open();

    std::shared_ptr<QueueItemBucket> cycle_bucket(uint32_t priority);
    std::shared_ptr<QueueItemBucket> get_next_bucket(std::unique_lock<std::mutex>& lock, uint32_t priority, uint64_t last_seq);
    void update_min_seq();
    void flush_current_buckets();
    void clean_unsaved();

    bool save_needed(long save_delay);
    bool save(std::unique_lock<std::mutex>& lock, long save_delay, bool final_save);

    std::string _dir;
    std::string _data_dir;
    std::string _cursors_dir;
    uint32_t _num_priorities;
    size_t _max_file_data_size;
    size_t _max_unsaved_files;
    uint64_t _max_fs_consumed_bytes;
    double _max_fs_consumed_pct;
    double _min_fs_free_pct;

    std::mutex _mutex;
    std::condition_variable _saver_cond;

    bool _closed;

    uint64_t _next_seq;
    uint64_t _next_cursor_id;

    // The minimum seq for each priority
    std::vector<uint64_t> _min_seq;

    // The maximum seq for each priority
    std::vector<uint64_t> _max_seq;

    // The maximum seq in _files for each priority
    std::vector<uint64_t> _max_file_seq;

    // The currently being filled bucket for each priority
    std::vector<std::shared_ptr<QueueItemBucket>> _current_buckets;

    // The set of all queue files/buckets (excluding current) for each priority
    std::vector<std::map<uint64_t, std::shared_ptr<QueueFile>>> _files;

    // The set of files/buckets that have yet to be saved for each priority
    std::vector<std::map<uint64_t, _UnsavedEntry>> _unsaved;

    std::unordered_map<std::string, std::shared_ptr<QueueCursor>> _cursors;
    std::unordered_map<uint64_t, std::shared_ptr<QueueCursorHandle>> _cursor_handles;

    std::chrono::steady_clock::time_point _last_save_warning;

    std::thread _saver_thread;

    PriorityQueueStats _stats;
};


#endif //AUOMS_PRIORITYQUEUE_H
