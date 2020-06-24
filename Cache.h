/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_RULIST_H
#define AUOMS_RULIST_H

#include <chrono>
#include <unordered_map>
#include <functional>

enum class CacheEntryOP {
    NOOP,
    TOUCH,
    REMOVE,
    STOP,
};

template<typename K, typename V>
class Cache {
public:

    Cache() {
        _newest._newer = nullptr;
        _newest._older = &_oldest;
        _oldest._newer = &_newest;
        _oldest._older = nullptr;
    }

    ~Cache() {
        for (const auto& e: _entries) {
            delete e.second;
        }
    }
    inline bool empty() const { return _entries.empty(); }
    inline size_t size() const { return _entries.size(); }

    void add(const K& key, const V& value) {
        auto itr = _entries.find(key);
        if (itr != _entries.end()) {
            touch(itr->second);
            itr->second->_item = value;
        } else {
            auto entry = new CacheEntry(key, value);
            _entries.emplace(key, entry);
            _newest._older->_newer = entry;
            entry->_newer = &_newest;
            entry->_older = _newest._older;
            _newest._older = entry;
        }
    }

    bool remove(const K& key) {
        auto itr = _entries.find(key);
        if (itr != _entries.end()) {
            remove(itr->second);
            return true;
        }
        return false;
    }

    bool touch(const K& key) {
        auto itr = _entries.find(key);
        if (itr != _entries.end()) {
            touch(itr->second);
            return true;
        }
        return false;
    }

    bool on(const K& key, const std::function<CacheEntryOP(size_t entry_count, const std::chrono::steady_clock::time_point& last_touched, V& value)>& fn) {
        auto itr = _entries.find(key);
        if (itr != _entries.end()) {
            auto entry = itr->second;
            auto op = fn(_entries.size(), entry->_last_touched, entry->_item);
            if (op == CacheEntryOP::TOUCH) {
                touch(entry);
            } else if (op == CacheEntryOP::REMOVE) {
                remove(entry);
            }
            return true;
        }
        return false;
    }

    void for_all_oldest_first(const std::function<CacheEntryOP(size_t entry_count, const std::chrono::steady_clock::time_point& last_touched, const K& key, V& value)>& fn) {
        auto now = std::chrono::steady_clock::now();
        while (_oldest._newer != &_newest) {
            auto entry = _oldest._newer;
            auto op = fn(_entries.size(), entry->_last_touched, entry->_key, entry->_item);
            switch (op) {
                case CacheEntryOP::TOUCH:
                    touch(entry);
                    break;
                case CacheEntryOP::REMOVE:
                    remove(entry);
                    break;
                case CacheEntryOP::STOP:
                    return;
            }
        }
    }

    void for_all_newest_first(const std::function<CacheEntryOP(size_t entry_count, const std::chrono::steady_clock::time_point& last_touched, const K& key, V& value)>& fn) {
        auto now = std::chrono::steady_clock::now();
        while (_newest._older != &_oldest) {
            auto entry = _newest._older;
            auto op = fn(_entries.size(), entry->_last_touched, entry->_key, entry->_item);
            switch (op) {
                case CacheEntryOP::TOUCH:
                    touch(entry);
                    break;
                case CacheEntryOP::REMOVE:
                    remove(entry);
                    break;
                case CacheEntryOP::STOP:
                    return;
            }
        }
    }
private:
    class CacheEntry {
    public:
        CacheEntry(): _older(nullptr), _newer(nullptr), _last_touched(), _key(), _item() {}
        CacheEntry(const K& key, const V& item): _older(nullptr), _newer(nullptr), _last_touched(std::chrono::steady_clock::now()), _key(key), _item(item) {}

        inline void remove() {
            _older->_newer = _newer;
            _newer->_older = _older;
            _older = nullptr;
            _newer = nullptr;
        }

        CacheEntry *_older;
        CacheEntry *_newer;
        std::chrono::steady_clock::time_point _last_touched;
        K _key;
        V _item;
    };

    void remove(CacheEntry* entry) {
        entry->remove();
        _entries.erase(entry->_key);
        delete (entry);
    }

    void touch(CacheEntry* entry) {
        entry->remove();
        entry->_last_touched = std::chrono::steady_clock::now();
        _newest._older->_newer = entry;
        entry->_newer = &_newest;
        entry->_older = _newest._older;
        _newest._older = entry;
    }

    std::unordered_map<K, CacheEntry*> _entries;
    CacheEntry _newest;
    CacheEntry _oldest;

};

#endif //AUOMS_RULIST_H
