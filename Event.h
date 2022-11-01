/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_EVENT_H
#define AUOMS_EVENT_H

#include "FieldType.h"

#include <cstdint>
#include <iterator>
#include <memory>
#include <string_view>
#include <vector>


constexpr uint16_t EVENT_FLAG_IS_AUOMS_EVENT = 1;
constexpr uint16_t EVENT_FLAG_HAS_EXTENSIONS = 2;

class EventRecord;

class EventRecordField {
public:
    typedef std::random_access_iterator_tag  iterator_category;
    typedef EventRecordField        value_type;
    typedef int32_t  difference_type;
    typedef EventRecordField*   pointer;
    typedef EventRecordField& reference;


    EventRecordField() {
        _data = nullptr;
        _roffset = 0;
        _fidxoffset = 0;
        _foffset = 0;
        _index = 0;
    }

    EventRecordField(const EventRecordField& other) = default;
    EventRecordField(EventRecordField&& other) = default;
    EventRecordField& operator=(const EventRecordField& other) = default;
    EventRecordField& operator=(EventRecordField&& other) = default;

    const char* FieldNamePtr() const;
    uint16_t FieldNameSize() const;
    std::string_view FieldName() const;

    const char* RawValuePtr() const;
    uint32_t RawValueSize() const;
    std::string_view RawValue() const;

    const char* InterpValuePtr() const;
    uint32_t InterpValueSize() const;
    std::string_view InterpValue() const;

    field_type_t FieldType() const;

    uint32_t RecordType() const;

    EventRecord Record() const;

    operator bool() const {
        return _data != nullptr;
    }

    EventRecordField& operator+=(int32_t movement) { move(movement); return (*this); }
    EventRecordField& operator-=(int32_t movement) { move(-movement); return (*this); }
    EventRecordField& operator++()                 { move(1); return (*this); }
    EventRecordField& operator--()                 { move(-1); return (*this); }
    EventRecordField  operator++(int32_t)          { auto temp(*this); move(1); return temp;}
    EventRecordField  operator--(int32_t)          { auto temp(*this); move(-1); return temp;}

    EventRecordField  operator+(int32_t movement) const { auto temp(*this); temp.move(movement); return temp; }
    EventRecordField  operator-(int32_t movement) const { auto temp(*this); temp.move(-movement); return temp; }

    int32_t operator+(const EventRecordField& other) const { return other._index + _index; }
    int32_t operator-(const EventRecordField& other) const { return other._index - _index; }

    bool operator==(const EventRecordField& other) const {
        return _data == other._data && _roffset == other._roffset && _foffset == other._foffset;
    }

    bool operator!=(const EventRecordField& other) const { return !(*this == other); }

    const EventRecordField* operator->() const { return this; }
    EventRecordField* operator->() { return this; }
    const EventRecordField& operator*() const { return *this; }
    EventRecordField& operator*() { return *this; }

private:
    friend class EventRecord;

    EventRecordField(const uint8_t* data, uint32_t roffset, uint32_t fidxoffset, uint32_t index);

    void move(int32_t n);

    const uint8_t* _data;
    uint32_t _roffset;
    uint32_t _fidxoffset;
    uint32_t _foffset;
    uint32_t _index;
};

class EventRecord {
public:
    typedef std::random_access_iterator_tag  iterator_category;
    typedef EventRecord        value_type;
    typedef int32_t  difference_type;
    typedef EventRecord*   pointer;
    typedef EventRecord& reference;


    EventRecord() {
        _data = nullptr;
        _roffset = 0;
        _index = 0;
    }

    EventRecord(const EventRecord& other) = default;
    EventRecord(EventRecord&& other) = default;
    EventRecord& operator=(const EventRecord& other) = default;
    EventRecord& operator=(EventRecord&& other) = default;


    uint32_t RecordType() const;
    const char* RecordTypeNamePtr() const;
    uint16_t RecordTypeNameSize() const;
    std::string_view RecordTypeName() const;

    const char* RecordTextPtr() const;
    uint16_t RecordTextSize() const;
    std::string_view RecordText() const;

    uint16_t NumFields() const;

    EventRecordField FieldAt(uint32_t idx) const;
    EventRecordField FieldByName(const char* name) const {
        return FieldByName(std::string_view(name));
    }
    EventRecordField FieldByName(const std::string& name) const {
        return FieldByName(std::string_view(name));
    }
    EventRecordField FieldByName(const std::string_view& name) const;

    operator bool() const {
        return _data != nullptr;
    }

    EventRecord& operator+=(int32_t movement) { move(movement); return (*this); }
    EventRecord& operator-=(int32_t movement) { move(-movement); return (*this); }
    EventRecord& operator++()                 { move(1); return (*this); }
    EventRecord& operator--()                 { move(-1); return (*this); }
    EventRecord  operator++(int32_t)          { auto temp(*this); move(1); return temp;}
    EventRecord  operator--(int32_t)          { auto temp(*this); move(-1); return temp;}
    EventRecord  operator+(int32_t movement) const { auto temp(*this); temp.move(movement); return temp; }
    EventRecord  operator-(int32_t movement) const { auto temp(*this); temp.move(-movement); return temp; }

    int32_t operator+(const EventRecord& other) { return other._index + _index; }
    int32_t operator-(const EventRecord& other) { return other._index - _index; }

    bool operator==(const EventRecord& other) const {
        return _data == other._data && _roffset == other._roffset;
    }

    bool operator!=(const EventRecord& other) const { return !(*this == other); }

    const EventRecord* operator->() const { return this; }
    EventRecord* operator->() { return this; }
    const EventRecord& operator*() const { return *this; }
    EventRecord& operator*() { return *this; }

    EventRecordField begin() const;
    EventRecordField end() const;

    EventRecordField begin_sorted() const;
    EventRecordField end_sorted() const;

private:
    friend class Event;
    friend class EventRecordField;

    EventRecord(const uint8_t* data, uint32_t index);
    void move(int32_t n);

    const uint8_t* _data;
    uint32_t _roffset;
    uint32_t _index;
};


class EventExtension {
public:
    typedef std::random_access_iterator_tag  iterator_category;
    typedef EventExtension        value_type;
    typedef int32_t  difference_type;
    typedef EventExtension*   pointer;
    typedef EventExtension& reference;


    EventExtension() {
        _data = nullptr;
        _offset = 0;
        _eoffset = 0;
        _index = 0;
    }

    EventExtension(const EventExtension& other) = default;
    EventExtension(EventExtension&& other) = default;
    EventExtension& operator=(const EventExtension& other) = default;
    EventExtension& operator=(EventExtension&& other) = default;


    uint32_t Type() const;
    uint32_t Size() const;
    const void* Data() const;

    operator bool() const {
        return _data != nullptr;
    }

    EventExtension& operator+=(int32_t movement) { move(movement); return (*this); }
    EventExtension& operator-=(int32_t movement) { move(-movement); return (*this); }
    EventExtension& operator++()                 { move(1); return (*this); }
    EventExtension& operator--()                 { move(-1); return (*this); }
    EventExtension  operator++(int32_t)          { auto temp(*this); move(1); return temp;}
    EventExtension  operator--(int32_t)          { auto temp(*this); move(-1); return temp;}
    EventExtension  operator+(int32_t movement) const { auto temp(*this); temp.move(movement); return temp; }
    EventExtension  operator-(int32_t movement) const { auto temp(*this); temp.move(-movement); return temp; }

    int32_t operator+(const EventExtension& other) { return other._index + _index; }
    int32_t operator-(const EventExtension& other) { return other._index - _index; }

    bool operator==(const EventExtension& other) const {
        return _data == other._data && _eoffset == other._eoffset;
    }

    bool operator!=(const EventExtension& other) const { return !(*this == other); }

    const EventExtension* operator->() const { return this; }
    EventExtension* operator->() { return this; }
    const EventExtension& operator*() const { return *this; }
    EventExtension& operator*() { return *this; }

private:
    friend class Event;
    friend class EventExtensions;

    EventExtension(const uint8_t* data, uint32_t offset, uint32_t index);
    void move(int32_t n);

    const uint8_t* _data;
    uint32_t _offset;
    uint32_t _eoffset;
    uint32_t _index;
};


class EventExtensions {
public:
    EventExtensions(const EventExtensions& other) = default;
    EventExtensions(EventExtensions&& other) = default;
    EventExtensions& operator=(const EventExtensions& other) = default;
    EventExtensions& operator=(EventExtensions&& other) = default;

    operator bool() const {
        return _data != nullptr;
    }

    uint32_t NumExtensions() const;
    EventExtension ExtensionAt(uint32_t index) const;

    EventExtension begin() const;
    EventExtension end() const;

private:
    friend class Event;

    EventExtensions(const uint8_t* data, uint32_t offset): _data(data), _offset(offset) {};

    const uint8_t* _data;
    uint32_t _offset;
};

class Event {
public:
    static inline std::pair<uint32_t, uint32_t> GetVersionAndSize(const void* data) {
        auto hdr = *reinterpret_cast<const uint32_t*>(data);
        return std::make_pair(hdr >> 24, hdr & 0x00FFFFFF);
    }

    Event(const void* data, size_t size) {
        _data = reinterpret_cast<const uint8_t*>(data);
        _size = size;
    }

    Event(const Event& other) = default;
    Event(Event&& other) = default;
    Event& operator=(const Event& other) = default;
    Event& operator=(Event&& other) = default;

    const void* Data() const;
    uint32_t Size() const;
    uint64_t Seconds() const;
    uint32_t Milliseconds() const;
    uint64_t Serial() const;

    uint16_t Priority() const;
    uint16_t Flags() const;
    int32_t Pid() const;

    uint16_t NumRecords() const;
    EventRecord RecordAt(uint32_t index) const;

    EventRecord begin() const;
    EventRecord end() const;

    uint32_t NumExtensions() const;
    uint32_t ExtensionTypeAt(uint32_t index) const;
    EventExtension ExtensionAt(uint32_t index) const;

    EventExtensions Extensions() const;

    int Validate() const;
private:
    friend class EventRecord;

    const uint8_t* _data;
    size_t _size;
};

class IEventBuilderAllocator {
public:
    // Return true on success, false if closed
    virtual bool Allocate(void** data, size_t size) = 0;
    // Return 1 on success, 0 on closed, and -1 if item too large
    virtual int Commit() = 0;
    // Return true on success, false if closed
    virtual bool Rollback() = 0;
};

class BasicEventBuilderAllocator: public IEventBuilderAllocator {
public:
    explicit BasicEventBuilderAllocator(size_t capacity): _buffer() {
        _buffer.reserve(capacity);
    }
    BasicEventBuilderAllocator(): _buffer() {}

    bool Allocate(void** data, size_t size) override {
        _buffer.resize(size);
        *data = _buffer.data();
        _commited = false;
        return true;
    }

    int Commit() override {
        _commited = true;
        return 1;
    }

    bool Rollback() override {
        _buffer.resize(0);
        _commited = false;
        return true;
    }

    inline void Reserve(size_t capacity) {
        _buffer.reserve(capacity);
    }

    inline bool IsCommited() const {
        return _commited;
    }

    inline Event GetEvent() const {
        return Event(_buffer.data(), _buffer.size());
    }

private:
    std::vector<uint8_t> _buffer;
    bool _commited;
};


class IEventPrioritizer {
public:
    virtual uint16_t Prioritize(const Event& event) = 0;
};

class DefaultPrioritizer: public IEventPrioritizer {
public:
    static std::shared_ptr<IEventPrioritizer> Create(uint16_t default_priority) {
        return std::shared_ptr<IEventPrioritizer>(new DefaultPrioritizer(default_priority));
    }

    DefaultPrioritizer(uint16_t default_priority): _default_priority(default_priority)  {}

    uint16_t Prioritize(const Event& event) override {
        return _default_priority;
    }

private:
    uint16_t _default_priority;
};

class EventBuilder {
public:
    EventBuilder(std::shared_ptr<IEventBuilderAllocator> allocator, std::shared_ptr<IEventPrioritizer> prioritizer): _allocator(allocator), _prioritizer(prioritizer), _data(nullptr), _size(0), _extensions_offset(0)
    {}

    ~EventBuilder() = default;

    bool BeginEvent(uint64_t sec, uint32_t msec, uint64_t serial, uint16_t num_records);
    void SetEventPriority(uint16_t flags);
    uint16_t GetEventPriority();
    void AddEventFlags(uint16_t flags);
    uint16_t GetEventFlags();
    void SetEventPid(int32_t pid);
    int32_t GetEventPid();
    int EndEvent();
    bool CancelEvent();
    bool BeginRecord(uint32_t record_type, const char* record_name, const char* record_text, uint16_t num_fields);
    bool BeginRecord(uint32_t record_type, const std::string_view& record_name, const std::string_view& record_text, uint16_t num_fields);
    bool EndRecord();
    bool AddField(const char *field_name, const char* raw_value, const char* interp_value, field_type_t field_type);
    bool AddField(const std::string_view& field_name, const std::string_view& raw_value, const std::string_view& interp_value, field_type_t field_type);
    int GetFieldCount();
    bool BeginExtensions(uint32_t num_extensions);
    bool AddExtension(uint32_t type, uint32_t size, void* data);
    bool EndExtensions();

private:
    std::shared_ptr<IEventBuilderAllocator> _allocator;
    std::shared_ptr<IEventPrioritizer> _prioritizer;

    uint8_t* _data;
    size_t _size;
    uint32_t _roffset;
    uint32_t _fidxoffset;
    uint32_t _fsortedidxoffset;
    uint32_t _foffset;
    uint32_t _record_idx;
    uint16_t _num_fields;
    uint32_t _field_idx;
    uint32_t _extensions_offset;
    uint32_t _eoffset;
    uint32_t _extension_idx;
};

std::string EventToRawText(const Event& event, bool include_interp);

#endif //AUOMS_EVENT_H
