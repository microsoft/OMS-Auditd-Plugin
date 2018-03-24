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

#include <cstdint>
#include <iterator>
#include <memory>

// This enum mirrors the auparse_type_t found in auparse-defs.h
// The values here must appear in the same order as their counterpart in the definition of auparse_type_t
typedef enum:uint16_t {
    FIELD_TYPE_UNCLASSIFIED,
    FIELD_TYPE_UID,
    FIELD_TYPE_GID,
    FIELD_TYPE_SYSCALL,
    FIELD_TYPE_ARCH,
    FIELD_TYPE_EXIT,
    FIELD_TYPE_ESCAPED,
    FIELD_TYPE_PERM,
    FIELD_TYPE_MODE,
    FIELD_TYPE_SOCKADDR,
    FIELD_TYPE_FLAGS,
    FIELD_TYPE_PROMISC,
    FIELD_TYPE_CAPABILITY,
    FIELD_TYPE_SUCCESS,
    FIELD_TYPE_A0,
    FIELD_TYPE_A1,
    FIELD_TYPE_A2,
    FIELD_TYPE_A3,
    FIELD_TYPE_SIGNAL,
    FIELD_TYPE_LIST,
    FIELD_TYPE_TTY_DATA,
    FIELD_TYPE_SESSION,
    FIELD_TYPE_CAP_BITMAP,
    FIELD_TYPE_NFPROTO,
    FIELD_TYPE_ICMPTYPE,
    FIELD_TYPE_PROTOCOL,
    FIELD_TYPE_ADDR,
    FIELD_TYPE_PERSONALITY,
    FIELD_TYPE_SECCOMP,
    FIELD_TYPE_OFLAG,
    FIELD_TYPE_MMAP,
    FIELD_TYPE_MODE_SHORT,
    FIELD_TYPE_MAC_LABEL,
    FIELD_TYPE_PROCTITLE
} event_field_type_t;

constexpr event_field_type_t MIN_FIELD_TYPE = FIELD_TYPE_UNCLASSIFIED;
constexpr event_field_type_t MAX_FIELD_TYPE = FIELD_TYPE_PROCTITLE;

constexpr uint32_t EVENT_FLAG_IS_AUOMS_EVENT = 1;

class IEventBuilderAllocator {
public:
    virtual int Allocate(void** data, size_t size) = 0;
    virtual int Commit() = 0;
    virtual int Rollback() = 0;
};

class EventBuilder {
public:
    EventBuilder(std::shared_ptr<IEventBuilderAllocator> allocator): _allocator(allocator), _data(nullptr), _size(0)
    {}

    ~EventBuilder() {
    }

    int BeginEvent(uint64_t sec, uint32_t msec, uint64_t serial, uint16_t num_records);
    void SetEventFlags(uint32_t flags);
    uint32_t GetEventFlags();
    void SetEventPid(int32_t pid);
    int32_t GetEventPid();
    int EndEvent();
    int CancelEvent();
    int BeginRecord(uint32_t record_type, const char* record_name, const char* record_text, uint16_t num_fields);
    int EndRecord();
    int AddField(const char *field_name, const char* raw_value, const char* interp_value, event_field_type_t field_type);
    int GetFieldCount();

private:
    std::shared_ptr<IEventBuilderAllocator> _allocator;

    uint8_t* _data;
    size_t _size;
    uint32_t _roffset;
    uint32_t _fidxoffset;
    uint32_t _fsortedidxoffset;
    uint32_t _foffset;
    uint32_t _record_idx;
    uint16_t _num_fields;
    uint32_t _field_idx;
};

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

    const char* FieldName() const;
    uint16_t FieldNameSize() const;

    const char* RawValue() const;
    uint16_t RawValueSize() const;

    const char* InterpValue() const;
    uint16_t InterpValueSize() const;

    event_field_type_t FieldType() const;

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
    const char* RecordTypeName() const;
    uint16_t RecordTypeNameSize() const;
    const char* RecordText() const;
    uint16_t RecordTextSize() const;
    uint16_t NumFields() const;

    EventRecordField FieldAt(uint32_t idx) const;
    EventRecordField FieldByName(const char* name) const;

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

class Event {
public:
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

    uint32_t Flags() const;
    int32_t Pid() const;

    uint16_t NumRecords() const;
    EventRecord RecordAt(uint32_t index) const;

    EventRecord begin() const;
    EventRecord end() const;

private:
    friend class EventRecord;

    const uint8_t* _data;
    size_t _size;
};

#endif //AUOMS_EVENT_H
