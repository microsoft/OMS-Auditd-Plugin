/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "Event.h"

#include "Queue.h"

#include "Logger.h"

#include <cstring>
#include <algorithm>
#include <exception>
#include <iostream>

/*****************************************************************************
 ** CONSTANTS that define structure of AuditEvent
 *****************************************************************************/

/*
 *  Event:
 *      uint32_t size (including size)
 *      uint64_t sec
 *      uint32_t msec
 *      uint64_t serial
 *      uint16_t num_records
 *      uint16_t priority
 *      uint16_t flags
 *      int32_t pid
 *      RecordIndex:
 *          uint32_t[] offsets (from start of event)
 *      Records:
 *          uint32_t record_type
 *          uint16_t num_fields
 *          uint16_t record_name_size
 *          uint16_t record_text_size
 *          FieldIndex: (original order)
 *              uint32_t offsets (from start of record)
 *          FieldIndex: (sorted by field name)
 *              uint32_t offsets (from start of record)
 *          char[] record_type_name (null terminated)
 *          char[] record_text (null terminated)
 *          Fields:
 *              uint16_t field_type
 *              uint16_t field_name_size
 *              uint32_t raw_value_size
 *              uint32_t interp_value_size
 *              char[] field_name (null terminated)
 *              char[] raw_value (null terminated)
 *              char[] interp_value  (null terminated, only present if interp_value_size > 0)
 *      Extensions:
 *          uint32_t num_extensions
 *          uint32_t[] index
 *          Extension:
 *              uint32_t type
 *              uint32_t size
 *              *data
 *      uint32_t extensions_offset
 */

inline uint32_t& INDEX_VALUE(uint8_t* data, uint32_t offset, uint32_t index) {
    return *reinterpret_cast<uint32_t*>(data+offset+sizeof(uint32_t)*index);
}

inline uint32_t INDEX_VALUE(const uint8_t* data, uint32_t offset, uint32_t index) {
    return *reinterpret_cast<const uint32_t*>(data+offset+sizeof(uint32_t)*index);
}

inline uint32_t* INDEX_PTR(uint8_t* data, uint32_t offset, uint32_t index) {
    return reinterpret_cast<uint32_t*>(data+offset+sizeof(uint32_t)*index);
}

inline const uint32_t* INDEX_PTR(const uint8_t* data, uint32_t offset, uint32_t index) {
    return reinterpret_cast<const uint32_t*>(data+offset+sizeof(uint32_t)*index);
}

inline char* CHAR_PTR(uint8_t* data, uint32_t offset) {
    return reinterpret_cast<char*>(data+offset);
}

inline const char* CHAR_PTR(const uint8_t* data, uint32_t offset) {
    return reinterpret_cast<const char*>(data+offset);
}

constexpr uint32_t EVENT_SIZE_OFFSET = 0;
constexpr uint32_t EVENT_SIZE_SIZE = sizeof(uint32_t);
inline uint32_t EVENT_SIZE(const uint8_t* data) { return *reinterpret_cast<const uint32_t*>(data+EVENT_SIZE_OFFSET) & 0x00FFFFFF; }
inline void SET_EVENT_SIZE(uint8_t* data, uint32_t size) { *reinterpret_cast<uint32_t*>(data+EVENT_SIZE_OFFSET) = (*reinterpret_cast<uint32_t*>(data+EVENT_SIZE_OFFSET) & 0xFF000000) | (size&0x00FFFFFF); }
inline uint32_t EVENT_VERSION(const uint8_t* data) { return (*reinterpret_cast<const uint32_t*>(data+EVENT_SIZE_OFFSET) >> 24) & 0xFF; }
inline void SET_EVENT_VERSION(uint8_t* data, uint32_t version) { *reinterpret_cast<uint32_t*>(data+EVENT_SIZE_OFFSET) = (version << 24) | (*reinterpret_cast<uint32_t*>(data+EVENT_SIZE_OFFSET) & 0x00FFFFFF); }

constexpr uint32_t EVENT_SEC_OFFSET = EVENT_SIZE_OFFSET + EVENT_SIZE_SIZE;
constexpr uint32_t EVENT_SEC_SIZE = sizeof(uint64_t);
inline uint64_t& EVENT_SEC(uint8_t* data) { return *reinterpret_cast<uint64_t*>(data+EVENT_SEC_OFFSET); }
inline uint64_t EVENT_SEC(const uint8_t* data) { return *reinterpret_cast<const uint64_t*>(data+EVENT_SEC_OFFSET); }

constexpr uint32_t EVENT_MSEC_OFFSET = EVENT_SEC_OFFSET + EVENT_SEC_SIZE;
constexpr uint32_t EVENT_MSEC_SIZE = sizeof(uint32_t);
inline uint32_t& EVENT_MSEC(uint8_t* data) { return *reinterpret_cast<uint32_t*>(data+EVENT_MSEC_OFFSET); }
inline uint32_t EVENT_MSEC(const uint8_t* data) { return *reinterpret_cast<const uint32_t*>(data+EVENT_MSEC_OFFSET); }

constexpr uint32_t EVENT_SERIAL_OFFSET = EVENT_MSEC_OFFSET + EVENT_MSEC_SIZE;
constexpr uint32_t EVENT_SERIAL_SIZE = sizeof(uint64_t);
inline uint64_t& EVENT_SERIAL(uint8_t* data) { return *reinterpret_cast<uint64_t*>(data+EVENT_SERIAL_OFFSET); }
inline uint64_t EVENT_SERIAL(const uint8_t* data) { return *reinterpret_cast<const uint64_t*>(data+EVENT_SERIAL_OFFSET); }

constexpr uint32_t EVENT_NUM_RECORDS_OFFSET = EVENT_SERIAL_OFFSET + EVENT_SERIAL_SIZE;
constexpr uint32_t EVENT_NUM_RECORDS_SIZE = sizeof(uint16_t);
inline uint16_t& EVENT_NUM_RECORDS(uint8_t* data) { return *reinterpret_cast<uint16_t*>(data+EVENT_NUM_RECORDS_OFFSET); }
inline uint16_t EVENT_NUM_RECORDS(const uint8_t* data) { return *reinterpret_cast<const uint16_t*>(data+EVENT_NUM_RECORDS_OFFSET); }

constexpr uint32_t EVENT_PRIORITY_OFFSET = EVENT_NUM_RECORDS_OFFSET + EVENT_NUM_RECORDS_SIZE;
constexpr uint32_t EVENT_PRIORITY_SIZE = sizeof(uint16_t);
inline uint16_t& EVENT_PRIORITY(uint8_t* data) { return *reinterpret_cast<uint16_t*>(data+EVENT_PRIORITY_OFFSET); }
inline uint16_t EVENT_PRIORITY(const uint8_t* data) { return *reinterpret_cast<const uint16_t*>(data+EVENT_PRIORITY_OFFSET); }

constexpr uint32_t EVENT_FLAGS_OFFSET = EVENT_PRIORITY_OFFSET + EVENT_PRIORITY_SIZE;
constexpr uint32_t EVENT_FLAGS_SIZE = sizeof(uint16_t);
inline uint16_t& EVENT_FLAGS(uint8_t* data) { return *reinterpret_cast<uint16_t*>(data+EVENT_FLAGS_OFFSET); }
inline uint16_t EVENT_FLAGS(const uint8_t* data) { return *reinterpret_cast<const uint16_t*>(data+EVENT_FLAGS_OFFSET); }

constexpr uint32_t EVENT_PID_OFFSET = EVENT_FLAGS_OFFSET + EVENT_FLAGS_SIZE;
constexpr uint32_t EVENT_PID_SIZE = sizeof(int32_t);
inline int32_t& EVENT_PID(uint8_t* data) { return *reinterpret_cast<int32_t*>(data+EVENT_PID_OFFSET); }
inline int32_t EVENT_PID(const uint8_t* data) { return *reinterpret_cast<const int32_t*>(data+EVENT_PID_OFFSET); }

constexpr uint32_t EVENT_RECORD_INDEX_OFFSET = EVENT_PID_OFFSET + EVENT_PID_SIZE;
constexpr uint32_t EVENT_RECORD_INDEX_SIZE(uint32_t num_records) { return sizeof(uint32_t) * num_records; }
inline uint32_t& EVENT_RECORD_INDEX_VALUE(uint8_t* data, int index) {
    return *reinterpret_cast<uint32_t*>(data+EVENT_RECORD_INDEX_OFFSET+sizeof(uint32_t)*index);
}

constexpr uint32_t EVENT_HEADER_SIZE(uint32_t num_records) { return EVENT_RECORD_INDEX_OFFSET + EVENT_RECORD_INDEX_SIZE(num_records); }


constexpr uint32_t RECORD_TYPE_OFFSET = 0;
constexpr uint32_t RECORD_TYPE_SIZE = sizeof(uint32_t);
inline uint32_t& RECORD_TYPE(uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<uint32_t*>(data+record_offset);
}
inline uint32_t RECORD_TYPE(const uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<const uint32_t*>(data+record_offset);
}

constexpr uint32_t RECORD_NUM_FIELDS_OFFSET = RECORD_TYPE_OFFSET + RECORD_TYPE_SIZE;
constexpr uint32_t RECORD_NUM_FIELDS_SIZE = sizeof(uint16_t);
inline uint16_t& RECORD_NUM_FIELDS(uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<uint16_t*>(data+record_offset+RECORD_NUM_FIELDS_OFFSET);
}
inline uint16_t RECORD_NUM_FIELDS(const uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<const uint16_t*>(data+record_offset+RECORD_NUM_FIELDS_OFFSET);
}

constexpr uint32_t RECORD_NAME_SIZE_OFFSET = RECORD_NUM_FIELDS_OFFSET + RECORD_NUM_FIELDS_SIZE;
constexpr uint32_t RECORD_NAME_SIZE_SIZE = sizeof(uint16_t);
inline uint16_t& RECORD_NAME_SIZE(uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<uint16_t*>(data+record_offset+RECORD_NAME_SIZE_OFFSET);
}
inline uint16_t RECORD_NAME_SIZE(const uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<const uint16_t*>(data+record_offset+RECORD_NAME_SIZE_OFFSET);
}

constexpr uint32_t RECORD_TEXT_SIZE_OFFSET = RECORD_NAME_SIZE_OFFSET + RECORD_NAME_SIZE_SIZE;
constexpr uint32_t RECORD_TEXT_SIZE_SIZE = sizeof(uint16_t);
inline uint16_t& RECORD_TEXT_SIZE(uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<uint16_t*>(data+record_offset+RECORD_TEXT_SIZE_OFFSET);
}
inline uint16_t RECORD_TEXT_SIZE(const uint8_t* data, uint32_t record_offset) {
    return *reinterpret_cast<const uint16_t*>(data+record_offset+RECORD_TEXT_SIZE_OFFSET);
}

constexpr uint32_t RECORD_FIELD_INDEX_OFFSET = RECORD_TEXT_SIZE_OFFSET + RECORD_TEXT_SIZE_SIZE;
constexpr uint32_t RECORD_FIELD_INDEX_SIZE(uint16_t num_fields) { return sizeof(uint32_t) * num_fields; }

inline uint32_t RECORD_FIELD_SORTED_INDEX_OFFSET(uint16_t num_fields) {
    return RECORD_FIELD_INDEX_OFFSET + RECORD_FIELD_INDEX_SIZE(num_fields);
}

constexpr uint32_t RECORD_TYPE_NAME_OFFSET(uint16_t num_fields) { return RECORD_FIELD_INDEX_OFFSET + RECORD_FIELD_INDEX_SIZE(num_fields) * 2; }

inline char* RECORD_TYPE_NAME_PTR(uint8_t* data, uint32_t record_offset, uint16_t num_fields) {
    return reinterpret_cast<char*>(data+record_offset+RECORD_TYPE_NAME_OFFSET(num_fields));
}

inline const char* RECORD_TYPE_NAME_PTR(const uint8_t* data, uint32_t record_offset, uint16_t num_fields) {
    return reinterpret_cast<const char*>(data+record_offset+RECORD_TYPE_NAME_OFFSET(num_fields));
}

constexpr uint32_t RECORD_TEXT_OFFSET(uint16_t num_fields, uint16_t name_size) { return RECORD_FIELD_INDEX_OFFSET + RECORD_FIELD_INDEX_SIZE(num_fields) * 2 + name_size; }

inline char* RECORD_TEXT_PTR(uint8_t* data, uint32_t record_offset, uint16_t num_fields, uint16_t name_size) {
    return reinterpret_cast<char*>(data+record_offset+RECORD_TEXT_OFFSET(num_fields, name_size));
}

inline const char* RECORD_TEXT_PTR(const uint8_t* data, uint32_t record_offset, uint16_t num_fields, uint16_t name_size) {
    return reinterpret_cast<const char*>(data+record_offset+RECORD_TEXT_OFFSET(num_fields, name_size));
}

constexpr uint32_t RECORD_HEADER_SIZE(uint16_t num_fields, uint16_t name_size, uint16_t text_size) {
    return RECORD_TYPE_NAME_OFFSET(num_fields) + name_size + text_size;
}

constexpr uint32_t FIELD_TYPE_OFFSET = 0;
constexpr uint32_t FIELD_TYPE_SIZE = sizeof(uint16_t);
inline uint16_t& FIELD_TYPE(uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<uint16_t*>(data+record_offset+field_offset+FIELD_TYPE_OFFSET);
}
inline uint16_t FIELD_TYPE(const uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<const uint16_t*>(data+record_offset+field_offset+FIELD_TYPE_OFFSET);
}

constexpr uint32_t FIELD_NAME_SIZE_OFFSET = FIELD_TYPE_SIZE;
constexpr uint32_t FIELD_NAME_SIZE_SIZE = sizeof(uint16_t);
inline uint16_t& FIELD_NAME_SIZE(uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<uint16_t*>(data+record_offset+field_offset+FIELD_NAME_SIZE_OFFSET);
}
inline uint16_t FIELD_NAME_SIZE(const uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<const uint16_t*>(data+record_offset+field_offset+FIELD_NAME_SIZE_OFFSET);
}

constexpr uint32_t FIELD_RAW_SIZE_OFFSET = FIELD_NAME_SIZE_OFFSET + FIELD_NAME_SIZE_SIZE;
constexpr uint32_t FIELD_RAW_SIZE_SIZE = sizeof(uint32_t);
inline uint32_t& FIELD_RAW_SIZE(uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<uint32_t*>(data+record_offset+field_offset+FIELD_RAW_SIZE_OFFSET);
}
inline uint32_t FIELD_RAW_SIZE(const uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<const uint32_t*>(data+record_offset+field_offset+FIELD_RAW_SIZE_OFFSET);
}

constexpr uint32_t FIELD_INTERP_SIZE_OFFSET = FIELD_RAW_SIZE_OFFSET + FIELD_RAW_SIZE_SIZE;
constexpr uint32_t FIELD_INTERP_SIZE_SIZE = sizeof(uint32_t);
inline uint32_t& FIELD_INTERP_SIZE(uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<uint32_t*>(data+record_offset+field_offset+FIELD_INTERP_SIZE_OFFSET);
}
inline uint32_t FIELD_INTERP_SIZE(const uint8_t* data, uint32_t record_offset, uint32_t field_offset) {
    return *reinterpret_cast<const uint32_t*>(data+record_offset+field_offset+FIELD_INTERP_SIZE_OFFSET);
}

constexpr uint32_t FIELD_HEADER_SIZE = FIELD_INTERP_SIZE_OFFSET + FIELD_INTERP_SIZE_SIZE;
constexpr uint32_t FIELD_NAME_OFFSET = FIELD_HEADER_SIZE;

constexpr uint32_t FIELD_RAW_VALUE_OFFSET(uint16_t name_size) { return FIELD_NAME_OFFSET + name_size; }
constexpr uint32_t FIELD_INTERP_VALUE_OFFSET(uint16_t name_size, uint32_t raw_size) { return FIELD_NAME_OFFSET + name_size + raw_size; }

constexpr uint32_t EXTENSIONS_HEADER_SIZE = sizeof(uint32_t);
constexpr uint32_t EXTENSION_HEADER_SIZE = sizeof(uint32_t)*2;

inline uint32_t EXTENSIONS_OFFSET(const uint8_t* data) {
    return *reinterpret_cast<const uint32_t*>(data + (EVENT_SIZE(data) - sizeof(uint32_t)));
}

inline uint32_t& EXTENSIONS_OFFSET(uint8_t* data) {
    return *reinterpret_cast<uint32_t*>(data + (EVENT_SIZE(data) - sizeof(uint32_t)));
}

constexpr uint32_t EVENT_NUM_EXTENSIONS(const uint8_t* data, uint32_t offset) {
    return *reinterpret_cast<const uint32_t*>(data + offset + sizeof(uint32_t));
}

inline uint32_t& EVENT_NUM_EXTENSIONS(uint8_t* data, uint32_t offset) {
    return *reinterpret_cast<uint32_t*>(data + offset + sizeof(uint32_t));
}

constexpr uint32_t EXTENSIONS_INDEX_OFFSET(const uint8_t* data, uint32_t offset) {
    return *reinterpret_cast<const uint32_t*>(data + offset + (sizeof(uint32_t)*2));
}

inline uint32_t EXTENSION_OFFSET(const uint8_t* data, uint32_t offset, uint32_t index) {
    return reinterpret_cast<const uint32_t*>(data + offset + (sizeof(uint32_t)*2))[index];
}

inline uint32_t& EXTENSION_OFFSET(uint8_t* data, uint32_t offset, uint32_t index) {
    return reinterpret_cast<uint32_t*>(data + offset + (sizeof(uint32_t)*2))[index];
}

constexpr uint32_t EXTENSION_TYPE(const uint8_t* data, uint32_t offset) {
    return *reinterpret_cast<const uint32_t*>(data + offset);
}

inline uint32_t& EXTENSION_TYPE(uint8_t* data, uint32_t offset) {
    return *reinterpret_cast<uint32_t*>(data + offset);
}

constexpr uint32_t EXTENSION_SIZE(const uint8_t* data, uint32_t offset) {
    return *reinterpret_cast<const uint32_t*>(data + offset + sizeof(uint32_t));
}

inline uint32_t& EXTENSION_SIZE(uint8_t* data, uint32_t offset) {
    return *reinterpret_cast<uint32_t*>(data + offset + sizeof(uint32_t));
}

constexpr const void* EXTENSION_DATA(const uint8_t* data, uint32_t offset) {
    return data + offset + (sizeof(uint32_t)*2);
}

constexpr void* EXTENSION_DATA(uint8_t* data, uint32_t offset) {
    return data + offset + (sizeof(uint32_t)*2);
}

/*****************************************************************************
 ** EventBuilder
 *****************************************************************************/

bool EventBuilder::BeginEvent(uint64_t sec, uint32_t msec, uint64_t serial, uint16_t num_records) {
    if (_data != nullptr) {
        throw std::runtime_error("Event already started!");
    }

    if (num_records == 0) {
        throw std::runtime_error("num_records == 0!");
    }

    _extensions_offset = 0;
    _extension_idx = 0;
    _roffset = EVENT_HEADER_SIZE(num_records);
    _record_idx = 0;

    size_t size = _roffset;
    if (!_allocator->Allocate(reinterpret_cast<void**>(&_data), size)) {
        return false;
    }
    _size = size;

    SET_EVENT_VERSION(_data, 1);
    SET_EVENT_SIZE(_data, 0);
    EVENT_SEC(_data) = sec;
    EVENT_MSEC(_data) = msec;
    EVENT_SERIAL(_data) = serial;
    EVENT_NUM_RECORDS(_data) = num_records;
    EVENT_PRIORITY(_data) = 0;
    EVENT_FLAGS(_data) = 0;
    EVENT_PID(_data) = -1;

    return true;
}

void EventBuilder::SetEventPriority(uint16_t priority) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    EVENT_PRIORITY(_data) = priority;
}

uint16_t EventBuilder::GetEventPriority() {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    return EVENT_PRIORITY(_data);
}

void EventBuilder::AddEventFlags(uint16_t flags) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    EVENT_FLAGS(_data) |= flags;
}

uint16_t EventBuilder::GetEventFlags() {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    return EVENT_FLAGS(_data);
}

void EventBuilder::SetEventPid(int32_t pid) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    EVENT_PID(_data) = pid;
}

int32_t EventBuilder::GetEventPid() {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    return EVENT_PID(_data);
}

int EventBuilder::EndEvent() {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    if (_record_idx != EVENT_NUM_RECORDS(_data)) {
        throw std::runtime_error("EventRecord ended prematurely: Expected " + std::to_string(EVENT_NUM_RECORDS(_data)) + " records, only " + std::to_string(_record_idx) + " were added");
    }

    if (_extensions_offset != 0 &&  _extension_idx != EVENT_NUM_EXTENSIONS(_data, _extensions_offset)) {
        throw std::runtime_error("Event ended prematurely: Expected " + std::to_string(EVENT_NUM_EXTENSIONS(_data, _extensions_offset)) + " extensions, only " + std::to_string(_extension_idx) + " were added");
    }

    SET_EVENT_SIZE(_data, static_cast<uint32_t>(_size));

    if (_prioritizer) {
        Event event(_data, _size);
        SetEventPriority(_prioritizer->Prioritize(event));
    }

    _data = nullptr;
    _size = 0;
    return _allocator->Commit();
};

bool EventBuilder::CancelEvent() {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    SET_EVENT_SIZE(_data, 0);

    _data = nullptr;
    _size = 0;
    return _allocator->Rollback();
}

bool EventBuilder::BeginRecord(uint32_t record_type, const char* record_name, const char* record_text, uint16_t num_fields) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    size_t name_size = strlen(record_name);
    size_t text_size = strlen(record_text);

    return BeginRecord(record_type, std::string_view(record_name, name_size), std::string_view(record_text, text_size), num_fields);
}

bool EventBuilder::BeginRecord(uint32_t record_type, const std::string_view& record_name, const std::string_view& record_text, uint16_t num_fields) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    if (num_fields == 0) {
        throw std::runtime_error("num_field == 0!");
    }

    _num_fields = num_fields;
    _field_idx = 0;

    size_t name_size = record_name.size()+1;
    if (name_size > UINT16_MAX) {
        throw std::runtime_error("record_name length exceeds limit");
    }

    size_t text_size = record_text.size()+1;
    if (text_size > UINT16_MAX) {
        throw std::runtime_error("record_text length exceeds limit");
    }

    size_t record_hdr_size = RECORD_HEADER_SIZE(num_fields, static_cast<uint16_t>(name_size), static_cast<uint16_t>(text_size));
    size_t size = _size+record_hdr_size;
    if (!_allocator->Allocate(reinterpret_cast<void**>(&_data), size)) {
        return false;
    }
    _size = size;

    EVENT_RECORD_INDEX_VALUE(_data, _record_idx) = static_cast<uint32_t>(_roffset);
    RECORD_TYPE(_data, _roffset) = record_type;
    RECORD_NUM_FIELDS(_data, _roffset) = num_fields;
    RECORD_NAME_SIZE(_data, _roffset) = static_cast<uint16_t>(name_size);
    RECORD_TEXT_SIZE(_data, _roffset) = static_cast<uint16_t>(text_size);

    memcpy(RECORD_TYPE_NAME_PTR(_data, _roffset, num_fields), record_name.data(), record_name.size());
    RECORD_TYPE_NAME_PTR(_data, _roffset, num_fields)[name_size-1] = 0;

    memcpy(RECORD_TEXT_PTR(_data, _roffset, num_fields, static_cast<uint16_t>(name_size)), record_text.data(), record_text.size());
    RECORD_TEXT_PTR(_data, _roffset, num_fields, static_cast<uint16_t>(name_size))[text_size-1] = 0;

    _foffset = record_hdr_size;
    _fidxoffset = _roffset+RECORD_FIELD_INDEX_OFFSET;
    _fsortedidxoffset = _roffset+RECORD_FIELD_SORTED_INDEX_OFFSET(num_fields);

    return true;
}

bool EventBuilder::EndRecord() {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    if (_field_idx != _num_fields) {
        throw std::runtime_error("EventRecord ended prematurely: Expected " + std::to_string(_num_fields) + " fields, only " + std::to_string(_field_idx) + " where added");
    }

    // Sort fields
    memcpy(_data+_fsortedidxoffset, _data+_fidxoffset, sizeof(uint32_t)*_num_fields);
    uint32_t* start = INDEX_PTR(_data, _fsortedidxoffset, 0);
    uint32_t* end = INDEX_PTR(_data, _fsortedidxoffset, _num_fields);
    std::sort(start, end, [this](uint32_t a, uint32_t b) -> bool {
        return strcmp(CHAR_PTR(_data, _roffset+a+FIELD_NAME_OFFSET),
                      CHAR_PTR(_data, _roffset+b+FIELD_NAME_OFFSET)) < 0;
    });

    _record_idx += 1;
    _roffset = static_cast<uint32_t>(_size);

    return true;
}

bool EventBuilder::AddField(const char *field_name, const char* raw_value, const char* interp_value, field_type_t field_type) {
    size_t name_size = strlen(field_name);
    size_t raw_size = strlen(raw_value);
    std::string_view interp;
    if (interp_value != nullptr) {
        interp = std::string_view(interp_value, strlen(interp_value));
    }

    return AddField(std::string_view(field_name, name_size), std::string_view(raw_value, raw_size), interp, field_type);
}

bool EventBuilder::AddField(const std::string_view& field_name, const std::string_view& raw_value, const std::string_view& interp_value, field_type_t field_type) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    size_t name_size = field_name.size()+1;
    size_t raw_size = raw_value.size()+1;
    size_t fsize = FIELD_HEADER_SIZE + name_size + raw_size;
    size_t interp_size = interp_value.size();
    if (!interp_value.empty()) {
        interp_size = interp_value.size()+1;
        fsize += interp_size;
    }

    if (name_size > UINT16_MAX) {
        throw std::runtime_error("field_name length exceeds limit");
    }

    if (raw_size > UINT32_MAX) {
        throw std::runtime_error("raw_value length exceeds limit");
    }

    if (interp_size > UINT32_MAX) {
        throw std::runtime_error("interp_value length exceeds limit");
    }

    if (_field_idx >= _num_fields) {
        throw std::runtime_error("field count exceeds allocated number");
    }

    size_t size = _size+fsize;
    if (!_allocator->Allocate(reinterpret_cast<void**>(&_data), size)) {
        return false;
    }
    _size = size;

    FIELD_NAME_SIZE(_data, _roffset, _foffset) = static_cast<uint16_t>(name_size);
    FIELD_RAW_SIZE(_data, _roffset, _foffset) = static_cast<uint16_t>(raw_size);
    FIELD_INTERP_SIZE(_data, _roffset, _foffset) = static_cast<uint16_t>(interp_size);
    FIELD_TYPE(_data, _roffset, _foffset) = static_cast<uint16_t>(field_type);

    memcpy(_data + _roffset + _foffset + FIELD_NAME_OFFSET, field_name.data(), field_name.size());
    CHAR_PTR(_data, _roffset + _foffset + FIELD_NAME_OFFSET)[name_size-1] = 0;

    memcpy(_data + _roffset + _foffset + FIELD_RAW_VALUE_OFFSET(static_cast<uint16_t>(name_size)), raw_value.data(), raw_value.size());
    CHAR_PTR(_data, _roffset + _foffset + FIELD_RAW_VALUE_OFFSET(static_cast<uint16_t>(name_size)))[raw_size-1] = 0;

    if (interp_size > 0) {
        memcpy(_data + _roffset + _foffset + FIELD_INTERP_VALUE_OFFSET(static_cast<uint16_t>(name_size), static_cast<uint16_t>(raw_size)), interp_value.data(), interp_value.size());
        CHAR_PTR(_data, _roffset + _foffset + FIELD_INTERP_VALUE_OFFSET(static_cast<uint16_t>(name_size), static_cast<uint16_t>(raw_size)))[interp_size-1] = 0;
    }

    INDEX_VALUE(_data, _fidxoffset, _field_idx) = _foffset;

    _foffset += fsize;
    _field_idx += 1;

    return true;
}

int EventBuilder::GetFieldCount() {
    return _field_idx;
}

bool EventBuilder::BeginExtensions(uint32_t num_extensions) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    if (_record_idx != EVENT_NUM_RECORDS(_data)) {
        throw std::runtime_error("EventRecord ended prematurely: Expected " + std::to_string(EVENT_NUM_RECORDS(_data)) + " records, only " + std::to_string(_record_idx) + " were added");
    }

    size_t size = _size + EXTENSIONS_HEADER_SIZE + (sizeof(uint32_t) * num_extensions);
    if (!_allocator->Allocate(reinterpret_cast<void**>(&_data), size)) {
        return false;
    }
    _extensions_offset = _size;
    _size = size;
    _extension_idx = 0;
    _eoffset = _size;

    EVENT_NUM_EXTENSIONS(_data, _extensions_offset) = num_extensions;

    return true;
}

bool EventBuilder::AddExtension(uint32_t type, uint32_t data_size, void* data) {
    if (_data == nullptr) {
        throw std::runtime_error("Event not started!");
    }

    if (_extensions_offset == 0) {
        throw std::runtime_error("Event Extensions not started");
    }

    size_t size = _size + EXTENSION_HEADER_SIZE + data_size;
    if (!_allocator->Allocate(reinterpret_cast<void**>(&_data), size)) {
        return false;
    }

    EXTENSION_OFFSET(_data, _extensions_offset, _extension_idx) = _eoffset;
    EXTENSION_TYPE(_data, _eoffset) = type;
    EXTENSION_SIZE(_data, _eoffset) = data_size;
    memcpy(_data, data, size);

    _extension_idx += 1;
    _eoffset = _size;
    _size = size;

    return true;
}

bool EventBuilder::EndExtensions() {
    if (_extension_idx != EVENT_NUM_EXTENSIONS(_data, _extensions_offset)) {
        throw std::runtime_error("Event ended prematurely: Expected " + std::to_string(EVENT_NUM_EXTENSIONS(_data, _extensions_offset)) + " extensions, only " + std::to_string(_extension_idx) + " were added");
    }

    size_t size = _size+sizeof(uint32_t);
    if (!_allocator->Allocate(reinterpret_cast<void**>(&_data), size)) {
        return false;
    }
    _size = size;

    SET_EVENT_SIZE(_data, static_cast<uint32_t>(_size));
    EXTENSIONS_OFFSET(_data) - _extensions_offset;
    EVENT_FLAGS(_data) |= EVENT_FLAG_HAS_EXTENSIONS;


    return true;
}

/*****************************************************************************
 ** EventRecordField
 *****************************************************************************/

const char* EventRecordField::FieldNamePtr() const {
    return CHAR_PTR(_data, _roffset + _foffset + FIELD_NAME_OFFSET);
}

uint16_t EventRecordField::FieldNameSize() const {
    return FIELD_NAME_SIZE(_data, _roffset, _foffset) - static_cast<uint16_t>(1);
}

std::string_view EventRecordField::FieldName() const {
    return std::string_view(CHAR_PTR(_data, _roffset + _foffset + FIELD_NAME_OFFSET),
                            FIELD_NAME_SIZE(_data, _roffset, _foffset) - static_cast<uint16_t>(1));
}

const char* EventRecordField::RawValuePtr() const {
    return CHAR_PTR(_data, _roffset + _foffset + FIELD_RAW_VALUE_OFFSET(FIELD_NAME_SIZE(_data, _roffset, _foffset)));
}

uint32_t EventRecordField::RawValueSize() const {
    return FIELD_RAW_SIZE(_data, _roffset, _foffset) - static_cast<uint16_t>(1);
}

std::string_view EventRecordField::RawValue() const {
    return std::string_view(CHAR_PTR(_data, _roffset + _foffset + FIELD_RAW_VALUE_OFFSET(FIELD_NAME_SIZE(_data, _roffset, _foffset))),
                            FIELD_RAW_SIZE(_data, _roffset, _foffset) - static_cast<uint16_t>(1));
}

const char* EventRecordField::InterpValuePtr() const {
    if (FIELD_INTERP_SIZE(_data, _roffset, _foffset) > 0) {
        return CHAR_PTR(_data, _roffset + _foffset + FIELD_INTERP_VALUE_OFFSET(
                FIELD_NAME_SIZE(_data, _roffset, _foffset),
                FIELD_RAW_SIZE(_data, _roffset, _foffset)
        ));
    } else {
        return nullptr;
    }
}

uint32_t EventRecordField::InterpValueSize() const {
    if (FIELD_INTERP_SIZE(_data, _roffset, _foffset) > 0) {
        return FIELD_INTERP_SIZE(_data, _roffset, _foffset) - static_cast<uint16_t>(1);
    } else {
        return 0;
    }
}

std::string_view EventRecordField::InterpValue() const {
    if (FIELD_INTERP_SIZE(_data, _roffset, _foffset) > 0) {
        return std::string_view(CHAR_PTR(_data, _roffset + _foffset + FIELD_INTERP_VALUE_OFFSET(
                                         FIELD_NAME_SIZE(_data, _roffset, _foffset),
                                         FIELD_RAW_SIZE(_data, _roffset, _foffset))),
                                FIELD_INTERP_SIZE(_data, _roffset, _foffset) - static_cast<uint16_t>(1));
    } else {
        return std::string_view();
    }
}

field_type_t EventRecordField::FieldType() const {
    return static_cast<enum field_type_t>(FIELD_TYPE(_data, _roffset, _foffset));
}

uint32_t EventRecordField::RecordType() const {
    return RECORD_TYPE(_data, _roffset);
}

EventRecord EventRecordField::Record() const {
    return EventRecord(_data, _index);
}

EventRecordField::EventRecordField(const uint8_t* data, uint32_t roffset, uint32_t fidxoffset, uint32_t index) {
    _data = data;
    _roffset = roffset;
    _fidxoffset = fidxoffset;
    _index = index;
    if (_index < RECORD_NUM_FIELDS(_data, _roffset)) {
        _foffset = INDEX_VALUE(_data, _fidxoffset, _index);
    } else {
        _foffset = EVENT_SIZE(_data);
    }
}

void EventRecordField::move(int32_t n) {
    _index += n;
    if (_index < RECORD_NUM_FIELDS(_data, _roffset)) {
        _foffset = INDEX_VALUE(_data, _fidxoffset, _index);
    } else {
        _foffset = EVENT_SIZE(_data);
    }
}

/*****************************************************************************
 ** EventRecord
 *****************************************************************************/

uint32_t EventRecord::RecordType() const {
    return RECORD_TYPE(_data, _roffset);
}

const char* EventRecord::RecordTypeNamePtr() const {
    return RECORD_TYPE_NAME_PTR(_data, _roffset, RECORD_NUM_FIELDS(_data, _roffset));
}

uint16_t EventRecord::RecordTypeNameSize() const {
    return RECORD_NAME_SIZE(_data, _roffset) - static_cast<uint16_t>(1);
}

std::string_view EventRecord::RecordTypeName() const {
    return std::string_view(RECORD_TYPE_NAME_PTR(_data, _roffset, RECORD_NUM_FIELDS(_data, _roffset)),
                            RECORD_NAME_SIZE(_data, _roffset) - static_cast<uint16_t>(1));
}

const char* EventRecord::RecordTextPtr() const {
    return RECORD_TEXT_PTR(_data, _roffset, RECORD_NUM_FIELDS(_data, _roffset), RECORD_NAME_SIZE(_data, _roffset));
}

uint16_t EventRecord::RecordTextSize() const {
    return RECORD_TEXT_SIZE(_data, _roffset) - static_cast<uint16_t>(1);
}

std::string_view EventRecord::RecordText() const {
    return std::string_view(RECORD_TEXT_PTR(_data, _roffset, RECORD_NUM_FIELDS(_data, _roffset), RECORD_NAME_SIZE(_data, _roffset)),
                            RECORD_TEXT_SIZE(_data, _roffset) - static_cast<uint16_t>(1));
}

uint16_t EventRecord::NumFields() const {
    return RECORD_NUM_FIELDS(_data, _roffset);
}

EventRecordField EventRecord::FieldAt(uint32_t idx) const {
    if (idx >= RECORD_NUM_FIELDS(_data, _roffset)) {
        throw std::out_of_range("Field index out of range for EventRecord: " + std::to_string(idx));
    }
    return EventRecordField(
            _data,
            _roffset,
            _roffset+RECORD_FIELD_INDEX_OFFSET,
            idx
    );

}

EventRecordField EventRecord::FieldByName(const std::string_view& name) const {
    uint16_t num_fields = RECORD_NUM_FIELDS(_data, _roffset);
    if (num_fields == 0) {
        throw std::out_of_range("Record has no fields");
    }
    uint32_t idxoffset = _roffset+RECORD_FIELD_SORTED_INDEX_OFFSET(num_fields);
    const uint32_t* start = INDEX_PTR(_data, idxoffset, 0);
    const uint32_t* end = INDEX_PTR(_data, idxoffset, num_fields);

    auto res = std::lower_bound(start, end, name, [this](uint32_t e, const std::string_view& v) -> bool {
        return v.compare(CHAR_PTR(this->_data, this->_roffset + e + FIELD_NAME_OFFSET)) > 0;
    });

    if (res == end) {
        return EventRecordField();
    }

    const char* found = CHAR_PTR(_data, _roffset + *res + FIELD_NAME_OFFSET);

    if (name.compare(found) != 0) {
        return EventRecordField();
    }

    return EventRecordField(
            _data,
            _roffset,
            _roffset+RECORD_FIELD_SORTED_INDEX_OFFSET(num_fields),
            static_cast<uint32_t>(res - start)
    );
}

EventRecordField EventRecord::begin() const {
    if (NumFields() > 0) {
        return EventRecordField(
                _data,
                _roffset,
                _roffset + RECORD_FIELD_INDEX_OFFSET,
                0
        );
    } else {
        throw std::out_of_range("Record has no fields");
    }
}

EventRecordField EventRecord::end() const {
    if (NumFields() > 0) {
        return EventRecordField(
                _data,
                _roffset,
                _roffset+RECORD_FIELD_INDEX_OFFSET,
                RECORD_NUM_FIELDS(_data, _roffset)
        );
    } else {
        throw std::out_of_range("Record has no fields");
    }
}

EventRecordField EventRecord::begin_sorted() const {
    if (NumFields() > 0) {
        return EventRecordField(
                _data,
                _roffset,
                _roffset+RECORD_FIELD_SORTED_INDEX_OFFSET(RECORD_NUM_FIELDS(_data, _roffset)),
                0
        );
    } else {
        throw std::out_of_range("Record has no fields");
    }
}

EventRecordField EventRecord::end_sorted() const {
    if (NumFields() > 0) {
        return EventRecordField(
                _data,
                _roffset,
                _roffset+RECORD_FIELD_SORTED_INDEX_OFFSET(RECORD_NUM_FIELDS(_data, _roffset)),
                RECORD_NUM_FIELDS(_data, _roffset)
        );
    } else {
        throw std::out_of_range("Record has no fields");
    }
}

EventRecord::EventRecord(const uint8_t* data, uint32_t index) {
    _data = data;
    _index = index;
    if (_index < EVENT_NUM_RECORDS(_data)) {
        _roffset = INDEX_VALUE(_data, EVENT_RECORD_INDEX_OFFSET, _index);
    } else {
        _roffset = EVENT_SIZE(_data);
    }
}

void EventRecord::move(int32_t n) {
    _index += n;
    if (_index < EVENT_NUM_RECORDS(_data)) {
        _roffset = INDEX_VALUE(_data, EVENT_RECORD_INDEX_OFFSET, _index);
    } else {
        _roffset = EVENT_SIZE(_data);
    }
}

/*****************************************************************************
 ** EventExtension
 *****************************************************************************/

uint32_t EventExtension::Type() const {
    return EXTENSION_TYPE(_data, _eoffset);
}

uint32_t EventExtension::Size() const {
    return EXTENSION_SIZE(_data, _eoffset);
}

const void* EventExtension::Data() const {
    return EXTENSION_DATA(_data, _eoffset);
}

EventExtension::EventExtension(const uint8_t* data, uint32_t offset, uint32_t index) {
    _data = data;
    _offset = offset;
    _index = index;
    if (_index < EVENT_NUM_EXTENSIONS(_data, _offset)) {
        _eoffset = EXTENSION_OFFSET(_data, _offset, _index);
    } else {
        _eoffset = EVENT_SIZE(_data);
    }
}

void EventExtension::move(int32_t n) {
    _index += n;
    if (_index < EVENT_NUM_EXTENSIONS(_data, _offset)) {
        _eoffset = EXTENSION_OFFSET(_data, _offset, _index);
    } else {
        _eoffset = EVENT_SIZE(_data);
    }
}

/*****************************************************************************
 ** EventExtensions
 *****************************************************************************/

uint32_t EventExtensions::NumExtensions() const {
    if (_data != nullptr) {
        return EVENT_NUM_EXTENSIONS(_data, _offset);
    }
    return 0;
}

EventExtension EventExtensions::ExtensionAt(uint32_t index) const {
    if (_data == nullptr || index >= EVENT_NUM_EXTENSIONS(_data, _offset)) {
        throw std::out_of_range("Extension index out of range for event: " + std::to_string(index));
    }
    return EventExtension(_data, _offset, index);
}

EventExtension EventExtensions::begin() const {
    if (_data != nullptr && EVENT_NUM_EXTENSIONS(_data, _offset) > 0) {
        return EventExtension(_data, _offset, 0);
    } else {
        throw std::out_of_range("Event has no extensions");
    }
}

EventExtension EventExtensions::end() const {
    if (_data != nullptr && EVENT_NUM_EXTENSIONS(_data, _offset) > 0) {
        return EventExtension(_data, _offset, EVENT_NUM_EXTENSIONS(_data, _offset));
    } else {
        throw std::out_of_range("Event has no extensions");
    }
}


/*****************************************************************************
 ** Event
 *****************************************************************************/

const void* Event::Data() const {
    return _data;
}

uint32_t Event::Size() const {
    return EVENT_SIZE(_data);
}

uint64_t Event::Seconds() const {
    return EVENT_SEC(_data);
}

uint32_t Event::Milliseconds() const {
    return EVENT_MSEC(_data);
}

uint64_t Event::Serial() const {
    return EVENT_SERIAL(_data);
}

uint16_t Event::NumRecords() const {
    return EVENT_NUM_RECORDS(_data);
}

uint16_t Event::Priority() const {
    return EVENT_PRIORITY(_data);
}

uint16_t Event::Flags() const {
    return EVENT_FLAGS(_data);
}

int32_t Event::Pid() const {
    return EVENT_PID(_data);
}

EventRecord Event::RecordAt(uint32_t index) const {
    if (index >= EVENT_NUM_RECORDS(_data)) {
        throw std::out_of_range("Record index out of range for event: " + std::to_string(index));
    }
    return EventRecord(_data, index);
}

EventRecord Event::begin() const {
    if (EVENT_NUM_RECORDS(_data) > 0) {
        return EventRecord(_data, 0);
    } else {
        throw std::out_of_range("Event has no records");
    }
}

EventRecord Event::end() const {
    if (EVENT_NUM_RECORDS(_data) > 0) {
        return EventRecord(_data, EVENT_NUM_RECORDS(_data));
    } else {
        throw std::out_of_range("Event has no records");
    }
}

uint32_t Event::NumExtensions() const {
    if ((EVENT_FLAGS(_data) & EVENT_FLAG_HAS_EXTENSIONS) == 0) {
        return 0;
    }
    return EVENT_NUM_EXTENSIONS(_data, EXTENSIONS_OFFSET(_data));
}

uint32_t Event::ExtensionTypeAt(uint32_t index) const {
    if ((EVENT_FLAGS(_data) & EVENT_FLAG_HAS_EXTENSIONS) == 0 || index >= EVENT_NUM_EXTENSIONS(_data, EXTENSIONS_OFFSET(_data))) {
        throw std::out_of_range("Extension index out of range for event: " + std::to_string(index));
    }
    return EXTENSION_TYPE(_data, EXTENSION_OFFSET(_data, EXTENSIONS_OFFSET(_data), index));
}

EventExtension Event::ExtensionAt(uint32_t index) const {
    if ((EVENT_FLAGS(_data) & EVENT_FLAG_HAS_EXTENSIONS) == 0 || index >= EVENT_NUM_EXTENSIONS(_data, EXTENSIONS_OFFSET(_data))) {
        throw std::out_of_range("Extension index out of range for event: " + std::to_string(index));
    }
    return EventExtension(_data, EXTENSIONS_OFFSET(_data), index);
}

EventExtensions Event::Extensions() const {
    if ((EVENT_FLAGS(_data) & EVENT_FLAG_HAS_EXTENSIONS) == 0) {
        return EventExtensions(nullptr, 0);
    }
    return EventExtensions(_data, EXTENSIONS_OFFSET(_data));
}

int Event::Validate() const {
    if (_size <= EVENT_RECORD_INDEX_OFFSET) {
        return 1;
    }

    size_t offset = EVENT_RECORD_INDEX_OFFSET+EVENT_NUM_RECORDS(_data)*sizeof(uint32_t);

    if (_size <= offset) {
        return 2;
    }

    for (int ridx = 0; ridx < EVENT_NUM_RECORDS(_data); ++ridx) {
        auto roffset = INDEX_VALUE(_data, EVENT_RECORD_INDEX_OFFSET, ridx);

        if (offset != roffset) {
            return 3;
        }

        offset += RECORD_FIELD_INDEX_OFFSET;
        if (_size <= roffset + RECORD_FIELD_INDEX_OFFSET) {
            return 4;
        }

        offset += RECORD_NUM_FIELDS(_data, roffset)*sizeof(uint32_t)*2;
        if (_size <= offset) {
            return 5;
        }

        if (offset != roffset + RECORD_TYPE_NAME_OFFSET(RECORD_NUM_FIELDS(_data, roffset))) {
            return 6;
        }

        offset += RECORD_NAME_SIZE(_data, roffset);

        if (_size <= offset) {
            return 6;
        }

        if (offset != roffset + RECORD_TEXT_OFFSET(RECORD_NUM_FIELDS(_data, roffset), RECORD_NAME_SIZE(_data, roffset))) {
            return 7;
        }

        offset += RECORD_TEXT_SIZE(_data, roffset);

        if (_size <= offset) {
            return 7;
        }

        for (int fidx = 0; fidx < RECORD_NUM_FIELDS(_data, roffset); ++fidx) {
            auto foffset = INDEX_VALUE(_data, roffset + RECORD_FIELD_INDEX_OFFSET, fidx);

            if (offset != roffset + foffset) {
                return 8;
            }

            offset += FIELD_INTERP_SIZE_OFFSET + FIELD_INTERP_SIZE_SIZE;
            if (_size <= offset) {
                return 9;
            }

            offset += FIELD_NAME_SIZE(_data, roffset, foffset);
            if (_size < offset) {
                return 10;
            }

            offset += FIELD_RAW_SIZE(_data, roffset, foffset);
            if (_size < offset) {
                return 11;
            }

            offset += FIELD_INTERP_SIZE(_data, roffset, foffset);
            if (_size < offset) {
                return 12;
            }
        }
    }
    return 0;
}

std::string EventToRawText(const Event& event, bool include_interp) {
    std::string id;
    std::string msec;
    msec.resize(4, 0);
    snprintf(msec.data(), 4, "%03d", event.Milliseconds());
    msec.resize(3);
    id.append("audit(");
    id.append(std::to_string(event.Seconds()));
    id.append(".");
    id.append(msec);
    id.append(":");
    id.append(std::to_string(event.Serial()));
    id.append("):");

    std::string out;

    for (auto& rec : event) {
        out.append("type=");
        out.append(rec.RecordTypeName());
        out.append(" ");
        out.append(id);
        for (auto& f: rec) {
            out.append(" ");
            out.append(f.FieldName());
            out.append("=");
            out.append(f.RawValue());
            if (include_interp && f.InterpValueSize() > 0) {
                out.append("(");
                out.append(f.InterpValue());
                out.append(")");
            }
        }
        out.append("\n");
    }

    return out;
}
