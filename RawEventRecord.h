/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_RAWEVENTRECORD_H
#define AUOMS_RAWEVENTRECORD_H

#include <array>
#include <string>
#include <string_view>
#include <vector>

#include "Event.h"
#include "EventId.h"
#include "RecordType.h"

class RawEventRecord {
public:
    static constexpr size_t MAX_RECORD_SIZE = 9*1024; // MAX_AUDIT_MESSAGE_LENGTH in libaudit.h is 8970

    explicit RawEventRecord(): _record_fields(128), _unparsable(false) {}

    inline char* Data() { return _data.data(); };

    bool Parse(RecordType record_type, size_t size);
    bool AddRecord(EventBuilder& builder);

    inline EventId GetEventId() { return _event_id; }
    inline RecordType GetRecordType() { return _record_type; }
    inline size_t GetSize() { return _size; }
    inline bool IsEmpty() { return _record_fields.empty(); }

private:
    std::array<char, MAX_RECORD_SIZE> _data;
    size_t _size;
    RecordType _record_type;
    std::string_view _node;
    std::string _node_str;
    std::string_view _type_name;
    std::string _type_name_str;
    EventId _event_id;
    std::vector<std::pair<std::string_view,std::string_view>> _record_fields;
    bool _unparsable;
};


#endif //AUOMS_RAWEVENTRECORD_H
