/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <iostream>

#include "RawEventRecord.h"
#include "Translate.h"
#include "StringUtils.h"

using namespace std::literals;

class RecordFieldIterator {
public:
    explicit RecordFieldIterator(std::string_view str): _str(str), _idx(0) {}

    // Advance to the next space delimited text
    // _val is set, _key is blank
    bool next_text() {
        static auto SV_WSP = " \n"sv;

        if (_idx == std::string_view::npos || _idx >= _str.size()) {
            return false;
        }
        auto idx = _str.find_first_of(SV_WSP, _idx);
        if (idx == std::string_view::npos) {
            idx = _str.size();
        }
        _val = _str.substr(_idx, idx-_idx);
        _idx = _str.find_first_not_of(SV_WSP, idx);
        return true;
    }

    // Advance to the next key=value
    bool next_kv() {
        static auto SV_MSG = "msg"sv;
        static auto SV_WSP = " \n"sv;
        static auto SV_WSPQ = "' \n"sv;
        static auto SV_SP = " "sv;
        static auto SV_EQ = "="sv;
        static auto SV_DQ = "\""sv;

        if (_idx == std::string_view::npos || _idx >= _str.size()) {
            return false;
        }

        // Find the '='
        auto idx = _str.find_first_of(SV_EQ, _idx);
        if (idx == std::string_view::npos) {
            // No '=' found, assume remainder of text is unparsable
            idx = _str.size();
            _val = _str.substr(_idx, idx-_idx);
            _key = std::string_view(); // Make _key empty to signal that _val has remainder of text
            return true;
        }

        _key = _str.substr(_idx, idx-_idx);
        idx += 1; // Skip past the '='
        _idx = idx; // Set _idx to start of value

        // For certain record types, some of the data is inside a "msg='...'" field.
        if (_key == SV_MSG && _str[_idx] == '\'') {
            _idx += 1; // Skip past the (') char
            return next_kv();
        } else {
            if (_str[_idx] == '"') {
                // Value is double quoted, look for end quote
                idx = _str.find_first_of(SV_DQ, _idx+1);
                if (idx == std::string_view::npos) {
                    idx = _str.size();
                } else {
                    idx += 1; // Include end quote
                }
            } else {
                // Value is not double quoted, value ends at first white space or single quote
                idx = _str.find_first_of(SV_WSPQ, _idx);
                if (idx == std::string_view::npos) {
                    idx = _str.size();
                }
            }
            _val = _str.substr(_idx, idx-_idx);
            // Advance _idx to start of next kv (skip past white space and single quote
            _idx = _str.find_first_not_of(SV_WSPQ, idx);
        }
        return true;
    }

    inline std::string_view key() {
        return _key;
    }

    inline std::string_view value() {
        return _val;
    }

    inline std::string_view remainder() {
        return _str.substr(_idx);
    }

private:
    std::string_view _str;
    std::string_view _key;
    std::string_view _val;
    size_t _idx;
};

bool RawEventRecord::Parse(RecordType record_type, size_t size) {
    static auto SV_NODE = "node="sv;
    static auto SV_TYPE = "type="sv;
    static auto SV_MSG = "msg="sv;
    static auto SV_AUDIT_BEGIN = "audit("sv;
    static auto SV_AUDIT_END = "):"sv;

    _size = size;
    _record_type = record_type;
    _record_fields.resize(0);
    std::string_view str = std::string_view(_data.data(), _size);
    RecordFieldIterator itr(str);
    if (!itr.next_text()) {
        return false;
    }

    // Event record prefixes have three possible formats:
    //  From the dispatcher (audisp)
    //      node=<> type=<> msg=audit(<sec>.<msec>:<serial>): <...>
    //      type=<> msg=audit(<sec>.<msec>:<serial>): <...>
    //  From the kernel:
    //      audit(<sec>.<msec>:<serial>): <...>
    //

    if (starts_with(itr.value(), SV_NODE)) {
        _node = itr.value().substr(5);
        if (!itr.next_text()) {
            return false;
        }
    } else {
        _node = std::string_view();
    }

    if (starts_with(itr.value(), SV_TYPE)) {
        _type_name = itr.value().substr(5);
        if (!itr.next_text()) {
            return false;
        }
    } else {
        _type_name = std::string_view();
    }

    if (_type_name.empty() && _record_type != RecordType::UNKNOWN) {
        _type_name = RecordTypeToName(_record_type, _type_name_str);
    } else if (!_type_name.empty() && _record_type == RecordType::UNKNOWN) {
        _record_type = RecordNameToType(std::string(_type_name));
    }

    auto val = itr.value();
    if (starts_with(val, SV_MSG)) {
        val = val.substr(4);
    }

    if (starts_with(val, SV_AUDIT_BEGIN) && ends_with(val, SV_AUDIT_END)) {
        auto event_id_str = val.substr(SV_AUDIT_BEGIN.size(), val.size()-(SV_AUDIT_BEGIN.size()+SV_AUDIT_END.size()));
        auto pidx = event_id_str.find_first_of('.');
        if (pidx == std::string_view::npos) {
            return false;
        }
        auto cidx = event_id_str.find_first_of(':', pidx);
        if (cidx == std::string_view::npos) {
            return false;
        }
        auto sec_str = event_id_str.substr(0, pidx);
        auto msec_str = event_id_str.substr(pidx+1, 3);
        auto ser_str = event_id_str.substr(cidx+1);
        try {
            uint64_t sec = static_cast<uint64_t>(std::stoll(std::string(sec_str.data(), sec_str.size()), 0));
            uint32_t msec = static_cast<uint32_t>(std::stoi(std::string(msec_str.data(), msec_str.size()), 0));
            uint64_t ser = static_cast<uint64_t>(std::stoll(std::string(ser_str.data(), ser_str.size()), 0));
            _event_id = EventId(sec, msec, ser);
        } catch (std::invalid_argument&) {
            _event_id = EventId();
            return false;
        } catch (std::out_of_range&) {
            _event_id = EventId();
            return false;
        }

        // The IMA code does't follow the proper audit message format so take the whole message
        if (_record_type == RecordType::INTEGRITY_POLICY_RULE) {
            _record_fields.emplace_back(std::make_pair(std::string_view(),itr.remainder()));
            _unparsable = true;
            return true;
        }

        while(itr.next_kv()) {
            _record_fields.emplace_back(std::make_pair(itr.key(),itr.value()));
        }
        return true;
    }

    return false;
}

bool RawEventRecord::AddRecord(EventBuilder& builder) {
    static auto SV_NODE = "node"sv;
    static auto SV_UNPARSED_TEXT = "unparsed_text"sv;
    static auto SV_EMPTY = ""sv;

    uint16_t num_fields = static_cast<uint16_t>(_record_fields.size());
    if (!_node.empty()) {
        num_fields++;
    }

    if (!builder.BeginRecord(static_cast<uint32_t>(_record_type), _type_name, std::string_view(_data.data(), _size), num_fields)) {
        return false;
    }

    if (!_node.empty()) {
        if (!builder.AddField(SV_NODE, _node, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
            return false;
        }
    }

    // If record is marked as unparsable, then the text (after the 'audit():' section is included as the only value in
    // _record_fields
    if (_unparsable) {
        if (!builder.AddField(SV_UNPARSED_TEXT, _record_fields[0].second, SV_EMPTY, field_type_t::UNESCAPED)) {
            return false;
        }
        return builder.EndRecord();
    }

    int unknown_key = 1;
    for (auto& f: _record_fields) {
        int ret;
        if (!f.first.empty()) {
            ret = builder.AddField(f.first, f.second, SV_EMPTY, field_type_t::UNCLASSIFIED);
        } else {
            std::string key = "unknown" + std::to_string(unknown_key);
            ret = builder.AddField(key, f.second, SV_EMPTY, field_type_t::UNCLASSIFIED);
            unknown_key += 1;
        }
        if (!ret) {
            return ret;
        }
    }

    return builder.EndRecord();
}
