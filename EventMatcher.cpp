/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "EventMatcher.h"

#include "RecordType.h"
#include "Translate.h"
#include "StringUtils.h"

#include <cassert>
#include <sstream>
#include <re2/re2.h>
#include <re2/set.h>
#include <re2/stringpiece.h>

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"

static std::unordered_map<std::string, FieldMatchRuleOp> s_opName2op = {
    {"eq", FIELD_OP_EQ},
    {"!eq", FIELD_OP_NEQ},
    {"in", FIELD_OP_IN},
    {"!in", FIELD_OP_NIN},
    {"re", FIELD_OP_RE},
    {"!re", FIELD_OP_NRE},
};

/****************************************************************************
 *
 ****************************************************************************/

std::shared_ptr<FieldMatchRule> FieldMatchRule::FromJSON(const rapidjson::Value& value) {
    if (!value.IsObject()) {
        throw new std::invalid_argument("FieldMatchRule::FromJSON(): value is not a JSON object");
    }

    std::string name;
    std::string op_name;
    FieldMatchRuleOp op;
    std::vector<std::string> values;

    auto m = value.FindMember("name");
    if (m == value.MemberEnd()) {
        throw new std::invalid_argument("FieldMatchRule::FromJSON(): Missing 'name'");
    }
    name = m->value.GetString();

    m = value.FindMember("op");
    if (m == value.MemberEnd()) {
        throw new std::invalid_argument("FieldMatchRule::FromJSON(): Missing 'op'");
    }
    op_name = m->value.GetString();

    m = value.FindMember("value");
    if (m != value.MemberEnd()) {
        if (value.HasMember("values")) {
            throw new std::invalid_argument("FieldMatchRule::FromJSON(): Only one of 'value' or 'values' is allowed");
        }

        if (!m->value.IsString()) {
            throw new std::invalid_argument("FieldMatchRule::FromJSON(): Invalid JSON type for 'value', must be a string");
        }
        values.emplace_back(m->value.GetString());
    } else {
        m = value.FindMember("values");
        
        if (m == value.MemberEnd()) {
            throw new std::invalid_argument("FieldMatchRule::FromJSON(): Missing values, one of 'value' or 'values' required");
        }
        if (!m->value.IsArray()) {
            throw new std::invalid_argument("FieldMatchRule::FromJSON(): Invalid JSON type for 'values', must be an array");
        }
        if (m->value.Size() == 0) {
            throw new std::invalid_argument("FieldMatchRule::FromJSON(): 'values' array is empty");
        }
        values.reserve(m->value.Size());
        for (auto it = m->value.Begin(); it != m->value.End(); ++it) {
            if (!it->IsString()) {
                throw new std::invalid_argument("FieldMatchRule::FromJSON(): Invalid JSON type for entry in 'values' array");
            }
            values.emplace_back(it->GetString());
        }
    }

    std::transform(op_name.begin(), op_name.end(), op_name.begin(), [](unsigned char c){ return std::tolower(c); });

    auto opit = s_opName2op.find(op_name);
    if (opit == s_opName2op.end()) {
            throw new std::invalid_argument(std::string("FieldMatchRule::FromJSON(): Invalid op value: ") + op_name);
    }

    return std::make_shared<FieldMatchRule>(name, opit->second, values);
}

std::shared_ptr<FieldMatchRule> FieldMatchRule::FromJSON(const std::string& str) {
    rapidjson::Document doc;
    doc.Parse(str.c_str());
    if (doc.HasParseError()) {
        throw std::runtime_error(rapidjson::GetParseError_En(doc.GetParseError()));
    }
    return FromJSON(doc);
}

void FieldMatchRule::ToJSON(rapidjson::Writer<rapidjson::StringBuffer>& writer) const {
    writer.StartObject();
    writer.Key("name");
    writer.String(_name.data(), _name.size());
    writer.Key("op");
    switch(_op) {
    case FIELD_OP_EQ:
        writer.String("eq");
        break;
    case FIELD_OP_NEQ:
        writer.String("!eq");
        break;
    case FIELD_OP_IN:
        writer.String("in");
        break;
    case FIELD_OP_NIN:
        writer.String("!in");
        break;
    case FIELD_OP_RE:
        writer.String("re");
        break;
    case FIELD_OP_NRE:
        writer.String("!re");
        break;
    default:
        writer.String("unknown");
        break;
    }
    if (_values.size() < 2) {
        writer.Key("value");
        writer.String(_values[0].data(), _values[0].size());
    } else {
        writer.StartArray();
        for (auto& s : _values) {
            writer.String(s.data(), s.size());
        }
        writer.EndArray();
    }
    writer.EndObject();
}

std::string FieldMatchRule::ToJSONString() const {
    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
    ToJSON(writer);
    return std::string(buf.GetString(), buf.GetSize());
}

/****************************************************************************
 *
 ****************************************************************************/

std::shared_ptr<EventMatchRule> EventMatchRule::FromJSON(const rapidjson::Value& value) {
    if (!value.IsObject()) {
        throw new std::invalid_argument("EventMatchRule::FromJSON(): value is not a JSON object");
    }

    auto m = value.FindMember("record_types");
    if (m == value.MemberEnd()) {
        throw new std::invalid_argument("EventMatchRule::FromJSON(): Missing 'record_types'");
    }
    std::unordered_set<RecordType> rctypes;
    if (!m->value.IsArray()) {
        throw new std::invalid_argument("EventMatchRule::FromJSON(): Invalid JSON type for 'record_types', must be an array");
    }
    if (m->value.Size() == 0) {
        throw new std::invalid_argument("EventMatchRule::FromJSON(): 'record_types' array is empty");
    }
    for (auto it = m->value.Begin(); it != m->value.End(); ++it) {
        if (!it->IsString()) {
            throw new std::invalid_argument("EventMatchRule::FromJSON(): Invalid JSON type for entry in 'record_types' array");
        }
        auto rc = RecordNameToType(std::string_view(it->GetString(), it->GetStringLength()));
        rctypes.emplace(rc);
    }

    m = value.FindMember("field_rules");
    if (m == value.MemberEnd()) {
        throw new std::invalid_argument("EventMatchRule::FromJSON(): Missing 'field_rules'");
    }
    if (!m->value.IsArray()) {
        throw new std::invalid_argument("EventMatchRule::FromJSON(): Invalid JSON type for 'field_rules', must be an array");
    }
    if (m->value.Size() == 0) {
        throw new std::invalid_argument("EventMatchRule::FromJSON(): 'field_rules' array is empty");
    }
    std::vector<std::shared_ptr<FieldMatchRule>> rules;
    rules.reserve(m->value.Size());
    for (auto it = m->value.Begin(); it != m->value.End(); ++it) {
        rules.emplace_back(FieldMatchRule::FromJSON(*it));
    }

    return std::make_shared<EventMatchRule>(rctypes, rules);
}

std::shared_ptr<EventMatchRule> EventMatchRule::FromJSON(const std::string& str) {
    rapidjson::Document doc;
    doc.Parse(str.c_str());
    if (doc.HasParseError()) {
        throw std::runtime_error(rapidjson::GetParseError_En(doc.GetParseError()));
    }
    return FromJSON(doc);
}

void EventMatchRule::ToJSON(rapidjson::Writer<rapidjson::StringBuffer>& writer) const {
    writer.StartObject();

    writer.Key("record_types");
    writer.StartArray();
    RecordType rtypes[_record_types.size()];
    std::copy(_record_types.begin(), _record_types.end(), &rtypes[0]);
    std::sort(&rtypes[0], &rtypes[_record_types.size()]);
    for (auto& r : rtypes) {
        auto name = RecordTypeToName(r);
        writer.String(name.data(), name.size());
    }
    writer.EndArray();

    writer.Key("field_rules");
    writer.StartArray();
    for (auto& r : _rules) {
        r->ToJSON(writer);
    }
    writer.EndArray();

    writer.EndObject();
}

std::string EventMatchRule::ToJSONString() const {
    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
    ToJSON(writer);
    return std::string(buf.GetString(), buf.GetSize());
}

/****************************************************************************
 *
 ****************************************************************************/

class EventMatcher::FieldMatcher {
public:
    FieldMatcher(const std::string& name, int num_event_rules, int index): _name(name), _num_event_rules(num_event_rules), _index(index), _re_set(RE2::Options(), RE2::UNANCHORED) {
        RE2::Options opts;
        opts.set_never_capture(true);

        _re_set = RE2::Set(opts, RE2::UNANCHORED);

        _rules.assign(_num_event_rules, nullptr);
        _shift_counts.resize(_num_event_rules, 1);
        _not_mask.resize(_num_event_rules, 0);
    }

    void AddPatterns(int em_idx, std::shared_ptr<FieldMatchRule> rule) {
        assert(em_idx < _rules.size());
        _rules[em_idx] = rule;
    }

    bool Compile(int num_event_rules, std::vector<std::string>* errors) {
        for (int i = 0; i < _rules.size(); i++) {
            if (_rules[i] != nullptr) {
                _shift_counts[i] = _rules[i]->MinMatch();
                _not_mask[i] = _rules[i]->Op() & FIELD_OP_NOT;
            }
        }

        std::string error;
        for (int i = 0; i < _rules.size(); i++) {
            if (_rules[i] != nullptr) {
                for (auto& p : _rules[i]->Values()) {
                    std::string e;
                    auto idx = _re_set.Add(p, &e);
                    if (idx < 0) {
                        errors->emplace_back("Invalid pattern '" + p + "': " + e);
                        return false;
                    }
                    _to_rule.emplace_back(i);
                    assert(_to_rule.size() == idx+1);
                }
            }
        }

        if (!_re_set.Compile()) {
            return false;
        }

        _matches.clear();
        _matches.reserve(_to_rule.size());

        return true;
    }

    bool Match(const EventRecord& record, uint32_t* ruleMatchedFields) {
        auto f = record.FieldByName(_name);

        if (!f) {
            return false;
        }

        re2::StringPiece val;
        if (f.InterpValueSize() > 0) {
            val = re2::StringPiece(f.InterpValuePtr(), f.InterpValueSize());
        } else {
            val = re2::StringPiece(f.RawValuePtr(), f.RawValueSize());
        }

        if (!_re_set.Match(val, &_matches)) {
            uint32_t matchCount = 0;
            for (int i = 0; i < _not_mask.size(); i++) {
                auto tmp = (0 ^ _not_mask[i]);
                ruleMatchedFields[i] |= tmp << _index;
                matchCount += tmp;
            }
            return matchCount > 0;
        }

        int32_t tmp[_shift_counts.size()];
        std::fill(tmp, tmp+_shift_counts.size(), 0x80000000);

        for (auto m :_matches) {
            tmp[_to_rule[m]] >>= 1;
        }

        for (int i = 0; i < _shift_counts.size(); i++) {
            ruleMatchedFields[i] |= (((static_cast<uint32_t>(tmp[i]) >> 31-_shift_counts[i]) & 1) ^ _not_mask[i]) << _index;
        }

        return true;
    }

    std::string _name;
    int _num_event_rules;
    int _index;
    std::vector<std::shared_ptr<FieldMatchRule>> _rules;
    RE2::Set _re_set;
    std::vector<int> _to_rule;
    std::vector<int32_t> _shift_counts;
    std::vector<uint32_t> _not_mask;
    std::vector<int> _matches;
};

/****************************************************************************
 *
 ****************************************************************************/

bool EventMatcher::Compile(const std::vector<std::shared_ptr<EventMatchRule>>& rules) {
    _rules.clear();
    for (auto& r : rules) {
        _rules.emplace_back(r);
    }
    _fields.clear();
    _errors.clear();
    _rules_field_mask.assign(_rules.size(), 0);
    _record_type_field_mask.clear();
    _fieldsMap.clear();

    for (int i = 0; i < _rules.size(); i++) {
        auto& r = _rules[i];
        for (auto& f : r->Rules()) {
            std::shared_ptr<FieldMatcher> fm;
            auto fmi = _fieldsMap.find(f->Name());
            if (fmi == _fieldsMap.end()) {
                if (_fields.size() >= 32) {
                    _errors.emplace_back("Number of fields (" + std::to_string(0) + ") exceeds limit of 32");
                    return false;
                }
                fm = std::make_shared<FieldMatcher>(f->Name(), _rules.size(), _fields.size());
                _fieldsMap[f->Name()] = fm;
                _fields.emplace_back(fm);
            } else {
                fm = fmi->second;
            }
            std::string error;
            fm->AddPatterns(i, f);
            _rules_field_mask[i] |= 1 << fm->_index;
            for (auto rt : r->RecordTypes()) {
                _record_type_field_mask[static_cast<uint32_t>(rt)] |= 1 << fm->_index;
            }
        }
    }    

    bool failed = false;
    for (auto& f : _fields) {
        if (!f->Compile(_rules.size(), &_errors)) {
            _errors.emplace_back("Failed to compile RE2::Set for field '" + f->_name + '"');
            failed = true;
        }
    }

    return !failed;
}

int EventMatcher::Match(const Event& event) {
    if (event.NumRecords() < 1) {
        return -1;
    }
    auto record = event.RecordAt(0);

    auto rmi = _record_type_field_mask.find(record.RecordType());
    if (rmi == _record_type_field_mask.end()) {
        return -1;
    }
    uint32_t record_field_mask = rmi->second;
    if (record_field_mask == 0) {
        return -1;
    }

    uint32_t fieldMatches[_rules.size()];
    memset(fieldMatches, 0, _rules.size()*sizeof(uint32_t));

    int fcount = 0;
    for (auto& f : _fields) {
        if (((1<< f->_index) & record_field_mask) != 0) {
            f->Match(record, fieldMatches);
        }
    }

    for (int i = 0; i < _rules.size(); i++) {
        if ((fieldMatches[i] & _rules_field_mask[i]) == _rules_field_mask[i] && _rules[i]->RecordTypes().count(static_cast<RecordType>(record.RecordType())) > 0) {
            return i;
        }
    }

    return -1;
}
