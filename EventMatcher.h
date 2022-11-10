/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_EVENTMATCHER_H
#define AUOMS_EVENTMATCHER_H

#include <memory>
#include <functional>
#include <unordered_set>
#include <unordered_map>

#include "Event.h"
#include "RecordType.h"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>


enum FieldMatchRuleOp: int {
    FIELD_OP_NOT = 1,
    FIELD_OP_EQ = 1<<1,
    FIELD_OP_NEQ = FIELD_OP_EQ|FIELD_OP_NOT,
    FIELD_OP_IN = 2<<1,
    FIELD_OP_NIN = FIELD_OP_IN|FIELD_OP_NOT,
    FIELD_OP_RE = 3<<1,
    FIELD_OP_NRE = FIELD_OP_RE|FIELD_OP_NOT,
};

class FieldMatchRule {
public:
    FieldMatchRule(const std::string& name, FieldMatchRuleOp op, const std::string& value): _name(name), _op(op) {
        switch (op&(~FIELD_OP_NOT)) {
        case FIELD_OP_EQ:
            _values.emplace_back("^" + value + "$");
            break;
        case FIELD_OP_IN:
            _values.emplace_back("^" + value + "$");
            break;
        case FIELD_OP_RE:
            _values.emplace_back(value);
            break;
        }
        _min_match = 1;
    }
    FieldMatchRule(const std::string& name, FieldMatchRuleOp op, const std::vector<std::string>& values): _name(name), _op(op) {
        switch (op&(~FIELD_OP_NOT)) {
        case FIELD_OP_EQ:
            _values.emplace_back("^" + values[0] + "$");
            _min_match = 1;
            break;
        case FIELD_OP_IN:
            for (auto& v : values) {
                _values.emplace_back("^" + v + "$");
            }
            _min_match = 1;
            break;
        case FIELD_OP_RE:
            _values = values;
            _min_match = values.size();
            break;
        }
        std::sort(_values.begin(), _values.end());
    }

    static std::shared_ptr<FieldMatchRule> FromJSON(const rapidjson::Value& value);
    static std::shared_ptr<FieldMatchRule> FromJSON(const std::string& str);
    void ToJSON(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;
    std::string ToJSONString() const;

    inline const std::string& Name() const {
        return _name;
    }

    inline FieldMatchRuleOp Op() const {
        return _op;
    }

    inline const std::vector<std::string>& Values() const {
        return _values;
    }

    inline int MinMatch() const {
        return _min_match;
    }

private:
    std::string _name;
    FieldMatchRuleOp _op;
    std::vector<std::string> _values;
    int _min_match;
};

class EventMatchRule {
public:
    EventMatchRule(const std::unordered_set<RecordType>& record_types, const std::vector<std::shared_ptr<FieldMatchRule>>& rules): _record_types(record_types) {
        _rules.reserve(rules.size());

        for (auto& r : rules) {
            auto i = _rulesMap.find(r->Name());
            if (i == _rulesMap.end()) {
                _rules.emplace_back(r);
                _rulesMap.emplace(r->Name(), r);
            }
        }
    }

    static std::shared_ptr<EventMatchRule> FromJSON(const rapidjson::Value& value);
    static std::shared_ptr<EventMatchRule> FromJSON(const std::string& str);
    void ToJSON(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;
    std::string ToJSONString() const;

    inline const std::vector<std::shared_ptr<FieldMatchRule>>& Rules() const {
        return _rules;
    }

    inline const std::unordered_set<RecordType>& RecordTypes() const {
        return _record_types;
    }

    inline std::shared_ptr<FieldMatchRule> Rule(const std::string& name) const {
        return _rulesMap.at(name);
    }

private:
    std::unordered_set<RecordType> _record_types;
    std::vector<std::shared_ptr<FieldMatchRule>> _rules;
    std::unordered_map<std::string, std::shared_ptr<FieldMatchRule>> _rulesMap;
};

class EventMatcher {
public:
    bool Compile(const std::vector<std::shared_ptr<EventMatchRule>>& rules);

    inline const std::vector<std::string>& Errors() {
        return _errors;
    }

    // Return -1 if the event doesn't match any rule
    // Otherwise return the index of the match rule in the vector passed in via Compile().
    // If event matches multiple event rules, then the lowest index of all rules that matched is returned.
    int Match(const Event& event);

private:
    class FieldMatcher;

    std::vector<std::shared_ptr<const EventMatchRule>> _rules;
    std::vector<uint32_t> _rules_field_mask;
    std::unordered_map<uint32_t, uint32_t> _record_type_field_mask;

    std::vector<std::shared_ptr<FieldMatcher>> _fields;
    std::unordered_map<std::string, std::shared_ptr<FieldMatcher>> _fieldsMap;
    std::vector<std::string> _errors;
};

#endif //AUOMS_EVENTMATCHER_H
