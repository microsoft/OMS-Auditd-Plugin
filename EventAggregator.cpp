/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "EventAggregator.h"
#include "EventId.h"
#include "Defer.h"
#include "StringUtils.h"

#include "rapidjson/error/en.h"

#include <sstream>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// From https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
constexpr size_t round_up_pow_2(size_t v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v;
}

/****************************************************************************
 *
 ****************************************************************************/

void AggregationRule::RulesFromJSON(const rapidjson::Value& value, std::vector<std::shared_ptr<AggregationRule>>& rules) {
    if (!value.IsArray()) {
        throw new std::invalid_argument("AggregationRule::RulesFromJSON(): value is not a JSON array");
    }

    rules.resize(0);
    rules.reserve(value.Size());

    for (auto it = value.Begin(); it != value.End(); ++it) {
        auto rule = FromJSON(*it);
        rules.emplace_back(rule);
    }
}

std::shared_ptr<AggregationRule> AggregationRule::FromJSON(const rapidjson::Value& value) {
    if (!value.IsObject()) {
        throw new std::invalid_argument("AggregationRule::FromJSON(): value is not a JSON object");
    }

    std::string name;
    std::string op_name;
    FieldMatchRuleOp op;
    std::vector<std::string> values;

    auto m = value.FindMember("match_rule");
    if (m == value.MemberEnd()) {
        throw new std::invalid_argument("FieldMatchRule::FromJSON(): Missing 'match_rule'");
    }
    auto match_rule = EventMatchRule::FromJSON(m->value);

    m = value.FindMember("aggregation_fields");
    if (m == value.MemberEnd()) {
        throw new std::invalid_argument("FieldMatchRule::FromJSON(): Missing 'aggregation_fields'");
    }
    if (!m->value.IsObject()) {
        throw new std::invalid_argument("AggregationRule::FromJSON(): aggregation_fields is not a JSON object");
    }
    if (m->value.MemberCount() == 0) {
        throw new std::invalid_argument("AggregationRule::FromJSON(): aggregation_fields is empty");
    }
    std::vector<AggregationField> agg_fields;
    agg_fields.reserve(m->value.MemberCount());
    for (auto it = m->value.MemberBegin(); it != m->value.MemberEnd(); ++it) {
        AggregationFieldMode mode = AggregationFieldMode::DYNAMIC;
        auto am = it->value.FindMember("mode");
        if (am != it->value.MemberEnd()) {
            if (strncmp(am->value.GetString(), "raw", am->value.GetStringLength()) == 0) {
                mode = AggregationFieldMode::RAW;
            } else if (strncmp(am->value.GetString(), "interp", am->value.GetStringLength()) == 0) {
                mode = AggregationFieldMode::INTERP;
            } else if (strncmp(am->value.GetString(), "dynamic", am->value.GetStringLength()) == 0) {
                mode = AggregationFieldMode::DYNAMIC;
            } else if (strncmp(am->value.GetString(), "drop", am->value.GetStringLength()) == 0) {
                mode = AggregationFieldMode::DROP;
            } else {
                throw new std::invalid_argument(std::string("AggregationRule::FromJSON(): Invalid 'mode' valud for aggregation field: ") + am->value.GetString());
            }
        }
        am = it->value.FindMember("output_name");
        if (am == it->value.MemberEnd()) {
            agg_fields.emplace_back(std::string(it->name.GetString(), it->name.GetStringLength()), mode);
        } else {
            agg_fields.emplace_back(std::string(it->name.GetString(), it->name.GetStringLength()), mode, std::string(am->value.GetString(), am->value.GetStringLength()));
        }
    }

    AggregationFieldMode time_field_mode = AggregationFieldMode::NORMAL;
    AggregationFieldMode serial_field_mode = AggregationFieldMode::NORMAL;
    uint32_t max_pending = DEFAULT_MAX_PENDING;
    uint32_t max_count = DEFAULT_MAX_COUNT;
    uint32_t max_size = DEFAULT_MAX_SIZE;
    uint32_t max_time = DEFAULT_MAX_TIME;
    bool send_first = DEFAULT_SEND_FIRST;

    m = value.FindMember("time_field_mode");
    if (m != value.MemberEnd()) {
        if (!m->value.IsString()) {
            throw new std::invalid_argument("AggregationRule::FromJSON(): time_field_mode is not a JSON string");
        }
        if (strncmp(m->value.GetString(), "full", m->value.GetStringLength()) == 0) {
            time_field_mode = AggregationFieldMode::NORMAL;
        } else if (strncmp(m->value.GetString(), "delta", m->value.GetStringLength()) == 0) {
            time_field_mode = AggregationFieldMode::DELTA;
        } else if (strncmp(m->value.GetString(), "drop", m->value.GetStringLength()) == 0) {
            time_field_mode = AggregationFieldMode::DROP;
        } else {
            throw new std::invalid_argument(std::string("AggregationRule::FromJSON(): Invalid 'time_field_mode' value: ") + m->value.GetString());
        }
    }

    m = value.FindMember("serial_field_mode");
    if (m != value.MemberEnd()) {
        if (!m->value.IsString()) {
            throw new std::invalid_argument("AggregationRule::FromJSON(): serial_field_mode is not a JSON string");
        }
        if (strncmp(m->value.GetString(), "full", m->value.GetStringLength()) == 0) {
            serial_field_mode = AggregationFieldMode::NORMAL;
        } else if (strncmp(m->value.GetString(), "delta", m->value.GetStringLength()) == 0) {
            serial_field_mode = AggregationFieldMode::DELTA;
        } else if (strncmp(m->value.GetString(), "drop", m->value.GetStringLength()) == 0) {
            serial_field_mode = AggregationFieldMode::DROP;
        } else {
            throw new std::invalid_argument(std::string("AggregationRule::FromJSON(): Invalid 'serial_field_mode' value: ") + m->value.GetString());
        }
    }

    m = value.FindMember("max_pending");
    if (m != value.MemberEnd()) {
        if (!m->value.IsUint()) {
            throw new std::invalid_argument("AggregationRule::FromJSON(): max_pending is not a JSON unsigned integer");
        }
        max_pending = m->value.GetUint();
    }

    m = value.FindMember("max_count");
    if (m != value.MemberEnd()) {
        if (!m->value.IsUint()) {
            throw new std::invalid_argument("AggregationRule::FromJSON(): max_count is not a JSON unsigned integer");
        }
        max_count = m->value.GetUint();
    }

    m = value.FindMember("max_size");
    if (m != value.MemberEnd()) {
        if (!m->value.IsUint()) {
            throw new std::invalid_argument("AggregationRule::FromJSON(): max_size is not a JSON unsigned integer");
        }
        max_size = m->value.GetUint();
    }

    m = value.FindMember("max_time");
    if (m != value.MemberEnd()) {
        if (!m->value.IsUint()) {
            throw new std::invalid_argument("AggregationRule::FromJSON(): max_time is not a JSON unsigned integer");
        }
        max_time = m->value.GetUint();
    }

    m = value.FindMember("send_first");
    if (m != value.MemberEnd()) {
        if (!m->value.IsBool()) {
            throw new std::invalid_argument("AggregationRule::FromJSON(): send_first is not a JSON bool");
        }
        send_first = m->value.GetBool();
    }

    return std::make_shared<AggregationRule>(match_rule, agg_fields, time_field_mode, serial_field_mode, max_pending, max_count, max_size, max_time, send_first);
}

void AggregationRule::ToJSON(rapidjson::Writer<rapidjson::StringBuffer>& writer) const {
    writer.StartObject();

    writer.Key("match_rule");
    _match_rule->ToJSON(writer);

    writer.Key("aggregation_fields");
    writer.StartObject();
    for (auto& a : _aggregation_fields) {
        writer.Key(a.Name().data(), a.Name().size());
        writer.StartObject();
        writer.Key("mode");
        switch(a.Mode()) {
        case AggregationFieldMode::DYNAMIC:
            writer.String("dynamic");
            break;
        case AggregationFieldMode::RAW:
            writer.String("raw");
            break;
        case AggregationFieldMode::INTERP:
            writer.String("interp");
            break;
        case AggregationFieldMode::DROP:
            writer.String("drop");
            break;
        default:
            writer.String("dynamic");
            break;
        }
        writer.Key("output_name");
        writer.String(a.OutputName().data(), a.OutputName().size());
        writer.EndObject();
    }
    writer.EndObject();

    writer.Key("time_field_mode");
    switch(_time_field_mode) {
    case AggregationFieldMode::DELTA:
        writer.String("delta");
        break;
    case AggregationFieldMode::DROP:
        writer.String("drop");
        break;
    default:
        writer.String("full");
        break;
    }

    writer.Key("serial_field_mode");
    switch(_serial_field_mode) {
    case AggregationFieldMode::DELTA:
        writer.String("delta");
        break;
    case AggregationFieldMode::DROP:
        writer.String("drop");
        break;
    default:
        writer.String("full");
        break;
    }

    writer.Key("max_pending");
    writer.Uint(_max_pending);

    writer.Key("max_count");
    writer.Uint(_max_count);

    writer.Key("max_size");
    writer.Uint(_max_size);

    writer.Key("max_time");
    writer.Uint(_max_time);

    writer.Key("send_first");
    writer.Bool(_send_first);

    writer.EndObject();
}

std::shared_ptr<AggregationRule> AggregationRule::FromJSON(const std::string& str) {
    rapidjson::Document doc;
    doc.Parse(str.c_str());
    if (doc.HasParseError()) {
        throw std::runtime_error(rapidjson::GetParseError_En(doc.GetParseError()));
    }
    return FromJSON(doc);
}

std::string AggregationRule::ToJSONString() const {
    rapidjson::StringBuffer js_buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(js_buffer);
    ToJSON(writer);
    return std::string(js_buffer.GetString(), js_buffer.GetSize());
}

void AggregationRule::CalcAggregationKey(std::vector<std::string_view>& key, const Event& event) const {
    auto rec = event.RecordAt(0); 

    key.resize(0);
    key.reserve(rec->NumFields() - _aggregation_fields.size());

    for(auto& f : rec) {
        if (!HasAggregationField(f.FieldName())) {
            key.emplace_back(f.RawValuePtr(), f.RawValueSize());
        }
    }

    return;
}

/****************************************************************************
 *
 ****************************************************************************/

std::atomic<uint64_t> AggregatedEvent::_next_id(0);

uint64_t steady_to_unix(std::chrono::steady_clock::time_point tp) {
    auto now = std::chrono::steady_clock::now();
    auto st_now = std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(st_now) - std::chrono::duration_cast<std::chrono::seconds>(now - tp).count();
}

std::chrono::steady_clock::time_point unix_to_steady(time_t t) {
    auto now = std::chrono::steady_clock::now();
    auto st_now = std::chrono::system_clock::now();

    return now - std::chrono::duration_cast<std::chrono::seconds>(st_now - std::chrono::system_clock::from_time_t(t));
}

std::shared_ptr<AggregatedEvent> AggregatedEvent::Read(FILE* file, std::vector<std::shared_ptr<AggregationRule>> rules) {
    struct stat st;

    if (fstat(fileno(file), &st) != 0) {
        throw std::system_error(errno, std::system_category(), "fstat()");
    }

    auto foffset = ftell(file);
    if (foffset < 0) {
        throw std::system_error(errno, std::system_category(), "ftell()");
    }

    uint64_t max_data_size = st.st_size - foffset;

    int rule_idx, count;
    uint64_t origin_size, data_size, lsec, lser;
    uint32_t lmsec;
    time_t exp_time;
    if (fscanf(file, "AggregatedEvent:HEADER: %d:%ld:%ld:%d:%ld:%ld:%d:%ld\n", &rule_idx, &origin_size, &data_size, &count, &exp_time, &lsec, &lmsec, &lser) != 8) {
        throw std::runtime_error("AggregatedEvent::Read(): Invlid AggregatedEvent header: Failed to read all elements");
    }

    auto ae = std::shared_ptr<AggregatedEvent>(new AggregatedEvent());
    ae->_rule = rules.at(rule_idx);
    ae->_expiration_time = unix_to_steady(exp_time);
    ae->_last_event = EventId(lsec, lmsec, lser);
    ae->_count = count;

    if (origin_size > max_data_size) {
        throw std::runtime_error("AggregatedEvent::Read(): Invlid AggregatedEvent header: Origin Event size too large");
    }

    ae->_origin_event.resize(origin_size);

    if (data_size > max_data_size || data_size > ae->_rule->MaxSize()) {
        throw std::runtime_error("AggregatedEvent::Read(): Invlid AggregatedEvent header: Data size too large");
    }

    ae->_data.reserve(round_up_pow_2(data_size));
    ae->_data.resize(data_size);

    if (fscanf(file, "ORIGIN:") != 0) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid origin header");
    }

    if (fread(ae->_origin_event.data(), ae->_origin_event.size(), 1, file) != 1) {
        throw std::runtime_error("AggregatedEvent::Read(): Failed to read origin event data");
    }

    if (fscanf(file, "DATA:") != 0) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid data header");
    }

    if (fread(const_cast<char*>(ae->_data.data()), ae->_data.size(), 1, file) != 1) {
        throw std::runtime_error("AggregatedEvent::Read(): Failed to read values data");
    }

    int agg_key_size;
    if (fscanf(file, "AGGKEY: %d\n", &agg_key_size) != 1) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate key header");
    }
    ae->_agg_key.reserve(agg_key_size);
    for (int i = 0; i < agg_key_size; ++i) {
        uint64_t offset;
        uint64_t size;
        if (fscanf(file, "%ld:%ld\n", &offset, &size) != 2) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate key value: Failed to read");
        }
        if (offset+size > ae->_origin_event.size()) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate key value: Invalid offset or size");
        }
        ae->_agg_key.emplace_back(reinterpret_cast<const char*>(ae->_origin_event.data())+offset, size);
    }

    int num_agg_fields;
    if (fscanf(file, "AGGFIELDS: %d\n", &num_agg_fields) != 1) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate fields header: Failed to read");
    }
    if (num_agg_fields > ae->_rule->AggregationFields().size()) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate fields header: Num fields exeeds rule num fields");
    }
    ae->_aggregated_fields.resize(num_agg_fields);

    int num_values;
    if (fscanf(file, "AGGFIELD: %d\n", &num_values) != 1) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field header: Failed to read");
    }
    if (num_values > ae->_rule->MaxCount()) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field header: Num values exceeds rule max count");
    }
    ae->_event_times.reserve(round_up_pow_2(num_values));
    for (int i = 0; i < num_values; ++i) {
        uint64_t offset;
        uint64_t size;
        if (fscanf(file, "%ld:%ld\n", &offset, &size) != 2) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field value: Failed to read");
        }
        if (offset+size > ae->_data.size()) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field value: Invalid offset or size");
        }
        ae->_event_times.emplace_back(offset, size);
    }

    if (fscanf(file, "AGGFIELD: %d\n", &num_values) != 1) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field header: Failed to read");
    }
    if (num_values > ae->_rule->MaxCount()) {
        throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field header: Num values exceeds rule max count");
    }
    ae->_event_serials.reserve(round_up_pow_2(num_values));
    for (int i = 0; i < num_values; ++i) {
        uint64_t offset;
        uint64_t size;
        if (fscanf(file, "%ld:%ld\n", &offset, &size) != 2) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field value: Failed to read");
        }
        if (offset+size > ae->_data.size()) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field value: Invalid offset or size");
        }
        ae->_event_serials.emplace_back(offset, size);
    }

    for (int f = 0; f < num_agg_fields; ++f) {
        int num_values;
        if (fscanf(file, "AGGFIELD: %d\n", &num_values) != 1) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field header: Failed to read");
        }
        if (num_values > ae->_rule->MaxCount()) {
            throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field header: Num values exceeds rule max count");
        }
        ae->_aggregated_fields[f].reserve(round_up_pow_2(num_values));
        for (int i = 0; i < num_values; ++i) {
            uint64_t offset;
            uint64_t size;
            if (fscanf(file, "%ld:%ld\n", &offset, &size) != 2) {
                throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field value: Failed to read");
            }
            if (offset+size > ae->_data.size()) {
                throw std::runtime_error("AggregatedEvent::Read(): Invalid aggregate field value: Invalid offset or size");
            }
            if (size > 0) {
                ae->_aggregated_fields[f].emplace_back(offset, size);
            } else {
                ae->_aggregated_fields[f].emplace_back(0, 0);
            }
        }
    }

    return ae;
}

void AggregatedEvent::Write(FILE* file, const std::unordered_map<std::shared_ptr<AggregationRule>, int>& rules_map) const {

    auto rule_idx = rules_map.at(_rule);

    time_t exp_time = steady_to_unix(_expiration_time);

    if (fprintf(file, "AggregatedEvent:HEADER: %d:%ld:%ld:%d:%ld:%ld:%d:%ld\n", rule_idx, _origin_event.size(), _data.size(), _count, exp_time,
            _last_event.Seconds(), _last_event.Milliseconds(), _last_event.Serial()) < 0) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to write header");
    }

    if (fprintf(file, "ORIGIN:") < 0) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to write origin header");
    }

    if (fwrite(_origin_event.data(), _origin_event.size(), 1, file) != 1) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to write event data");
    }

    if (fprintf(file, "DATA:") < 0) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to write data header");
    }

    if (fwrite(_data.data(), _data.size(), 1, file) != 1) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to write field data");
    }

    if (fprintf(file, "AGGKEY: %ld\n", _agg_key.size()) < 0) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to write agg key header");
    }
    for (auto& k : _agg_key) {
        if (fprintf(file, "%ld:%ld\n", k.data()-reinterpret_cast<const char*>(_origin_event.data()), k.size()) < 0) {
            throw std::runtime_error("AggregatedEvent::Write(): Failed to agg key value");
        }
    }

    if (fprintf(file, "AGGFIELDS: %ld\n", _aggregated_fields.size()) < 0) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to agg fields header");
    }
    if (fprintf(file, "AGGFIELD: %ld\n", _event_times.size()) < 0) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to agg field header");
    }
    for (auto& v : _event_times) {
        if (fprintf(file, "%ld:%ld\n", v.first, v.second) < 0) {
            throw std::runtime_error("AggregatedEvent::Write(): Failed to agg field value");
        }
    }
    if (fprintf(file, "AGGFIELD: %ld\n", _event_serials.size()) < 0) {
        throw std::runtime_error("AggregatedEvent::Write(): Failed to agg field header");
    }
    for (auto& v : _event_serials) {
        if (fprintf(file, "%ld:%ld\n", v.first, v.second) < 0) {
            throw std::runtime_error("AggregatedEvent::Write(): Failed to agg field value");
        }
    }
    for (auto& f : _aggregated_fields) {
        if (fprintf(file, "AGGFIELD: %ld\n", f.size()) < 0) {
            throw std::runtime_error("AggregatedEvent::Write(): Failed to agg field header");
        }
        for (auto& v : f) {
            if (v.second > 0) {
                if (fprintf(file, "%ld:%ld\n", v.first, v.second) < 0) {
                    throw std::runtime_error("AggregatedEvent::Write(): Failed to agg field value");
                }
            } else {
                if (fprintf(file, "0:0\n") < 0) {
                    throw std::runtime_error("AggregatedEvent::Write(): Failed to agg field value");
                }
            }
        }
    }
}

bool AggregatedEvent::AddEvent(const Event& event) {
    if (_count == 0) {
        _origin_event.resize(event.Size());
        memcpy(_origin_event.data(), event.Data(), _origin_event.size());
        _rule->CalcAggregationKey(_agg_key, Event(_origin_event.data(), _origin_event.size()));
        Event origin_event(_origin_event.data(), _origin_event.size());
        _first_event = EventId(origin_event.Seconds(), origin_event.Milliseconds(), origin_event.Serial());
    }

    if (_count >= _rule->MaxCount()) {
        return false;
    }

    auto rec = event.RecordAt(0); 

    char evt_str[64];
    char evs_str[64];
    size_t evt_size = 0;
    size_t evs_size = 0;

    switch (_rule->TimeFieldMode()) {
    case AggregationFieldMode::NORMAL:
        evt_size = snprintf(evt_str, sizeof(evt_str), "%lu.%03u", event.Seconds(), event.Milliseconds());
        break;
    case AggregationFieldMode::DELTA: {
            int64_t base = (static_cast<int64_t>(_first_event.Seconds())*1000) + static_cast<int64_t>(_first_event.Milliseconds());
            int64_t val = (static_cast<int64_t>(event.Seconds())*1000) + static_cast<int64_t>(event.Milliseconds());
            int64_t delta = val - base;

            evt_size = snprintf(evt_str, sizeof(evt_str), "%ld", delta);
        }
        break;
    }

    switch (_rule->SerialFieldMode()) {
    case AggregationFieldMode::NORMAL:
        evs_size = snprintf(evs_str, sizeof(evs_str), "%lu", event.Serial());
        break;
    case AggregationFieldMode::DELTA:
        evs_size = snprintf(evs_str, sizeof(evs_str), "%ld", static_cast<int64_t>(event.Serial()) -  static_cast<int64_t>(_first_event.Serial()));
        break;
    }

    auto agg_fields = _rule->AggregationFields();
    EventRecordField fields[agg_fields.size()];

    uint32_t size = evt_size+evs_size;
    for (int i = 0; i < agg_fields.size(); ++i) {
        fields[i] = rec.FieldByName(agg_fields[i].Name());
        if (fields[i]) {
            switch(agg_fields[i].Mode()) {
            case AggregationFieldMode::DROP:
                break;
            case AggregationFieldMode::RAW:
                size += fields[i].RawValueSize();
                break;
            case AggregationFieldMode::INTERP:
                size += fields[i].InterpValueSize();
                break;
            default:
                if (fields[i].InterpValueSize() > 0) {
                    size += fields[i].InterpValueSize();
                } else {
                    size += fields[i].RawValueSize();
                }
                break;
            }
        }
    }

    if (_data.size() + size > _rule->MaxSize()) {
        return false;
    }

    if (_data.size() + size > _data.capacity()) {
        _data.reserve(_data.capacity()*2);
    }

    if (evt_size > 0) {
        auto start_offset = _data.size();
        _data.append(&evt_str[0], evt_size);
        _event_times.emplace_back(start_offset, evt_size);
    }

    if (evs_size) {
        auto start_offset = _data.size();
        _data.append(&evs_str[0], evs_size);
        _event_serials.emplace_back(start_offset, evs_size);
    }

    for (int i = 0; i < agg_fields.size(); ++i) {
        if (fields[i]) {
            const char* field_data = 0;
            size_t field_size = 0;
            switch(agg_fields[i].Mode()) {
            case AggregationFieldMode::DROP:
                continue;
            case AggregationFieldMode::RAW:
                field_data = fields[i].RawValuePtr();
                field_size = fields[i].RawValueSize();
                break;
            case AggregationFieldMode::INTERP:
                field_data = fields[i].InterpValuePtr();
                field_size = fields[i].InterpValueSize();
                break;
            default:
                if (fields[i].InterpValueSize() > 0) {
                    field_data = fields[i].InterpValuePtr();
                    field_size = fields[i].InterpValueSize();
                } else {
                    field_data = fields[i].RawValuePtr();
                    field_size = fields[i].RawValueSize();
                }
                break;
            }
            if (field_size > 0) {
                auto start_offset = _data.size();
                _data.append(field_data, field_size);
                _aggregated_fields[i].emplace_back(start_offset, field_size);
            } else {
                _aggregated_fields[i].emplace_back(0, 0);
            }
        } else {
            _aggregated_fields[i].emplace_back(0, 0);
        }
    }

    _count += 1;
    EventId id(event.Seconds(), event.Milliseconds(), event.Serial());

    if (_last_event < id) {
        _last_event = id;
    }

    return true;
}

bool add_time_field(EventBuilder& builder, const std::string_view& name, uint64_t sec, uint32_t ms) {
    char fmt[256];
    char buf[256];
    struct tm tm;
    time_t t = sec;
    sprintf(fmt, "%%Y-%%m-%%dT%%H:%%M:%%S.%03uZ", ms);
    gmtime_r(&t, &tm);
    auto tsize = strftime(buf, sizeof(buf), fmt, &tm);
    return builder.AddField(name, std::string_view(buf, tsize), std::string_view(), field_type_t::UNCLASSIFIED);
}

int AggregatedEvent::BuildEvent(EventBuilder& builder, rapidjson::StringBuffer& buffer) const {
    using namespace std::string_view_literals;

    static auto RT_NAME_SV = "AUOMS_AGGREGATE"sv;
    static auto ORIGINAL_RECORD_TYPE_CODE_SV = "original_record_type_code"sv;
    static auto ORIGINAL_RECORD_TYPE_SV = "original_record_type"sv;
    static auto AGG_EVENT_TIME_SV = "event_times"sv;
    static auto AGG_SERIAL_SV = "serials"sv;
    static auto FIRST_EVENT_TIME_SV = "first_event_time"sv;
    static auto LAST_EVENT_TIME_SV = "last_event_time"sv;
    static auto FIRST_SERIAL_SV = "first_serial"sv;
    static auto NUM_AGGREGATED_EVENTS_SV = "num_aggregated_events"sv;

    Event origin_event(_origin_event.data(), _origin_event.size());
    EventRecord origin_rec = origin_event.RecordAt(0);

    int field_count = 0;
    for (auto f : origin_rec) {
        if (!_rule->HasAggregationField(f.FieldName())) {
            field_count += 1;
        }
    }
    field_count += _rule->AggregationFields().size() - _rule->NumDropFields();
    field_count += 7; /* original_record_type_code+ original_record_type + event_times + serials + first_event_time + last_event_time + num_aggregated_events */

    if (_rule->TimeFieldMode() == AggregationFieldMode::DROP) {
        field_count -= 1; // remove event_times
    }
    switch (_rule->SerialFieldMode()) {
    case AggregationFieldMode::DROP:
        field_count -= 1; // remove serials
        break;
    case AggregationFieldMode::DELTA:
        field_count += 1; // add first_serial
        break;
    }

    if (!builder.BeginEvent(_last_event.Seconds(), _last_event.Milliseconds(), _last_event.Serial(), 1)) {
        return 0;
    }

    if (!builder.BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_AGGREGATE), RT_NAME_SV, origin_rec.RecordText(), field_count)) {
        return 0;
    }

    // Original Record Type Code
    {
        char buf[64];
        auto c_size = snprintf(buf, sizeof(buf), "%u", origin_rec.RecordType());
        if (!builder.AddField(ORIGINAL_RECORD_TYPE_CODE_SV, std::string_view(buf, c_size), std::string_view(), field_type_t::UNCLASSIFIED)) {
            return 0;
        }
    }

    // Original Record Type
    if (!builder.AddField(ORIGINAL_RECORD_TYPE_SV, origin_rec.RecordTypeName(), std::string_view(), field_type_t::UNCLASSIFIED)) {
        return 0;
    }

    // First Event Time
    if (!add_time_field(builder, FIRST_EVENT_TIME_SV, origin_event.Seconds(), origin_event.Milliseconds())) {
        return 0;
    }

    // Last Event Time
    if (!add_time_field(builder, LAST_EVENT_TIME_SV, _last_event.Seconds(), _last_event.Milliseconds())) {
        return 0;
    }

    if (_rule->SerialFieldMode() == AggregationFieldMode::DELTA) {
        char buf[64];
        auto c_size = snprintf(buf, sizeof(buf), "%lu", _first_event.Serial());
        if (!builder.AddField(FIRST_SERIAL_SV, std::string_view(buf, c_size), std::string_view(), field_type_t::UNCLASSIFIED)) {
            return 0;
        }
    }

    // Num Agg Events
    {
        char buf[64];
        auto c_size = snprintf(buf, sizeof(buf), "%u", _count);
        if (!builder.AddField(NUM_AGGREGATED_EVENTS_SV, std::string_view(buf, c_size), std::string_view(), field_type_t::UNCLASSIFIED)) {
            return 0;
        }
    }

    for (auto f : origin_rec) {
        if (_rule->FieldMode(f.FieldName()) == AggregationFieldMode::NORMAL) {
            if (!builder.AddField(f.FieldName(), f.RawValue(), f.InterpValue(), f.FieldType())) {
                return 0;
            }
        }
    }

    // Event Times
    if (_rule->TimeFieldMode() != AggregationFieldMode::DROP) {
        buffer.Clear();
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartArray();
        for (auto& v : _event_times) {
            writer.String(_data.data()+v.first, v.second);
        }
        writer.EndArray();
        if (!builder.AddField(AGG_EVENT_TIME_SV, std::string_view(buffer.GetString(), buffer.GetSize()), std::string_view(), field_type_t::UNCLASSIFIED)) {
            return 0;
        }
    }

    // Event Serials
    if (_rule->SerialFieldMode() != AggregationFieldMode::DROP) {
        buffer.Clear();
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartArray();
        for (auto& v : _event_serials) {
            writer.String(_data.data()+v.first, v.second);
        }
        writer.EndArray();
        if (!builder.AddField(AGG_SERIAL_SV, std::string_view(buffer.GetString(), buffer.GetSize()), std::string_view(), field_type_t::UNCLASSIFIED)) {
            return 0;
        }
    }

    auto agg_fields = _rule->AggregationFields();
    for (auto i = 0; i < agg_fields.size(); ++i) {
        if (agg_fields[i].Mode() == AggregationFieldMode::DROP) {
            continue;
        }
        buffer.Clear();
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartArray();
        for (auto& v : _aggregated_fields[i]) {
            writer.String(_data.data()+v.first, v.second);
        }
        writer.EndArray();
        if (!builder.AddField(agg_fields[i].OutputName(), std::string_view(buffer.GetString(), buffer.GetSize()), std::string_view(), field_type_t::UNCLASSIFIED)) {
            return 0;
        }
    }

    if (!builder.EndRecord()) {
        return 0;
    }

    return builder.EndEvent();
}

/****************************************************************************
 *
 ****************************************************************************/

void EventAggregator::SetRules(const std::vector<std::shared_ptr<AggregationRule>>& rules) {
    if (_rules.empty()) {
        // Assume this is empty so just init _rules and _events.
        _rules = rules;
        _events.reserve(_rules.size());
        _events.resize(0);
        for (auto& r : _rules) {
            _events.emplace_back(std::make_shared<PerRuleAgg>(r));
        }
    } else {
        // This was previously initialized (or loaded from a file)
        // For any partially aggregated events, if the previous rule does not match a new rule
        // Stuff it into the ready queue.

        // Get the index of the new rules, use the rule JSON as the key
        std::unordered_map<std::string, int> rule_idx;
        int idx = 0;
        for (auto& r : rules) {
            rule_idx.emplace(std::make_pair(r->ToJSONString(), idx));
            idx += 1;
        }

        // Make a copy of the _events
        std::vector<std::shared_ptr<PerRuleAgg>> events(_events);

        // Init the new _rules and _events
        _rules = rules;
        _events.reserve(_rules.size());
        _events.resize(0);
        for (auto& r : _rules) {
            _events.emplace_back(std::make_shared<PerRuleAgg>(r));
        }

        // Sort out the existing events        
        for (auto& e : events) {
            std::string js = e->_rule->ToJSONString();
            auto it = rule_idx.find(js);
            if (it == rule_idx.end()) {
                // This entries rule doesn't match any of the new rules so stuff its events into _ready_events
                for (auto& a : e->_events) {
                    _ready_events.push(a.second);
                }
            } else {
                // This entries rule matches a new rule
                // Copy its events into _events
                for (auto& a : e->_events) {
                    _events[it->second]->_events.emplace(a);
                    _events[it->second]->_events_age.emplace(a.second->AgeKey(), a.first);
                }
            }
        }

        // Re-initialize _aged_events
        _aged_events.clear();
        for (int i = 0; i < _events.size(); ++i) {
            auto e = _events[i];
            for (auto& a : e->_events) {
                _aged_events.emplace(a.second->AgeKey(), std::make_pair(a.second,i));
            }
        }
    }

    std::vector<std::shared_ptr<EventMatchRule>> erules;
    erules.reserve(_rules.size());
    for (auto& r : _rules) {
        erules.emplace_back(r->MatchRule());
    }

    if (!_matcher->Compile(erules)) {
        throw std::runtime_error(join(_matcher->Errors(), "\n"));
    }
}

void EventAggregator::Load(const std::string& path) {
    std::array<char, 256*1024> buf;

    FILE *file = fopen(path.c_str(), "r");
    if (file == nullptr) {
        throw std::system_error(errno, std::system_category(), "fopen("+path+", 'r')");
    }
    Defer defer_close([file](){
        fclose(file);
    });

    // Rerad the header
    size_t num_rules;
    size_t num_ready_events;
    size_t num_partial_events;
    if (fscanf(file, "EventAggregator::HEADER: %ld:%ld:%ld\n", &num_rules, &num_ready_events, &num_partial_events) != 3) {
        throw std::runtime_error("EventAggregator::Load(): Invalid header");
    }

    _rules.reserve(256);
    _rules.resize(0);

    // Read the aggregation rules
    for (int i = 0; i < num_rules; ++i) {
        size_t rule_size;
        if (fscanf(file, "RULE HEADER: %ld\n", &rule_size) != 1) {
            throw std::runtime_error("EventAggregator::Load(): Invalid rules header: Failed to read");
        }
        if (rule_size > buf.size()) {
            throw std::runtime_error("EventAggregator::Load(): Invalid rules header: size too large");
        }
        if (fread(buf.data(), rule_size, 1, file) != 1) {
            throw std::runtime_error("EventAggregator::Load(): Failed to read rule");
        }
        buf[rule_size] = 0;
        std::shared_ptr<AggregationRule> rule;
        try {
            rapidjson::Document doc;
            doc.ParseInsitu(buf.data());
            rule = AggregationRule::FromJSON(doc);
        } catch (const std::exception& ex) {
            std::stringstream str;
            str << "EventAggregator::Load(): Failed to parse rule: ";
            if (ex.what() != nullptr) {
                str << ex.what();
            } else {
                str << "Unknown exception";
            }
            throw std::runtime_error(str.str());
        }

        _rules.emplace_back(rule);
    }

    _events.reserve(_rules.size());
    _events.resize(0);

    // Initialize _events from the rules
    for (auto& r : _rules) {
        _events.emplace_back(std::make_shared<PerRuleAgg>(r));
    }

    // Read the ready events
    while(!_ready_events.empty()) {
        _ready_events.pop();
    }
    for (size_t i = 0; i < num_ready_events; ++i) {
        auto e = AggregatedEvent::Read(file, _rules);
        _ready_events.push(e);
    }

    // Capture rule indexes
    std::unordered_map<std::shared_ptr<AggregationRule>, int> rule_idxs;
    for (int i = 0; i < _rules.size(); ++i) {
        rule_idxs[_rules[i]] = i;
    }

    _aged_events.clear();

    // Read the partial events
    for (size_t i = 0; i < num_partial_events; ++i) {
        auto e = AggregatedEvent::Read(file, _rules);
        auto ridx = rule_idxs.at(e->Rule());
        _events[ridx]->_events.emplace(std::make_pair(e->AggregationKey(), e));
        _events[ridx]->_events_age.emplace(e->AgeKey(), e->AggregationKey());
        _aged_events.emplace(e->AgeKey(), std::make_pair(e, ridx));
    }

    // Collect the EventMatchRule from the Aggregation rules
    std::vector<std::shared_ptr<EventMatchRule>> erules;
    erules.reserve(_rules.size());
    for (auto& r : _rules) {
        erules.emplace_back(r->MatchRule());
    }

    // Compile the matcher
    if (!_matcher->Compile(erules)) {
        throw std::runtime_error(join(_matcher->Errors(), "\n"));
    }
}

void EventAggregator::Save(const std::string& path) {
    size_t num_partial_events = 0;
    for (auto& e : _events) {
        num_partial_events += e->_events.size();
    }


    FILE *file = fopen(path.c_str(), "w");
    if (file == nullptr) {
        throw std::system_error(errno, std::system_category(), "fopen("+path+", 'w')");
    }
    Defer defer_close([file](){
        fclose(file);
    });

    if (fchmod(fileno(file), 0600) != 0) {
        throw std::system_error(errno, std::system_category(), "fchmod()");
    }

    rapidjson::StringBuffer js_buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(js_buffer);

    // Write header
    if (fprintf(file, "EventAggregator::HEADER: %ld:%ld:%ld\n", _rules.size(), _ready_events.size(), num_partial_events) < 0) {
        throw std::runtime_error("EventAggregator::Save(): Failed to write header");
    }

    // Write Aggregation Rules
    for (auto& r : _rules) {
        js_buffer.Clear();
        writer.Reset(js_buffer);
        r->ToJSON(writer);
        if (fprintf(file, "RULE HEADER: %ld\n", js_buffer.GetSize()+1) < 0) {
            throw std::runtime_error("EventAggregator::Save(): Failed to write rule header");
        }
        if (fwrite(js_buffer.GetString(), js_buffer.GetSize(), 1, file) != 1) {
            throw std::runtime_error("EventAggregator::Save(): Failed to write rule data");
        }
        if (fprintf(file, "\n") < 0) {
            throw std::runtime_error("EventAggregator::Save(): Failed to write rule data");
        }
    }

    // Capture rule indexes
    std::unordered_map<std::shared_ptr<AggregationRule>, int> rule_idxs;
    for (int i = 0; i < _rules.size(); ++i) {
        rule_idxs[_rules[i]] = i;
    }

    // Make a copy of the _ready_events queue
    std::queue<std::shared_ptr<AggregatedEvent>> revents(_ready_events);

    // Write the ready events
    while(!revents.empty()) {
        revents.front()->Write(file, rule_idxs);
        revents.pop();
    }

    // Write the partial events
    for (auto& e : _events) {
        for (auto& a : e->_events) {
            a.second->Write(file, rule_idxs);
        }
    }
}

bool EventAggregator::AddEvent(const Event& event) {
    // Only consider events with one event record
    if (event.NumRecords() != 1) {
        return false;
    }

    // Check if event matches an aggregation rule
    auto idx = _matcher->Match(event);
    if (idx < 0) {
        return false;
    }

    auto& e = _events[idx];

    // Find AggregatedEvent based on Aggregation Key
    e->_rule->CalcAggregationKey(_tmp_key, event);
    auto it = e->_events.find(_tmp_key);
    if (it == e->_events.end()) {
        // Make sure we don't exceed the max pending limit
        while (e->_events.size() >= e->_rule->MaxPending()) {
            auto it2 = e->_events.find(e->_events_age.begin()->second);
            e->_events_age.erase(e->_events_age.begin());
            if (it2 != e->_events.end()) {
                _aged_events.erase(it2->second->AgeKey());
                _ready_events.emplace(it2->second);
                e->_events.erase(it2);
            }
        }

        // Create new AggregatedEvent
        auto agg = std::make_shared<AggregatedEvent>(e->_rule);
        if (!agg->AddEvent(event)) {
            return false;
        }
        // Event was added so add new AggregatedEvent to e->_events and _agged_events
        e->_events.emplace(std::make_pair(agg->AggregationKey(), agg));
        e->_events_age.emplace(agg->AgeKey(), agg->AggregationKey());
        _aged_events.emplace(agg->AgeKey(), std::make_pair(agg,idx));
        return true;
    } else {
        if (!it->second->AddEvent(event)) {
            // Event wasn't added to current AggregatedEvent so treat it as full and move it to the _ready_events queue
            _ready_events.emplace(it->second);
            _aged_events.erase(it->second->AgeKey());
            // Remove the entry from e->_events, it's key data lifecycle is tied to the agg we just removed.
            e->_events_age.erase(it->second->AgeKey());
            e->_events.erase(it);
            // Create a new AggregatedEvent
            auto agg = std::make_shared<AggregatedEvent>(e->_rule);
            // Try to add the event to the new AggregatedEvent
            if (!agg->AddEvent(event)) {
                // The event wasn't added to the new AggregatedEvent so return false
                return false;
            }
            e->_events.emplace(std::make_pair(agg->AggregationKey(), agg));
            e->_events_age.emplace(agg->AgeKey(), agg->AggregationKey());
            _aged_events.emplace(agg->AgeKey(), std::make_pair(agg,idx));
        }
        return true;
    }
}

std::tuple<bool, int64_t, bool> EventAggregator::HandleEvent(const std::function<std::pair<int64_t, bool> (const Event& event)>& handler_fn) {
    auto now = std::chrono::steady_clock::now();
    while (!_aged_events.empty() && _aged_events.begin()->first.first < now) {
        auto agg = _aged_events.begin()->second.first;
        auto idx = _aged_events.begin()->second.second;
        _ready_events.emplace(agg);
        // Remove the agg from _events so it doesn't keep accumulatting
        _events[idx]->_events_age.erase(_aged_events.begin()->first);
        _events[idx]->_events.erase(agg->AggregationKey());
        // Remove from _aged_events
        _aged_events.erase(_aged_events.begin());
    }

    if (_ready_events.empty()) {
        return std::make_tuple(false, 0, false);
    }

    auto agg = _ready_events.front();

    auto bret = agg->BuildEvent(_builder, _js_buffer);
    if (bret <= 0) {
        return std::make_tuple(false, bret, false);
    }

    auto fret = handler_fn(_allocator->GetEvent());

    if (fret.second) {
        _ready_events.pop();
    }

    return std::make_tuple(true, fret.first, fret.second);
}
