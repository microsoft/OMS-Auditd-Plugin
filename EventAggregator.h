/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_EVENTAGGREGATOR_H
#define AUOMS_EVENTAGGREGATOR_H

#include <atomic>
#include <chrono>
#include <functional>
#include <queue>
#include <unordered_map>
#include <vector>
#include <string_view>
#include <map>

#include "EventMatcher.h"
#include "EventId.h"

#include <rapidjson/document.h>

/*

    [
        {
            "match_rule": {
                "record_types": [],
                "field_rules": [
                    {
                        "field_name": "syscall",
                        "op": "re",
                        "value": "execve"
                    },
                    {
                        "field_name": "cmdline",
                        "op": "re",
                        "value": "/stuff/[0-9]+/foo"
                    },
                ]
            },
            "aggregation_fields": {
                "time": {
                    "mode": "raw" // interp, dynamic
                    "output_name": "aggregated_time"
                }
                "pid": {},
            },
            "time_field_mode": "drop", (full, delta, drop)
            "serial_field_mode": "drop",
            "max_size": 2048,
            "max_time": 300,
            "send_first_as_raw": true
        },
        {
            "match_rule": {
                "record_types": [],
                "field_rules": [
                    {
                        "field_name": "syscall",
                        "op": "re",
                        "values": ["execve","open"]
                    },
                ]
            },
        },
    ]


*/

enum class AggregationFieldMode: int {
    NORMAL = -1,
    DROP = 0,
    RAW = 1,
    INTERP = 2,
    DYNAMIC = 3,
    DELTA = 4,
};

class AggregationField {
public:
    AggregationField(const std::string& name): _name(name), _mode(AggregationFieldMode::DYNAMIC), _output_name(name) {}
    AggregationField(const std::string& name, AggregationFieldMode mode): _name(name), _mode(mode), _output_name(name) {}
    AggregationField(const std::string& name, AggregationFieldMode mode, const std::string& output_name): _name(name), _mode(mode), _output_name(output_name) {}

    inline const std::string& Name() const {
        return _name;
    }

    inline AggregationFieldMode Mode() const {
        return _mode;
    }

    inline const std::string& OutputName() const {
        return _output_name;
    }

private:
    std::string _name;
    AggregationFieldMode _mode;
    std::string _output_name;
};

class AggregationRule {
public:
    static constexpr uint32_t DEFAULT_MAX_PENDING = 1024;
    static constexpr uint32_t MIN_MAX_PENDING = 1;
    static constexpr uint32_t MAX_MAX_PENDING = 10240;
    static constexpr uint32_t DEFAULT_MAX_SIZE = 8192;
    static constexpr uint32_t MIN_MAX_SIZE = 128;
    static constexpr uint32_t MAX_MAX_SIZE = 128*1024;
    static constexpr uint32_t DEFAULT_MAX_COUNT = 1024;
    static constexpr uint32_t MIN_MAX_COUNT = 2;
    static constexpr uint32_t MAX_MAX_COUNT = 128*1024;
    static constexpr uint32_t DEFAULT_MAX_TIME = 900; // 15 minutes
    static constexpr uint32_t MIN_MAX_TIME = 1; // 1 second
    static constexpr uint32_t MAX_MAX_TIME = 3600; // 1 hour
    static constexpr bool DEFAULT_SEND_FIRST = false;
    

    AggregationRule(const std::shared_ptr<EventMatchRule>& match_rule, const std::vector<AggregationField>& aggregation_fields,
                    AggregationFieldMode time_field_mode, AggregationFieldMode serial_field_mode,
                    uint32_t max_pending, uint32_t max_count, uint32_t max_size, uint32_t max_time, bool send_first)
        : _match_rule(match_rule), _aggregation_fields(aggregation_fields), _aggregation_fields_map(),
          _time_field_mode(time_field_mode), _serial_field_mode(serial_field_mode),
          _max_pending(max_pending), _max_count(max_count), _max_size(max_size), _max_time(max_time), _send_first(send_first)
    {
        if (_max_pending < MIN_MAX_PENDING) {
            _max_pending = MIN_MAX_PENDING;
        } else if (_max_pending > MAX_MAX_PENDING) {
            _max_pending = MAX_MAX_PENDING;
        }

        if (_max_count < MIN_MAX_COUNT) {
            _max_count = MIN_MAX_COUNT;
        } else if (_max_count > MAX_MAX_COUNT) {
            _max_count = MAX_MAX_COUNT;
        }

        if (_max_size < MIN_MAX_SIZE) {
            _max_size - MIN_MAX_SIZE;
        } else if (_max_size > MAX_MAX_SIZE) {
            _max_size - MAX_MAX_SIZE;
        }

        if (_max_time < MIN_MAX_TIME) {
            _max_time = MIN_MAX_TIME;
        } else if (_max_time > MAX_MAX_TIME) {
            _max_time = MAX_MAX_TIME;
        }

        _num_drop_fields = 0;
        for (int i = 0; i < _aggregation_fields.size(); ++i) {
            if (_aggregation_fields[i].Mode() == AggregationFieldMode::DROP) {
                _num_drop_fields += 1;
            }
            _aggregation_fields_map.emplace(std::make_pair(std::string_view(_aggregation_fields[i].Name()), i));
        }
    }

    static void RulesFromJSON(const rapidjson::Value& value, std::vector<std::shared_ptr<AggregationRule>>& rules);
    static std::shared_ptr<AggregationRule> FromJSON(const rapidjson::Value& value);
    static std::shared_ptr<AggregationRule> FromJSON(const std::string& str);
    void ToJSON(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;
    std::string ToJSONString() const;

    inline std::shared_ptr<EventMatchRule> MatchRule() const {
        return _match_rule;
    }

    inline const std::vector<AggregationField>& AggregationFields() const {
        return _aggregation_fields;
    }

    inline int NumDropFields() const {
        return _num_drop_fields;
    }

    inline AggregationFieldMode FieldMode(const std::string_view& name) const {
        auto it = _aggregation_fields_map.find(name);
        if (it != _aggregation_fields_map.end()) {
            return _aggregation_fields[it->second].Mode();
        } else {
            return AggregationFieldMode::NORMAL;
        }
    }

    inline bool HasAggregationField(const std::string_view& name) const {
        return _aggregation_fields_map.count(name) > 0;
    }

    inline AggregationFieldMode TimeFieldMode() const {
        return _time_field_mode;
    }

    inline AggregationFieldMode SerialFieldMode() const {
        return _serial_field_mode;
    }

    inline uint32_t MaxPending() const {
        return _max_pending;
    }

    inline uint32_t MaxCount() const {
        return _max_count;
    }

    inline uint32_t MaxSize() const {
        return _max_size;
    }

    inline uint32_t MaxTime() const {
        return _max_time;
    }

    inline bool SendFirst() const {
        return _send_first;
    }

    // The aggregation key is the set of non-aggregated fields
    // The string_views placed in key point to data in event and thus have the
    // same validity lifespan
    void CalcAggregationKey(std::vector<std::string_view>& key, const Event& event) const;

private:
    std::shared_ptr<EventMatchRule> _match_rule;
    std::vector<AggregationField> _aggregation_fields;
    std::unordered_map<std::string_view, int> _aggregation_fields_map;
    int _num_drop_fields;
    AggregationFieldMode _time_field_mode;
    AggregationFieldMode _serial_field_mode;
    uint32_t _max_pending;
    uint32_t _max_count;
    uint32_t _max_size; //bytes
    uint32_t _max_time; //seconds
    bool _send_first;
};

class EventAggregator;

class AggregatedEvent {
public:
    AggregatedEvent(const std::shared_ptr<AggregationRule>& rule): _rule(rule), _last_event(0, 0, 0) {
        _id = _next_id.fetch_add(1);
        _count = 0;
        _expiration_time = std::chrono::steady_clock::now() + std::chrono::seconds(_rule->MaxTime());
        _data.reserve(AggregationRule::MIN_MAX_SIZE);
        _aggregated_fields.resize(_rule->AggregationFields().size());
        _event_times.reserve(AggregationRule::MIN_MAX_COUNT);
        _event_serials.reserve(AggregationRule::MIN_MAX_COUNT);
        for (auto& x : _aggregated_fields) {
            x.reserve(AggregationRule::MIN_MAX_COUNT);
        }
    }

    static std::shared_ptr<AggregatedEvent> Read(FILE* file, std::vector<std::shared_ptr<AggregationRule>> rules);
    void Write(FILE* file, const std::unordered_map<std::shared_ptr<AggregationRule>, int>& rules_map) const;

    inline const std::shared_ptr<AggregationRule>& Rule() const {
        return _rule;
    }

    inline bool Empty() const {
        return _count == 0;
    }

    inline uint64_t Id() const {
        return _id;
    }

    inline std::chrono::steady_clock::time_point ExpirationTime() const {
        return _expiration_time;
    }

    inline std::pair<std::chrono::steady_clock::time_point, uint64_t> AgeKey() const {
        return std::make_pair(_expiration_time, _id);
    }

    inline const std::vector<std::string_view>& AggregationKey() const {
        return _agg_key;
    }

    // Return true of the event was added
    // Return false if the event was not added (and thus the AggregatedEvent is full)
    bool AddEvent(const Event& event);

    int BuildEvent(EventBuilder& builder, rapidjson::StringBuffer& buffer) const;

private:
    friend class EventAggregator;

    AggregatedEvent() {}

    static std::atomic<uint64_t> _next_id;

    std::shared_ptr<AggregationRule> _rule;
    std::chrono::steady_clock::time_point _expiration_time;
    uint64_t _id;
    EventId _first_event;
    EventId _last_event;
    uint32_t _count;
    std::vector<uint8_t> _origin_event;
    std::vector<std::string_view> _agg_key;
    std::string _data;
    std::vector<std::pair<size_t, size_t>> _event_times;
    std::vector<std::pair<size_t, size_t>> _event_serials;
    std::vector<std::vector<std::pair<size_t, size_t>>> _aggregated_fields;
};

template<>
struct std::hash<std::vector<std::string_view>>
{
    std::size_t operator()(std::vector<std::string_view> const& v) const noexcept
    {
        size_t h = 0;
        for (auto& i : v) {
            // This is algorithm is taken from boost:hash_combine();
            h ^= std::hash<std::string_view>{}(i) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};

class EventAggregator {
public:
    EventAggregator():
        _allocator(std::make_shared<BasicEventBuilderAllocator>(256*1024)),
        _builder(_allocator, DefaultPrioritizer::Create(0)),
        _matcher(std::make_shared<EventMatcher>())
    {}

    // Set rules
    // If existing rules exist, any events associated with old rules that are not in the new set, will be flushed to the _ready_events queue.
    void SetRules(const std::vector<std::shared_ptr<AggregationRule>>& rules);

    // Load saved aggregation state from file
    // Any previous state is lost
    void Load(const std::string& path);

    // Save aggregation state to file
    void Save(const std::string& path);

    // Check if event is aggregated
    // Return true if the event was consumed (aggregated)
    bool AddEvent(const Event& event);

    // Check for complete/ready aggregated events and handle one
    // If handler_fn returns ret.second == true, then event was consumed
    // ret.get<0>, true if handler_fn invoked, false if no events ready
    // ret.get<1>, if get<0> is true, then ret.first from handler_fn, otherwise ret from AggregatedEvent::BuildEvent()
    // ret.get<2>, if get<0> is true, then ret.second from handler_fn, otherwise false
    std::tuple<bool, int64_t, bool> HandleEvent(const std::function<std::pair<int64_t, bool> (const Event& event)>& handler_fn);

    size_t NumReadyAggregates() const {
        return _ready_events.size();
    }

    size_t NumPendingAggregates() const {
        size_t count = 0;
        for (auto& e : _events) {
            count += e->_events.size();
        }
        return count;
    }

private:
    class PerRuleAgg {
    public:
        explicit PerRuleAgg(const std::shared_ptr<AggregationRule>& rule): _rule(rule), _events(16) {}

        std::shared_ptr<AggregationRule> _rule;
        std::unordered_map<std::vector<std::string_view>,std::shared_ptr<AggregatedEvent>> _events;
        std::map<std::pair<std::chrono::steady_clock::time_point, uint64_t>, std::vector<std::string_view>> _events_age;
    };

    std::vector<std::shared_ptr<AggregationRule>> _rules;
    std::shared_ptr<EventMatcher> _matcher;
    std::vector<std::shared_ptr<PerRuleAgg>> _events;
    std::map<std::pair<std::chrono::steady_clock::time_point, uint64_t>, std::pair<std::shared_ptr<AggregatedEvent>, int>> _aged_events;
    std::queue<std::shared_ptr<AggregatedEvent>> _ready_events;
    std::vector<std::string_view> _tmp_key;
    rapidjson::StringBuffer _js_buffer;
    std::shared_ptr<BasicEventBuilderAllocator> _allocator;
    EventBuilder _builder;
};

#endif //AUOMS_EVENTAGGREGATOR_H
