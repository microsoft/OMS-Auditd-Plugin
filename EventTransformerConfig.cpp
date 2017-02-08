/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "EventTransformerConfig.h"

#include "Logger.h"

static std::string _tolower(const std::string& in)
{
    std::string out = in;
    for (size_t i = 0; i < out.size(); i++ ) {
        out[i] = std::tolower(out[i]);
    }
    return out;
}

typedef bool (*config_set_func_t)(const std::string& name, EventTransformerConfig& et_config, const Config& config);

static std::unordered_map<std::string, config_set_func_t> _configSetters = {
        {"include_full_raw_text", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.IncludeFullRawText = config.GetBool(name);
            }
            return true;
        }},
        {"field_name_dedup_index_one_based", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.FieldNameDedupIndexOneBased = config.GetBool(name);
            }
            return true;
        }},
        {"field_name_dedup_index_global", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.FieldNameDedupIndexGlobal = config.GetBool(name);
            }
            return true;
        }},
        {"field_name_dedup_suffix_raw_field", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.FieldNameDedupSuffixRawField = config.GetBool(name);
            }
            return true;
        }},
        {"decode_escaped_field_values", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.DecodeEscapedFieldValues = config.GetBool(name);
            }
            return true;
        }},
        {"raw_text_field_name", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RawTextFieldName = config.GetString(name);
            }
            return true;
        }},
        {"field_name_separator", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.FieldNameSeparator = config.GetString(name);
            }
            return true;
        }},
        {"timestamp_field_name", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.TimestampFieldName = config.GetString(name);
            }
            return true;
        }},
        {"serial_field_name", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.SerialFieldName = config.GetString(name);
            }
            return true;
        }},
        {"msg_type_field_name", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.MsgTypeFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_count_field_name", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordCountFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_type_field_name", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordTypeFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_name_field_name", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordNameFieldName = config.GetString(name);
            }
            return true;
        }},
        {"field_suffix", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.FieldSuffix = config.GetString(name);
            }
            return true;
        }},

        {"field_emit_mode", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                std::string val = config.GetString(name);
                if (_tolower(val) == "raw") {
                    et_config.FieldEmitMode = EventTransformerConfig::EMIT_RAW;
                } else if (_tolower(val) == "interp" ) {
                    et_config.FieldEmitMode = EventTransformerConfig::EMIT_INTERP;
                } else if (_tolower(val) == "both") {
                    et_config.FieldEmitMode = EventTransformerConfig::EMIT_BOTH;
                } else {
                    return false;
                }
            }
            return true;
        }},
        {"field_prefix_mode", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                std::string val = config.GetString(name);
                if (_tolower(val) == "index") {
                    et_config.FieldPrefixMode = EventTransformerConfig::PREFIX_RECORD_INDEX;
                } else if (_tolower(val) == "type_number") {
                    et_config.FieldPrefixMode = EventTransformerConfig::PREFIX_RECORD_TYPE_NUMBER;
                } else if (_tolower(val) == "type_name") {
                    et_config.FieldPrefixMode = EventTransformerConfig::PREFIX_RECORD_TYPE_NAME;
                } else {
                    return false;
                }
            }
            return true;
        }},
        {"record_type_name_overrides", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                auto doc = config.GetJSON(name);
                if (!doc.IsObject()) {
                    return false;
                }
                for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
                    et_config.RecordTypeNameOverrideMap.emplace(std::make_pair(
                            it->name.GetInt(),
                            std::string(it->value.GetString(), it->value.GetStringLength())
                    ));
                }
            }
            return true;
        }},
        {"field_name_overrides", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                auto doc = config.GetJSON(name);
                if (!doc.IsObject()) {
                    return false;
                }
                for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
                    et_config.FieldNameOverrideMap.emplace(std::make_pair(
                            std::string(it->name.GetString(), it->name.GetStringLength()),
                            std::string(it->value.GetString(), it->value.GetStringLength())
                    ));
                }
            }
            return true;
        }},
        {"interpreted_field_names", [](const std::string& name, EventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                auto doc = config.GetJSON(name);
                if (!doc.IsObject()) {
                    return false;
                }
                for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
                    et_config.InterpFieldNameMap.emplace(std::make_pair(
                            std::string(it->name.GetString(), it->name.GetStringLength()),
                            std::string(it->value.GetString(), it->value.GetStringLength())
                    ));
                }
            }
            return true;
        }},
};

bool EventTransformerConfig::LoadFromConfig(const Config& config)
{
    bool good = true;
    for (auto cs : _configSetters) {
        try {
            if (!cs.second(cs.first, *this, config)) {
                Logger::Error("Invalid config value for '%s'", cs.first.c_str());
                good = false;
            }
        } catch (std::exception& ex) {
            Logger::Error("Invalid config value for '%s'", cs.first.c_str());
            good = false;
        }
    }
    return good;
}
