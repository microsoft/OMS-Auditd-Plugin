/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "OMSEventTransformerConfig.h"

#include "Logger.h"

static std::string _tolower(const std::string& in)
{
    std::string out = in;
    for (size_t i = 0; i < out.size(); i++ ) {
        out[i] = std::tolower(out[i]);
    }
    return out;
}

typedef bool (*config_set_func_t)(const std::string& name, OMSEventTransformerConfig& et_config, const Config& config);

static std::unordered_map<std::string, config_set_func_t> _configSetters = {
        {"include_full_raw_text", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.IncludeFullRawText = config.GetBool(name);
            }
            return true;
        }},
        {"raw_text_field_name", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RawTextFieldName = config.GetString(name);
            }
            return true;
        }},
        {"timestamp_field_name", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.TimestampFieldName = config.GetString(name);
            }
            return true;
        }},
        {"serial_field_name", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.SerialFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_type_field_name", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordTypeFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_type_name_field_name", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordTypeNameFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_count_field_name", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordCountFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_index_field_name", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordIndexFieldName = config.GetString(name);
            }
            return true;
        }},
        {"record_data_field_name_prefix", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.RecordDataFieldNamePrefix = config.GetString(name);
            }
            return true;
        }},
        {"field_suffix", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
            if (config.HasKey(name)) {
                et_config.FieldSuffix = config.GetString(name);
            }
            return true;
        }},
        {"record_type_name_overrides", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
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
        {"field_name_overrides", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
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
        {"interpreted_field_names", [](const std::string& name, OMSEventTransformerConfig& et_config, const Config& config)->bool{
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

bool OMSEventTransformerConfig::LoadFromConfig(const Config& config)
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
