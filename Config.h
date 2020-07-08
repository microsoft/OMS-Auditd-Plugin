/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_CONFIG_H
#define AUOMS_CONFIG_H

#include <cstdint>
#include <unordered_map>
#include <unordered_set>

#include <rapidjson/document.h>

class Config {
public:
    Config() = default;
    explicit Config(const std::unordered_set<std::string>& allowed_overrides): _allowed_overrides(allowed_overrides) {}
    explicit Config(const std::unordered_map<std::string, std::string>& map): _map(map) {}

    void Load(const std::string& path);

    bool HasKey(const std::string& name) const;

    bool GetBool(const std::string& name) const;
    bool GetBool(const std::string& name, bool default_value) const {
        if (HasKey(name)) {
            return GetBool(name);
        }
        return default_value;
    }

    int64_t GetInt64(const std::string& name) const;
    int64_t GetInt64(const std::string& name, int64_t default_value) const {
        if (HasKey(name)) {
            return GetInt64(name);
        }
        return default_value;
    }

    uint64_t GetUint64(const std::string& name) const;
    uint64_t GetUint64(const std::string& name, uint64_t default_value) const {
        if (HasKey(name)) {
            return GetUint64(name);
        }
        return default_value;
    }

    std::string GetString(const std::string& name) const;
    std::string GetString(const std::string& name, const std::string& default_value) const {
        if (HasKey(name)) {
            return GetString(name);
        }
        return default_value;
    }

    rapidjson::Document GetJSON(const std::string& name) const;

    bool operator==(const Config& other) { return _map == other._map; }
    bool operator!=(const Config& other) { return _map != other._map; }

private:
    void read_file(const std::string& path, std::unordered_map<std::string, std::string>& map);

    std::unordered_set<std::string> _allowed_overrides;
    std::unordered_map<std::string, std::string> _map;
};

#endif //AUOMS_CONFIG_H
