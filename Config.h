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
    explicit Config(std::unordered_map<std::string, std::string> map): _map(std::move(map)) {}

    void Load(const std::string& path);

    void SetString(const std::string& name, const std::string& value) {
        _map[name] = value;
    }

    bool HasKey(const std::string& name) const;
    bool GetBool(const std::string& name) const;
    double GetDouble(const std::string& name) const;
    int64_t GetInt64(const std::string& name) const;
    uint64_t GetUint64(const std::string& name) const;
    std::string GetString(const std::string& name) const;
    rapidjson::Document GetJSON(const std::string& name) const;

    bool operator==(const Config& other) { return _map == other._map; }
    bool operator!=(const Config& other) { return _map != other._map; }

private:
    std::unordered_map<std::string, std::string> _map;
};


#endif //AUOMS_CONFIG_H
