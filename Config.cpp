/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "Config.h"

#include "Logger.h"

#include <iostream>
#include <fstream>

std::string trim(const std::string& str)
{
    auto sidx = str.find_first_not_of(" \t");
    if (sidx == std::string::npos) {
        return std::string();
    }
    auto eidx = str.find_last_not_of(" \t");
    eidx++;
    return str.substr(sidx, eidx-sidx);
}

void Config::Load(const std::string& path)
{
    std::ifstream fs(path);

    int line_num = 1;
    for (std::string line; std::getline(fs, line); line_num++) {
        // Exclude comment lines
        auto idx = line.find_first_not_of(" \t");
        if (idx == std::string::npos || line[idx] == '#') {
            continue;
        }
        // Find '='
        idx = line.find('=');
        if (idx == std::string::npos) {
            throw std::runtime_error("Invalid parameter (missing '='): Line " + std::to_string(line_num));
        }

        std::string key = trim(line.substr(0, idx));
        std::string val = trim(line.substr(idx+1));

        if (val[0] == '"') {
            std::string nval;
            nval.reserve(val.size());
            std::string::size_type sidx = 1;
            auto eidx = val.find("\\\"", sidx);
            while (eidx != std::string::npos) {
                nval.append(val.substr(sidx, eidx - sidx));
                nval.append("\"");
                sidx = eidx + 2;
                eidx = val.find("\\\"", sidx);
            }
            eidx = val.find('"', sidx);
            if (eidx == std::string::npos) {
                throw std::runtime_error("Value is missing close quote '\"': Line " + std::to_string(line_num));
            }
            nval.append(val.substr(sidx, eidx - sidx));
            auto idx = val.find_first_not_of(" \t", eidx + 1);
            if (idx != std::string::npos && val[idx] != '#') {
                throw std::runtime_error("Invalid characters following value: Line " + std::to_string(line_num));
            }
            val = nval;
        } else if (val.size() > 3 && val[0] == 'R' && val[1] == '"') {
            auto spidx = val.find_first_of('(', 2);
            if (spidx == std::string::npos) {
                throw std::runtime_error("Invalid raw string value: Line " + std::to_string(line_num));
            }
            auto delim = val.substr(2, spidx-2);
            if (val[val.size()-1] != '"' || val[val.size()-2-delim.size()] != ')') {
                throw std::runtime_error("Invalid raw string value: Line " + std::to_string(line_num));
            }
            if (val.substr(val.size()-1-delim.size(), delim.size()) != delim) {
                throw std::runtime_error("Invalid raw string value: Line " + std::to_string(line_num));
            }
            val = val.substr(spidx+1, val.size()-((delim.size()*2)+5));
        } else if (val[0] == '{' || val[0] == '[') {
            int start_line_num = line_num;
            std::string nval = val;

            rapidjson::Document doc;
            while (doc.Parse(nval.c_str()).HasParseError()) {
                if (!std::getline(fs, line)) {
                    throw std::runtime_error("Incomplete or invalid JSON value: Line " + std::to_string(start_line_num));
                }
                nval.append(line);
            }
            val = nval;
        } else {
            auto eidx = val.find_first_of(" \t");
            if (eidx != std::string::npos) {
                auto cidx = val.find_first_not_of(" \t", eidx);
                if (cidx != std::string::npos) {
                    if (val[cidx] != '#') {
                        throw std::runtime_error("White space in value (may need to be quoted with '\"'): Line " + std::to_string(line_num));
                    }
                }
                val = val.substr(0, eidx);
            }
        }

        _map.insert(std::make_pair(key, val));
    }
}

bool Config::HasKey(const std::string& name) const
{
    return _map.count(name) > 0;
}

bool Config::GetBool(const std::string& name) const
{
    if (!HasKey(name)) {
        throw std::runtime_error("Config::GetBool(): Key not found: " + name);
    } else {
        std::string val = _map.at(name);
        if (val == "on" || val == "yes" || val == "true") {
            return true;
        }
        return false;
    }
}

double Config::GetDouble(const std::string& name) const
{
    if (!HasKey(name)) {
        throw std::runtime_error("Config::GetDouble(): Key not found: " + name);
    } else {
        return std::stod(_map.at(name));
    }
}

int64_t Config::GetInt64(const std::string& name) const
{
    if (!HasKey(name)) {
        throw std::runtime_error("Config::GetInt64(): Key not found: " + name);
    } else {
        return std::stoll(_map.at(name));
    }
}

uint64_t Config::GetUint64(const std::string& name) const
{
    if (!HasKey(name)) {
        throw std::runtime_error("Config::GetUint64(): Key not found: " + name);
    } else {
        return std::stoull(_map.at(name));
    }
}

std::string Config::GetString(const std::string& name) const
{
    if (!HasKey(name)) {
        throw std::runtime_error("Config::GetString(): Key not found: " + name);
    } else {
        return _map.at(name);
    }
}

rapidjson::Document Config::GetJSON(const std::string& name) const
{
    if (!HasKey(name)) {
        throw std::runtime_error("Config::GetJSON(): Key not found: " + name);
    } else {
        rapidjson::Document doc;
        doc.Parse(_map.at(name).c_str());
        return doc;
    }
}
