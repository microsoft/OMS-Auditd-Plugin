/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_STRINGTABLE_H
#define AUOMS_STRINGTABLE_H

#include <string_view>
#include <vector>
#include <unordered_map>
#include <initializer_list>

template <typename V>
class StringTable {
public:
    explicit StringTable(V unknown_val, std::initializer_list<std::pair<std::string, V>> values): _str(), _itos(), _stoi(values.size()), _unknown_val(unknown_val) {
        int max  = 0;
        int str_size = 0;
        for(auto& e: values) {
            str_size += e.first.size()+1;
            if (max < static_cast<int>(e.second)) {
                max = static_cast<int>(e.second);
            }
        }
        _str.reserve(str_size);
        _itos.resize(max+1);
        for(auto& e: values) {
            auto idx = _str.size();
            _str.append(e.first);
            _str.push_back(0);
            std::string_view sv(&_str[idx], e.first.size());
            // Ignore values where V < 0
            if (static_cast<int>(e.second) >= 0) {
                _itos[static_cast<int>(e.second)] = sv;
                _stoi[sv] = e.second;
            }
        }
    }

    std::string_view ToString(V i) const noexcept {
        if (static_cast<int>(i) < _itos.size()) {
            return _itos[static_cast<int>(i)];
        } else {
            return std::string_view();
        }
    }

    V ToInt(const std::string_view& str) const noexcept {
        auto itr = _stoi.find(str);
        if (itr != _stoi.end()) {
            return itr->second;
        } else {
            return _unknown_val;
        }
    }
private:
    std::string _str;
    std::vector<std::string_view> _itos;
    std::unordered_map<std::string_view, V> _stoi;
    V _unknown_val;
};

#endif //AUOMS_STRINGTABLE_H
