/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_STRINGUTILS_H
#define AUOMS_STRINGUTILS_H

#include <string>
#include <vector>
#include <algorithm>
#include <type_traits>
#include <cstdint>

int decode_hex(std::string& out, const char* hex, size_t len);

size_t decode_hex(void* buf, size_t buf_len, const char* hex, size_t len);

int unescape_raw_field(std::string& out, const char* in, size_t in_len);

// Escape non ASCII non-printable chars (< 0x20 && > 0x7E)
void tty_escape_string(std::string& out, const char* in, size_t in_len);
void tty_escape_string_append(std::string& out, const char* in, size_t in_len);

// Same as tty_escape_string, but also escape double quote
void json_escape_string(std::string& out, const char* in, size_t in_len);

size_t bash_escape_string(std::string& out, const char* in, size_t in_len);

void append_hex(std::string& out, uint32_t val);

template <typename Int>
void append_int(std::string& out, Int i) {
    if (std::is_signed<Int>::value) {
        if (i < 0) {
            out.push_back('-');
            i = -i;
        }
    }
    auto start_idx = out.end() - out.begin();
    do {
        out.push_back((i % 10)+'0');
        i /= 10;
    } while (i > 0);
    std::reverse(out.begin()+start_idx, out.end());
}

template <typename Int>
void append_uint(std::string& out, Int i) {
    auto u = static_cast<typename std::make_unsigned<Int>::type>(i);
    auto start_idx = out.end() - out.begin();
    do {
        out.push_back((u % 10)+'0');
        u /= 10;
    } while (u > 0);
    std::reverse(out.begin()+start_idx, out.end());
}

inline bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

inline bool starts_with(const std::string_view& str, const std::string_view& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size()-suffix.size(), suffix.size(), suffix) == 0;
}

inline bool ends_with(const std::string_view& str, const std::string_view& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size()-suffix.size(), suffix.size(), suffix) == 0;
}

std::string trim_whitespace(const std::string& str);

std::vector<std::string> split(const std::string& str, const std::string& sep);

inline std::vector<std::string> split(const std::string& str, char sep) {
    return split(str, std::string(&sep, 1));
}

std::string join(const std::vector<std::string>& vec, const std::string& sep);

#endif //AUOMS_STRINGUTILS_H
