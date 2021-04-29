/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "StringUtils.h"
#include <cstring>

static const int s_hex2int[256] {
        // 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 1F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 2F
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 3F
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 4F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 5F
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 6F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 7F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 8F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 9F
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // AF
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // BF
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // CF
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // DF
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // EF
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // FF
};

// Return -1 if string was not hex
// Return 0 if string was hex and was decoded
// Return 1 if decoded string needs escaping
int decode_hex(std::string& out, const char* hex, size_t len)
{
    if (len % 2 != 0) {
        // Not hex like we expected, just output the raw value
        out.assign(hex, len);
        return -1;
    }
    if (out.capacity() < len*2) {
        out.reserve(len*2);
    }
    out.resize(0);

    bool needs_escaping = false;
    auto p = hex;
    auto endp = hex+len;
    while (p != endp) {
        int i1 = s_hex2int[static_cast<uint8_t>(*p)];
        ++p;
        int i2 = s_hex2int[static_cast<uint8_t>(*p)];
        ++p;
        if (i1 < 0 || i2 < 0) {
            // Not hex like we expected, just output the raw value
            out.assign(hex, len);
            return -1;
        }
        char c = static_cast<char>(i1 << 4 | i2);
        out.push_back(c);
        needs_escaping |= (c < 0x20 || c > 0x7E);
    }
    return needs_escaping ? 1 : 0;
}

size_t decode_hex(void* buf, size_t buf_len, const char* hex, size_t len) {
    size_t size = 0;
    if (len % 2 != 0) {
        return 0;
    }
    if (buf_len*2 < len) {
        return 0;
    }

    uint8_t* out = reinterpret_cast<uint8_t*>(buf);
    auto p = hex;
    auto endp = hex+len;
    while (p != endp) {
        int i1 = s_hex2int[static_cast<uint8_t>(*p)];
        ++p;
        int i2 = s_hex2int[static_cast<uint8_t>(*p)];
        ++p;
        if (i1 < 0 || i2 < 0) {
            return 0;
        }
        uint8_t c = static_cast<uint8_t>(i1 << 4 | i2);
        *out = c;
        ++out;
        ++size;
    }
    return size;
}

// Return -1 if string was NULL, empty or copied as is
// Return 0 if string was "(null)"
// Return 1 if string was double quoted
// Return 2 if string was hex decoded
// Return 3 if string was hex decoded and decoded string has chars that might need escaping
int unescape_raw_field(std::string& out, const char* in, size_t in_len) {
    out.clear();
    if (in == nullptr || *in == 0) {
        return -1;
    }
    if (*in == '"') {
        if (in_len >= 2 && in[in_len-1] == '"') {
            out.assign(&in[1], in_len-2);
            return 1;
        } else {
            out.assign(in, in_len);
            return -1;
        }
    } else if (*in == '(') {
        out.assign(in, in_len);
        if (in[in_len-1] == ')') {
            return 0;
        } else {
            return -1;
        }
    } else {
        switch (decode_hex(out, in, in_len)) {
            default:
                return -1;
            case 0:
                return 2;
            case 1:
                return 3;
        }
    }
}

const char int2hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void tty_escape_string(std::string& out, const char* in, size_t in_len) {
    out.clear();
    tty_escape_string_append(out, in, in_len);
}

void tty_escape_string_append(std::string& out, const char* in, size_t in_len) {
    auto ptr = in;
    auto end = ptr+in_len;
    for (; ptr < end; ++ptr) {
        if (*ptr < 0x20 || *ptr > 0x7E) {
            out.push_back('\\');
            out.push_back('x');
            out.push_back(int2hex[static_cast<uint8_t>(*ptr) >> 4]);
            out.push_back(int2hex[*ptr & 0xF]);
        } else {
            out.push_back(*ptr);
        }
    }
}

void json_escape_string(std::string& out, const char* in, size_t in_len) {
    out.clear();
    auto ptr = in;
    auto end = ptr+in_len;
    for (; ptr < end; ++ptr) {
        if (*ptr < 0x20 || *ptr > 0x7E) {
            out.push_back('\\');
            out.push_back('x');
            out.push_back(int2hex[static_cast<uint8_t>(*ptr) >> 4]);
            out.push_back(int2hex[*ptr & 0xF]);
        } else if (*ptr == '"') {
            out.push_back('\\');
            out.push_back('"');
        } else {
            out.push_back(*ptr);
        }
    }
}

// Codes:
/*
 * Z -> null terminator
 * * -> Pass through
 * q -> Requires quoting
 * s -> Requires single quoting
 * - -> Requires bash quoting
 * e -> Requires escaping
 * S -> Has single quote
 *
 * 0x20 Space -> q
 * 0x21 ! -> s
 * 0x22 " -> e
 * 0x24 $ -> e
 * 0x26 & -> q
 * 0x27 ' -> S
 * 0x28 ( -> q
 * 0x29 ) -> q
 * 0x5C ~ -> e
 * 0x60 ` -> e
 * 0x7C | -> q
 */
const char* char_category_codes =
                "Z---------------"  // 0x00 - 0x0F
                "----------------"  // 0x10 - 0x1F
                "qse*e*qSqq******"  // 0x20 - 0x2F
                "***********qq*q*"  // 0x30 - 0x3F
                "****************"  // 0x40 - 0x4F
                "************e***"  // 0x50 - 0x5F
                "e***************"  // 0x60 - 0x6F
                "************q**-"  // 0x70 - 0x7F
                "----------------"  // 0x80 - 0x8F
                "----------------"  // 0x90 - 0x9F
                "----------------"  // 0xA0 - 0xAF
                "----------------"  // 0xB0 - 0xBF
                "----------------"  // 0xC0 - 0xCF
                "----------------"  // 0xD0 - 0xDF
                "----------------"  // 0xE0 - 0xEF
                "----------------"; // 0xF0 - 0xFF

const char* bare_escape_codes =
                "Z---------------"  // 0x00 - 0x0F
                "----------------"  // 0x10 - 0x1F
                "**\"*$**'********" // 0x20 - 0x2F
                "****************"  // 0x30 - 0x3F
                "****************"  // 0x40 - 0x4F
                "************\\***" // 0x50 - 0x5F
                "`***************"  // 0x60 - 0x6F
                "***************-"  // 0x70 - 0x7F
                "----------------"  // 0x80 - 0x8F
                "----------------"  // 0x90 - 0x9F
                "----------------"  // 0xA0 - 0xAF
                "----------------"  // 0xB0 - 0xBF
                "----------------"  // 0xC0 - 0xCF
                "----------------"  // 0xD0 - 0xDF
                "----------------"  // 0xE0 - 0xEF
                "----------------"; // 0xF0 - 0xFF

const char* quote_escape_codes =
                "Z---------------"  // 0x00 - 0x0F
                "----------------"  // 0x10 - 0x1F
                "**\"*$***********" // 0x20 - 0x2F
                "****************"  // 0x30 - 0x3F
                "****************"  // 0x40 - 0x4F
                "************\\***" // 0x50 - 0x5F
                "`***************"  // 0x60 - 0x6F
                "***************-"  // 0x70 - 0x7F
                "----------------"  // 0x80 - 0x8F
                "----------------"  // 0x90 - 0x9F
                "----------------"  // 0xA0 - 0xAF
                "----------------"  // 0xB0 - 0xBF
                "----------------"  // 0xC0 - 0xCF
                "----------------"  // 0xD0 - 0xDF
                "----------------"  // 0xE0 - 0xEF
                "----------------"; // 0xF0 - 0xFF

// code meanings:
//      'Z' - NULL end of string
//      '-' - Character needs to be \xNN escaped
//      '*' - Character doesn't need escaping or quoting.
//      other - Character must be escaped

const char* bash_escape_codes =
                "Z------abtnvfr--"  // 0x00 - 0x0F
                "-----------e----"  // 0x10 - 0x1F
                "*******'********"  // 0x20 - 0x2F
                "****************"  // 0x30 - 0x3F
                "****************"  // 0x40 - 0x4F
                "****************"  // 0x50 - 0x5F
                "****************"  // 0x60 - 0x6F
                "***************-"  // 0x70 - 0x7F
                "----------------"  // 0x80 - 0x8F
                "----------------"  // 0x90 - 0x9F
                "----------------"  // 0xA0 - 0xAF
                "----------------"  // 0xB0 - 0xBF
                "----------------"  // 0xC0 - 0xCF
                "----------------"  // 0xD0 - 0xDF
                "----------------"  // 0xE0 - 0xEF
                "----------------"; // 0xF0 - 0xFF

#define __ESCAPE_NEEDED 1
#define __QUOTE_NEEDED 2
#define __SINGLE_QUOTE_NEEDED 4
#define __BASH_QUOTE_NEEDED 8
#define __HAS_SINGLE_QUOTE 16

/*
 * Find the first null terminated string less than in_len in length and
 * append and escaped version to out.
 * The escaping is done in such a way that if the escaped string where pasted
 * on the bash command line the argument as seen by the executed process
 * would look identical to what was originally found in the input string.
 *
 * The special $'' bash quoting form is used if any of the input chars are < 0x20 or > 0x7E or if the input contains
 * both bash metacharacters ('|', '&', ';' '(', ')', '<', '>', ' ') and the '!' character.
 * Single quoting is used if the input contains a '!'.
 * Double quoting is used if there are any bash meta characters in the input
 */
size_t bash_escape_string(std::string& out, const char* in, size_t in_len) {
    int flags = 0;
    size_t size = 0;
    const char *ptr = in;
    const char* end = in+in_len;
    for(; ptr < end; ++ptr, ++size) {
        switch (char_category_codes[static_cast<uint8_t>(*ptr)]) {
            case 'Z':
                end = ptr;
                size -= 1;
                break;
            case '-':
                flags |= __BASH_QUOTE_NEEDED;
                break;
            case 'q':
                flags |= __QUOTE_NEEDED;
                break;
            case 's':
                flags |= __SINGLE_QUOTE_NEEDED;
                break;
            case 'e':
                flags |= __ESCAPE_NEEDED;
                break;
            case 'S':
                flags |= __HAS_SINGLE_QUOTE;
                break;
        }
    }

    // String is empty, use '' to represent empty string on bash commandline
    if (size == 0) {
        out.append("''");
        return 0;
    }

    // There are no flags, so string doesn't need any bash quoting/escaping
    if (flags == 0) {
        out.append(in, size);
        return size;
    }

    // If bash quoting isn't required and single quoting is required, check to see if the string has a single quote
    // if it does, switch to bash quoting instead.
    if ((flags & __SINGLE_QUOTE_NEEDED) != 0 && (flags & __BASH_QUOTE_NEEDED) == 0) {
        if ((flags & __HAS_SINGLE_QUOTE) != 0) {
            flags |= __BASH_QUOTE_NEEDED;
        } else {
            out.push_back('\'');
            out.append(in, size);
            out.push_back('\'');
            return size;
        }
    }

    const char* escape_codes = bare_escape_codes;

    if ((flags & __BASH_QUOTE_NEEDED) != 0) {
        escape_codes = bash_escape_codes;
        out.append("$'");
    } else if ((flags & __QUOTE_NEEDED) != 0) {
        escape_codes = quote_escape_codes;
        out.push_back('"');
    }

    ptr = in;
    end = in+size;
    for(; ptr < end; ++ptr) {
        switch (escape_codes[static_cast<uint8_t>(*ptr)]) {
            case '-':
                out.push_back('\\');
                out.push_back('x');
                out.push_back(int2hex[static_cast<uint8_t>(*ptr) >> 4]);
                out.push_back(int2hex[*ptr & 0xF]);
                break;
            case '*':
                out.push_back(*ptr);
                break;
            default:
                out.push_back('\\');
                out.push_back(escape_codes[static_cast<uint8_t>(*ptr)]);
                break;
        }
    }

    if ((flags & __BASH_QUOTE_NEEDED) != 0) {
        out.push_back('\'');
    } else if ((flags & __QUOTE_NEEDED) != 0) {
        out.push_back('"');
    }

    return size;
}

std::string trim_whitespace(const std::string& str) {
    size_t idx = 0;
    while(idx < str.size() && std::isspace(str[idx])) {
        idx += 1;
    }
    if (idx >= str.size()) {
        return std::string();
    }

    auto eidx = str.size()-1;
    while(eidx > 0 && std::isspace(str[eidx])) {
        eidx -= 1;
    }
    eidx += 1;
    return str.substr(idx, eidx-idx);
}

std::vector<std::string> split(const std::string& str, const std::string& sep) {
    std::vector<std::string> parts;

    size_t idx = 0;

    do {
        auto eidx = str.find_first_of(sep, idx);
        if (eidx == std::string::npos) {
            parts.emplace_back(str.substr(idx));
            return parts;
        }
        parts.emplace_back(str.substr(idx, eidx-idx));
        idx = str.find_first_not_of(sep, eidx);
    } while (idx < str.size());

    return parts;
}

std::string join(const std::vector<std::string>& vec, const std::string& sep) {
    std::string str;

    for (auto& part : vec) {
        if (!str.empty()) {
            str.append(sep);
        }
        str.append(part);
    }
    return str;
}
