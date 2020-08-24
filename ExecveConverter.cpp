/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "ExecveConverter.h"

#include "StringUtils.h"

#include <algorithm>
#include <climits>

int sv_to_int(const std::string_view& str, size_t* pos, int base) {
    char* end = nullptr;
    auto i = std::strtol(str.begin(), &end, base);
    if (pos != nullptr) {
        *pos = end - str.begin();
    }
    if (end == str.data() || end > str.end()) {
        return static_cast<int>(LONG_MAX);
    }
    return i;
}

int parse_execve_argnum(const std::string_view& fname) {
    if (fname[0] == 'a' && fname[1] >= '0' && fname[1] <= '9') {
        return sv_to_int(fname.substr(1), nullptr, 10);
    }
    return 0;
}

// Return 0 if "a%d"
// Return 1 if "a%d_len=%d"
// Return 2 if "a%d[%d]"
// Return -1 if error
int parse_execve_fieldname(const std::string_view& fname, const std::string_view& val, int& arg_num, int& arg_len, int& arg_idx) {
    using namespace std::string_view_literals;

    try {
        if (fname[0] == 'a' && fname[1] >= '0' && fname[1] <= '9') {
            auto name = fname.substr(1);
            size_t pos = 0;
            arg_num = sv_to_int(name, &pos, 10);
            if (pos == name.length()) {
                arg_len = 0;
                arg_idx = 0;
                return 0;
            } else if (name[pos] == '_') {
                static auto len_str = "_len"sv;
                if (name.substr(pos) == len_str && val[0] >= '0' && val[0] <= '9') {
                    arg_idx = 0;
                    arg_len = sv_to_int(val, &pos, 10);
                    if (pos == val.size()) {
                        return 1;
                    }
                }
            } else if (name[pos] == '[' && pos < name.size()) {
                name = name.substr(pos + 1);
                arg_len = 0;
                if (name[0] >= '0' && name[0] <= '9') {
                    arg_idx = sv_to_int(name, &pos, 10);
                    if (name[pos] == ']') {
                        return 2;
                    }
                }
            }
        }
    } catch (std::logic_error&) {
        return -1;
    }
    return -1;
}

void ExecveConverter::Convert(std::vector<EventRecord> execve_recs, std::string& cmdline) {
    static auto S_ELIPSIS = std::string("...");
    static auto S_MISSING_ARG_PIECE = std::string("<...>");

    cmdline.resize(0);

    // Sort EXECVE records so that args (e.g. a0, a1, a2 ...) will be in order.
    std::sort(execve_recs.begin(), execve_recs.end(), [](const EventRecord& a, const EventRecord& b) -> int {
        auto fa = a.FieldAt(0);
        auto fb = b.FieldAt(0);
        int a_num = parse_execve_argnum(fa.FieldName());
        int b_num = parse_execve_argnum(fb.FieldName());

        return a_num < b_num;
    });


    int expected_arg_num = 0;
    int expected_arg_len = 0;
    int accum_arg_len = 0;
    int expected_arg_idx = 0;
    for (auto& rec : execve_recs) {
        for (auto &f : rec) {
            auto fname = f.FieldName();
            auto val = f.RawValue();
            int arg_num = 0;
            int arg_len = 0;
            int arg_idx = 0;

            auto atype = parse_execve_fieldname(fname, val, arg_num, arg_len, arg_idx);
            if (atype < 0) {
                continue;
            }

            // Fill in arg gaps with place holder
            if (expected_arg_num < arg_num && expected_arg_len > 0) {
                if (accum_arg_len) {
                    if (!_tmp_val.empty()) {
                        unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
                        bash_escape_string(cmdline, _unescaped_val.data(), _unescaped_val.length());
                    }
                    if (expected_arg_len > accum_arg_len) {
                        cmdline.append(S_MISSING_ARG_PIECE);
                    }
                    expected_arg_num += 1;
                }
                expected_arg_len = 0;
                accum_arg_len = 0;
                expected_arg_idx = 0;
            }

            if (expected_arg_num < arg_num) {
                if (!cmdline.empty()) {
                    cmdline.push_back(' ');
                }
                cmdline.push_back('<');
                cmdline.append(std::to_string(expected_arg_num));
                cmdline.append(S_ELIPSIS);
                cmdline.append(std::to_string(arg_num-1));
                cmdline.push_back('>');
                expected_arg_num = arg_num;
            }

            switch (atype) {
                case 0: // a%d
                    // Previous arg might have been multi-part
                    if (expected_arg_len > 0) {
                        if (!_tmp_val.empty()) {
                            unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
                            bash_escape_string(cmdline, _unescaped_val.data(), _unescaped_val.length());
                        }
                        cmdline.append(S_MISSING_ARG_PIECE);
                        expected_arg_len = 0;
                        expected_arg_idx = 0;
                    }

                    _unescaped_val.resize(0);
                    if (!cmdline.empty()) {
                        cmdline.push_back(' ');
                    }
                    unescape_raw_field(_unescaped_val, val.data(), val.size());
                    bash_escape_string(cmdline, _unescaped_val.data(), _unescaped_val.length());
                    expected_arg_num += 1;
                    break;
                case 1: // a%d_len=%d
                    expected_arg_len = arg_len;
                    accum_arg_len = 0;
                    expected_arg_idx = 0;
                    _tmp_val.resize(0);
                    _unescaped_val.resize(0);
                    break;
                case 2: { // a%d[%d]
                    if (expected_arg_len == 0) {
                        // never saw the corresponding a%d_len=%d field, so just ignore the other parts
                        break;
                    }
                    if (expected_arg_idx == 0 && !cmdline.empty()) {
                        cmdline.push_back(' ');
                    }
                    if (expected_arg_idx < arg_idx) {
                        // There's a gap in the parts, so unescape and bash escape the part we have
                        // then fill in the missing parts with the place holder
                        if (!_tmp_val.empty()) {
                            unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
                            bash_escape_string(cmdline, _unescaped_val.data(), _unescaped_val.length());
                        }
                        cmdline.append(S_MISSING_ARG_PIECE);
                        _tmp_val.resize(0);
                        _unescaped_val.resize(0);
                        expected_arg_idx = arg_idx;
                    }
                    _tmp_val.append(val);
                    accum_arg_len += val.size();
                    expected_arg_idx += 1;
                    if (expected_arg_len <= accum_arg_len) {
                        unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
                        bash_escape_string(cmdline, _unescaped_val.data(), _unescaped_val.length());
                        expected_arg_len = 0;
                        accum_arg_len = 0;
                        expected_arg_idx = 0;
                        expected_arg_num += 1;
                    }
                    break;
                }
            }
        }
    }

    // Last arg might have been a multi-part (a%d_len=%d a%d[%d])
    if (expected_arg_len > 0) {
        if (!_tmp_val.empty()) {
            unescape_raw_field(_unescaped_val, _tmp_val.data(), _tmp_val.size());
            bash_escape_string(cmdline, _unescaped_val.data(), _unescaped_val.length());
        }
        if (expected_arg_len > accum_arg_len) {
            cmdline.append(S_MISSING_ARG_PIECE);
        }
    }
}

void ExecveConverter::ConvertRawCmdline(const std::string_view& raw_cmdline, std::string& cmdline) {
    const char* ptr = reinterpret_cast<const char*>(raw_cmdline.data());
    size_t size = raw_cmdline.size();

    cmdline.resize(0);

    while(size > 0) {
        if (!cmdline.empty()) {
            cmdline.push_back(' ');
        }
        // bash_escape_string will stop at the first NULL byte
        size_t n = bash_escape_string(cmdline, ptr, size);
        size -= n;
        ptr += n;
        // Skip past the NULL byte(s)
        while(size > 0 && *ptr == 0) {
            --size;
            ++ptr;
        }
    }
}
