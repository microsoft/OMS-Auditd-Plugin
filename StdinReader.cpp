/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <cstring>
#include "StdinReader.h"
#include "Logger.h"

ssize_t StdinReader::ReadLine(char* buf, size_t buf_len, long timeout, const std::function<bool()>& fn) {
    while (!have_line()) {
        auto ret = get_data(timeout, fn);
        if (ret != IO::OK) {
            return ret;
        }
    }

    auto str_len = _cur_idx-_start_idx;

    if (str_len > buf_len) {
        Logger::Error("StdinReader::ReadLine: buffer too small for line: Need %ld, buffer only has %ld", str_len, buf_len);
        return IO::FAILED;
    }

    strncpy(buf, &_data[_start_idx], str_len);

    // Skip past any newlines
    while(_cur_idx < _size && _data[_cur_idx] == '\n') {
        _cur_idx++;
    }
    _start_idx = _cur_idx;

    return str_len;
}

bool StdinReader::have_line() {
    if (_cur_idx < _size) {
        if (_data[_cur_idx] == '\n') {
            return true;
        }

        std::string_view _str(_data.data(), _size);
        auto idx = _str.find_first_of('\n', _cur_idx);
        if (idx != std::string_view::npos) {
            _cur_idx = idx;
            return true;
        } else {
            _cur_idx = _size;
        }
    }
    return false;
}

ssize_t StdinReader::get_data(long timeout, const std::function<bool()>& fn) {
    if (_size == _data.size()) {
        if (_start_idx > 0) {
            memmove(&_data[0], &_data[_start_idx], _size - _start_idx);
            _cur_idx -= _start_idx;
            _size -= _start_idx;
            _start_idx = 0;
        } else {
            Logger::Error("Buffer limit reached before newline found in input");
            return IO::FAILED;
        }
    }
    auto ret = Read(&_data[_size], _data.size() - _size, timeout, fn);
    if (ret <= 0) {
        return ret;
    }
    _size += ret;
    return IO::OK;
}
