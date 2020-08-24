/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Version.h"

#include "StringUtils.h"

bool Version::operator==(const Version& other) const {
    for (int i = 0; i < _ver.size(); ++i) {
        if (_ver[i] != other._ver[i]) {
            return false;
        }
    }
    return true;
}

bool Version::operator<(const Version& other) const {
    for (int i = 0; i < _ver.size(); ++i) {
        if (_ver[i] != other._ver[i]) {
            return _ver[i] < other._ver[i];
        }
    }
    return false;
}

void Version::parse() noexcept {
    auto parts = split(_str, ".-_");
    if (parts.empty()) {
        return;
    }

    for (int i = 0; i < parts.size(); ++i) {
        try {
            _ver[i] = stoi(parts[0]);
        } catch (std::exception&) {
            _ver[i] = -1;
        }
    }

    if (_ver[0] != -1) {
        for (int i = 1; i < _ver.size(); ++i) {
            if (_ver[i] == -1) {
                _ver[i] = 0;
            }
        }
    }
}
