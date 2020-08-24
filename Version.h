/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_VERSION_H
#define AUOMS_VERSION_H

#include <string>
#include <array>

class Version {
public:
    explicit Version(const std::string& str): _str(str), _ver() {
        _ver.fill(-1);
        parse();
    }

    inline std::string str() const { return _str; };

    explicit inline operator bool() const noexcept { return _ver[0] > -1; }

    bool operator==(const Version& other) const;
    bool operator<(const Version& other) const;

    inline bool operator!=(const Version& other) const {
        return !(*this == other);
    }

    inline bool operator>(const Version& other) const {
        return other < *this;
    }

    inline bool operator<=(const Version& other) const {
        return !(other < *this);
    }

    inline bool operator>=(const Version& other) const {
        return !(*this < other);
    }

private:
    void parse() noexcept;

    std::string _str;
    std::array<int, 3> _ver;
};


#endif //AUOMS_VERSION_H
