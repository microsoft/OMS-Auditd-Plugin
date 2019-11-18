/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_EVENTID_H
#define AUOMS_EVENTID_H

#include <cstdint>

class EventId {
public:
    EventId(uint64_t sec, uint32_t msec, uint64_t serial): _sec(sec), _msec(msec), _serial(serial)
    {}

    EventId(): _sec(0), _msec(0), _serial(0)
    {}

    EventId(const EventId&) = default;
    EventId& operator=(const EventId&) = default;

    inline uint64_t Seconds() const { return _sec; }
    inline uint32_t Milliseconds() const { return _msec; }
    inline uint64_t Serial() const { return _serial; }

    operator bool() const {
        return (_sec == 0 && _msec == 0 && _serial == 0);
    }

    bool operator==(const EventId& other) const {
        return _sec == other._sec && _msec == other._msec && _serial == other._serial;
    }

    bool operator!=(const EventId& other) const { return !(*this == other); }

    bool operator<(const EventId& other) const {
        if (_sec < other._sec) {
            return true;
        } else if (_sec > other._sec) {
            return false;
        } else {
            if (_msec < other._msec) {
                return true;
            } else if (_msec > other._msec) {
                return false;
            } else {
                return _serial < other._serial;
            }
        }
    }

    bool operator>(const EventId& other) const {
        if (_sec > other._sec) {
            return true;
        } else if (_sec < other._sec) {
            return false;
        } else {
            if (_msec > other._msec) {
                return true;
            } else if (_msec < other._msec) {
                return false;
            } else {
                return _serial > other._serial;
            }
        }
    }

    bool operator<=(const EventId& other) const {
        if (*this == other) {
            return true;
        } else {
            return *this < other;
        }
    }

    bool operator>=(const EventId& other) const {
        if (*this == other) {
            return true;
        } else {
            return *this > other;
        }
    }

private:
    uint64_t _sec;
    uint32_t _msec;
    uint64_t _serial;
};

namespace std
{
    template<> struct hash<EventId>
    {
        typedef EventId argument_type;
        typedef std::size_t result_type;
        result_type operator()(argument_type const& id) const noexcept
        {
            result_type const h1 ( std::hash<uint64_t>{}(id.Seconds()) );
            result_type const h2 ( std::hash<uint64_t>{}(id.Serial()) );
            result_type const h3 ( std::hash<uint32_t>{}(id.Milliseconds()) );
            return h1 ^ ((h2 ^ (h3 << 1)) << 1);
        }
    };
}

#endif //AUOMS_EVENTID_H
