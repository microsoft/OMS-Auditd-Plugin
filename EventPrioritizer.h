/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_EVENTPRIORITIZER_H
#define AUOMS_EVENTPRIORITIZER_H

#include "Event.h"
#include "Config.h"
#include "RecordType.h"

#include <unordered_map>

class EventPrioritizer: public IEventPrioritizer {
public:
    explicit EventPrioritizer(uint16_t default_priority): _default_priority(default_priority)  {}

    bool LoadFromConfig(Config& config);

    uint16_t Prioritize(const Event& event) override;

private:
    uint16_t _default_priority;
    std::unordered_map<RecordType, uint16_t> _record_type_priorities;
    std::unordered_map<RecordTypeCategory, uint16_t> _record_type_category_priorities;
    std::unordered_map<std::string, uint16_t> _syscall_priorities;
    std::string _syscall_name;
};


#endif //AUOMS_EVENTPRIORITIZER_H
