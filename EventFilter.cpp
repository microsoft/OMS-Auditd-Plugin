/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "EventFilter.h"
#include "RecordType.h"
#include "Logger.h"

std::shared_ptr<IEventFilter> EventFilter::NewEventFilter(const std::string& name, const Config& config, std::shared_ptr<UserDB> user_db, std::shared_ptr<FiltersEngine> filtersEngine, std::shared_ptr<ProcessTree> processTree) {
    std::bitset<FILTER_BITSET_SIZE> filterFlagsMask;

    // Load filter rules.
    auto proc_filter = std::make_shared<ProcFilter>(user_db);

    if (!proc_filter->ParseConfig(config)) {
        Logger::Error("Invalid 'process_filters' value");
        return nullptr;
    }

    filterFlagsMask = filtersEngine->AddFilterList(proc_filter->_filters, name);
    processTree->UpdateFlags();

    return std::shared_ptr<IEventFilter>(static_cast<IEventFilter*>(new EventFilter(name, filterFlagsMask, proc_filter, filtersEngine, processTree)));
}

EventFilter::~EventFilter() {
    _filtersEngine->RemoveFilterList(_proc_filter->_filters, _name);
    _processTree->UpdateFlags();
}

bool EventFilter::IsEventFiltered(const Event& event) {
    static std::string S_SYSCALL = "syscall";

    bool filtered = false;
    // Get event syscall
    std::string syscall;

    for (auto rec : event) {
        if (RecordTypeHasSyscallField(static_cast<RecordType>(rec.RecordType()))) {
            auto field = rec.FieldByName(S_SYSCALL);
            if (field) {
                syscall = field.InterpValue();
                break;
            }
        }
    }

    std::shared_ptr<ProcessTreeItem> p = nullptr;

    if (!syscall.empty()) {
        p = _processTree->GetInfoForPid(event.Pid());
    }

    return !syscall.empty() && _filtersEngine->IsEventFiltered(syscall, p, _filterFlagsMask);
}
