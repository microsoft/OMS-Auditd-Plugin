/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_EVENTFILTER_H
#define AUOMS_EVENTFILTER_H

#include "IEventFilter.h"
#include "Config.h"
#include "UserDB.h"
#include "ProcFilter.h"
#include "FiltersEngine.h"
#include "ProcessTree.h"

class AllPassEventFilter: public IEventFilter {
public:
    static std::shared_ptr<IEventFilter> NewEventFilter() {
        return std::shared_ptr<IEventFilter>(static_cast<IEventFilter*>(new AllPassEventFilter()));
    }

    bool IsEventFiltered(const Event& event) override {
        return false;
    }
};

class EventFilter: public IEventFilter {
public:
    virtual ~EventFilter();
    static std::shared_ptr<IEventFilter> NewEventFilter(const std::string& name, const Config& config, std::shared_ptr<UserDB> user_db, std::shared_ptr<FiltersEngine> filtersEngine, std::shared_ptr<ProcessTree> processTree);

    bool IsEventFiltered(const Event& event) override;
private:
    EventFilter(const std::string& name, const std::bitset<FILTER_BITSET_SIZE>& filterFlagsMask, const std::shared_ptr<ProcFilter>& proc_filter, std::shared_ptr<FiltersEngine> filtersEngine, std::shared_ptr<ProcessTree> processTree):
            _name(name), _filterFlagsMask(filterFlagsMask), _proc_filter(proc_filter), _filtersEngine(filtersEngine), _processTree(processTree)
    {}

    std::string _name;
    std::bitset<FILTER_BITSET_SIZE> _filterFlagsMask;

    std::shared_ptr<ProcFilter> _proc_filter;
    std::shared_ptr<FiltersEngine> _filtersEngine;
    std::shared_ptr<ProcessTree> _processTree;
};


#endif //AUOMS_EVENTFILTER_H
