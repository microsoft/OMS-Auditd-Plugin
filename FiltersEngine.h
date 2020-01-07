/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_FILTERS_ENGINE_H
#define AUOMS_FILTERS_ENGINE_H

#include <string>
#include <memory>
#include <set>
#include <unordered_set>
#include <list>
#include <unordered_map>
#include <queue>
#include <regex>
#include "Config.h"
#include "UserDB.h"
#include "ProcessInfo.h"
#include "ProcFilter.h"
#include "ProcessTree.h"
#include "ProcessDefines.h"


struct FiltersInfo {
    unsigned int bitPosition;
    std::unordered_set<std::string> outputs;
};

class ProcessTreeItem;

class FiltersEngine {
public:
    FiltersEngine(): _nextBitPosition(0) {}
    std::bitset<FILTER_BITSET_SIZE> AddFilterList(const std::vector<ProcFilterSpec>& pfsVec, const std::string& outputName);
    void RemoveFilterList(const std::vector<ProcFilterSpec>& pfsVec, const std::string& outputName);
    std::bitset<FILTER_BITSET_SIZE> GetFlags(const std::shared_ptr<ProcessTreeItem>& process, unsigned int height);
    std::bitset<FILTER_BITSET_SIZE> GetCommonFlagsMask();
    bool IsEventFiltered(const std::string& syscall, const std::shared_ptr<ProcessTreeItem>& p, const std::bitset<FILTER_BITSET_SIZE>& filterFlagsMask);

private:
    std::bitset<FILTER_BITSET_SIZE> AddFilter(const ProcFilterSpec& pfs, const std::string& outputName);
    void RemoveFilter(const ProcFilterSpec& pfs, const std::string& outputName);
    void SetCommonFlagsMask();
    bool ProcessMatchFilter(const std::shared_ptr<ProcessTreeItem>& process, const ProcFilterSpec& pfs, unsigned int height);
    bool syscallIsFiltered(const std::string& syscall, const std::unordered_map<std::string, bool>& syscalls);

    unsigned int _nextBitPosition;
    std::bitset<FILTER_BITSET_SIZE> _globalFlagsMask;
    std::unordered_set<std::string> _outputs;
    std::unordered_map<ProcFilterSpec, FiltersInfo, ProcFilterSpecHash, ProcFilterSpecCompare> _filtersBitPosition;
    std::unordered_map<unsigned int, std::unordered_map<std::string, bool>> _bitPositionSyscalls;
};

#endif //AUOMS_FILTERS_ENGINE_H
