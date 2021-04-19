/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "FiltersEngine.h"

#include "Logger.h"
#include "StringUtils.h"

#include <string>
#include <iostream>
#include <fstream>
#include <sys/stat.h> /* for stat() */
#include <dirent.h>
#include <algorithm>
#include <unistd.h>
#include <limits.h>

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::AddFilter(const ProcFilterSpec& pfs, const std::string& outputName)
{
    std::bitset<FILTER_BITSET_SIZE> ret;

    auto it = _filtersBitPosition.find(pfs);
    if (it != _filtersBitPosition.end()) {
        struct FiltersInfo& info = it->second;
        ret[info.bitPosition] = 1;
        if (info.outputs.count(outputName) == 0) {
            info.outputs.emplace(outputName);
        }
    } else {
        struct FiltersInfo info;
        info.bitPosition = _nextBitPosition;
        info.outputs.emplace(outputName);
        _filtersBitPosition[pfs] = info;
        ret[_nextBitPosition] = 1;

        // Insert the syscalls *in order* into an unordered_map that maps each one to a bool.
        // A true value indicates an exclusion syscall (no !) and a false value indicates an
        // inclusion syscall (!syscall).  If the syscall is already in the unordered_map then
        // ignore the repetitions; e.g. take the first value for each syscall only.
        std::unordered_map<std::string, bool>& syscalls = _bitPositionSyscalls[_nextBitPosition];
        for (auto s : pfs._syscalls) {
            if (s[0] != '!') {
                if (syscalls.count(s) == 0) {
                    syscalls[s] = true;
                }
            } else {
                if (syscalls.count(s.substr(1)) == 0) {
                    syscalls[s] = false;
                }
            }
        }
        _nextBitPosition++;
    }

    if (_outputs.count(outputName) == 0) {
        _outputs.insert(outputName);
    }

    return ret;
}

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::AddFilterList(const std::vector<ProcFilterSpec>& pfsVec, const std::string& outputName)
{
    std::bitset<FILTER_BITSET_SIZE> ret;

    for (auto pfs : pfsVec) {
        ret |= AddFilter(pfs, outputName);
    }

    SetCommonFlagsMask();

    return ret;
}

void FiltersEngine::RemoveFilter(const ProcFilterSpec& pfs, const std::string& outputName)
{
    // check that the filter exists
    auto it = _filtersBitPosition.find(pfs);
    if (it == _filtersBitPosition.end()) {
        return;
    }

    // check that the filter constains this output
    struct FiltersInfo& info = it->second;
    if ((info.outputs.count(outputName) == 0) && (info.outputs.size() > 0)) {
        return;
    }

    if (info.outputs.size() <= 1) {
        // outputs is either empty or only contains this output
        _bitPositionSyscalls.erase(info.bitPosition);
        _filtersBitPosition.erase(pfs);
    } else {
        // outputs contains this output and others
        info.outputs.erase(outputName);
    }
}

void FiltersEngine::RemoveFilterList(const std::vector<ProcFilterSpec>& pfsVec, const std::string& outputName)
{
    for (auto pfs : pfsVec) {
        RemoveFilter(pfs, outputName);
    }

    _outputs.erase(outputName);
    SetCommonFlagsMask();
}

bool FiltersEngine::ProcessMatchFilter(const std::shared_ptr<ProcessTreeItem>& process, const ProcFilterSpec& pfs, unsigned int height)
{
    if (pfs._depth != -1 && pfs._depth < height) {
        return false;
    }

    if (pfs._match_mask & PFS_MATCH_UID) {
        if (pfs._uid != process->uid()) {
            return false;
        }
    }

    if (pfs._match_mask & PFS_MATCH_GID) {
        if (pfs._gid != process->gid()) {
            return false;
        }
    }

    auto exe = process->exe();

    if (pfs._match_mask & PFS_MATCH_EXE_EQUALS) {
        if (pfs._exeMatchValue != exe) {
            return false;
        }
    }

    if (pfs._match_mask & PFS_MATCH_EXE_STARTSWITH) {
        if (!starts_with(exe, pfs._exeMatchValue)) {
            return false;
        }
    }

    if (pfs._match_mask & PFS_MATCH_EXE_CONTAINS) {
        if (exe.find(pfs._exeMatchValue) == std::string::npos) {
            return false;
        }
    }
    if (pfs._match_mask & PFS_MATCH_EXE_REGEX) {
        if (!re2::RE2::PartialMatch(exe, *pfs._exeRegex)) {
            return false;
        }
    }

    auto cmdline = process->cmdline();

    for (auto cf : pfs._cmdlineFilters) {
        if (cf._matchType == MatchEquals) {
            if (cf._matchValue != cmdline) {
                return false;
            }
        } else if (cf._matchType == MatchStartsWith) {
            if (!starts_with(cmdline, cf._matchValue)) {
                return false;
            }
        } else if (cf._matchType == MatchContains) {
            if (cmdline.find(cf._matchValue) == std::string::npos) {
                return false;
            }
        } else if (cf._matchType == MatchRegex) {
            if (!re2::RE2::PartialMatch(cmdline, *cf._matchRegex)) {
                return false;
            }
        }
    }

    return true;
}

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::GetFlags(const std::shared_ptr<ProcessTreeItem>& process, unsigned int height)
{
    std::bitset<FILTER_BITSET_SIZE> flags;

    for (auto element : _filtersBitPosition) {
        ProcFilterSpec pfs = element.first;
        if (ProcessMatchFilter(process, pfs, height)) {
            flags[element.second.bitPosition] = 1;
        }
    }

    return flags;
}

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::GetCommonFlagsMask()
{
    return _globalFlagsMask;
}

void FiltersEngine::SetCommonFlagsMask()
{
    std::bitset<FILTER_BITSET_SIZE> flags;
    unsigned int numberOfOutputs = _outputs.size();

    for (auto element : _filtersBitPosition) {
        if (element.second.outputs.size() == numberOfOutputs) {
            flags[element.second.bitPosition] = 1;
        }
    }

    _globalFlagsMask = flags;
}

bool FiltersEngine::syscallIsFiltered(const std::string& syscall, const std::unordered_map<std::string, bool>& syscalls)
{
    auto it = syscalls.find(syscall);
    if (it != syscalls.end()) {
        return it->second;
    } else {
        if (syscalls.count("*") > 0) {
            return true;
        }
    }
    return false;
}

bool FiltersEngine::IsEventFiltered(const std::string& syscall, const std::shared_ptr<ProcessTreeItem>& p, const std::bitset<FILTER_BITSET_SIZE>& filterFlagsMask)
{
    // Get event syscall
    bool filtered = false;

    if (syscall.empty() || !p) {
        return false;
    }

    // Check if this process is filtered
    std::bitset<FILTER_BITSET_SIZE> matched_flags = p->flags() & filterFlagsMask;

    // Find syscalls filtered for process
    for (unsigned int i=0; i<_nextBitPosition; i++) {
        if (matched_flags[i]) {
            std::unordered_map<std::string, bool>& syscalls = _bitPositionSyscalls[i];
            if (syscallIsFiltered(syscall, syscalls)) {
                filtered = true;
                break;
            }
        }
    }

    return filtered;
}


