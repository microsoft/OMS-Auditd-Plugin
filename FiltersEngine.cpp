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

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::AddFilter(ProcFilterSpec& pfs, std::string& outputName)
{
    std::bitset<FILTER_BITSET_SIZE> ret;

    if (_filtersBitPosition.count(pfs) > 0) {
        struct FiltersInfo info = _filtersBitPosition[pfs];
        ret[info.bitPosition] = 1;
        if (info.outputs.count(outputName) == 0) {
            info.outputs.emplace(outputName);
            _filtersBitPosition[pfs] = info;
        }
    } else {
        struct FiltersInfo info;
        info.bitPosition = _nextBitPosition;
        info.outputs.emplace(outputName);
        _filtersBitPosition[pfs] = info;
        ret[_nextBitPosition] = 1;
        _bitPositionSyscalls[_nextBitPosition] = pfs._syscalls;
        _nextBitPosition++;
    }

    if (_outputs.count(outputName) == 0) {
        _outputs.insert(outputName);
    }

    return ret;
}

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::AddFilterList(std::vector<ProcFilterSpec>& pfsVec, std::string& outputName)
{
    std::bitset<FILTER_BITSET_SIZE> ret;

    for (auto pfs : pfsVec) {
        ret |= AddFilter(pfs, outputName);
    }

    return ret;
}

bool FiltersEngine::ProcessMatchFilter(std::shared_ptr<ProcessTreeItem> process, ProcFilterSpec& pfs, unsigned int height)
{
    if (pfs._depth != -1 && pfs._depth < height) {
        return false;
    }

    if (pfs._match_mask & PFS_MATCH_UID) {
        if (pfs._uid != process->_uid) {
            return false;
        }
    }

    if (pfs._match_mask & PFS_MATCH_GID) {
        if (pfs._gid != process->_gid) {
            return false;
        }
    }

    if (pfs._match_mask & PFS_MATCH_EXE_EQUALS) {
        if (pfs._exeMatchValue != process->_exe) {
            return false;
        }
    }

    if (pfs._match_mask & PFS_MATCH_EXE_STARTSWITH) {
        if (!starts_with(process->_exe, pfs._exeMatchValue)) {
            return false;
        }
    }

    if (pfs._match_mask & PFS_MATCH_EXE_CONTAINS) {
        if (process->_exe.find(pfs._exeMatchValue) == std::string::npos) {
            return false;
        }
    }
    if (pfs._match_mask & PFS_MATCH_EXE_REGEX) {
        if (!std::regex_search(process->_exe, pfs._exeRegex)) {
            return false;
        }
    }

    for (auto cf : pfs._cmdlineFilters) {
        if (cf._matchType == MatchEquals) {
            if (cf._matchValue != process->_cmdline) {
                return false;
            }
        } else if (cf._matchType == MatchStartsWith) {
            if (!starts_with(process->_cmdline, cf._matchValue)) {
                return false;
            }
        } else if (cf._matchType == MatchContains) {
            if (process->_cmdline.find(cf._matchValue) == std::string::npos) {
                return false;
            }
        } else if (cf._matchType == MatchRegex) {
            if (!std::regex_search(process->_cmdline, cf._matchRegex)) {
                return false;
            }
        }
    }

    return true;
}

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::GetFlags(std::shared_ptr<ProcessTreeItem> process, unsigned int height)
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

std::bitset<FILTER_BITSET_SIZE> FiltersEngine::GetCommonFlagMask()
{
    std::bitset<FILTER_BITSET_SIZE> flags;
    unsigned int numberOfOutputs = _outputs.size();

    for (auto element : _filtersBitPosition) {
        if (element.second.outputs.size() == numberOfOutputs) {
            flags[element.second.bitPosition] = 1;
        }
    }

    return flags;
}

bool FiltersEngine::syscallIsFiltered(std::string& syscall, std::vector<std::string>& syscalls)
{
    for (auto s : syscalls) {
        if (s == "*") {
            return true;
        } else if (s == syscall) {
            return true;
        } else if (s == "!" + syscall) {
            return false;
        }
    }
    return false;
}


bool FiltersEngine::IsEventFiltered(std::string& syscall, std::shared_ptr<ProcessTreeItem> p, std::bitset<FILTER_BITSET_SIZE>& filterFlagsMask)
{
    // Get event syscall
    bool filtered = false;

    if (syscall.empty() || !p) {
        return false;
    }

    // Check if this process is filtered
    std::bitset<FILTER_BITSET_SIZE> matched_flags = p->_flags & filterFlagsMask;

    // Find syscalls filtered for process
    for (unsigned int i=0; i<_nextBitPosition; i++) {
        if (matched_flags[i]) {
            std::vector<std::string>& syscalls = _bitPositionSyscalls[i];
            if (syscallIsFiltered(syscall, syscalls)) {
                filtered = true;
                break;
            }
        }
    }

    return filtered;
}


