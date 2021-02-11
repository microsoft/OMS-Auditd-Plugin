/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_PROC_FILTER_H
#define AUOMS_PROC_FILTER_H

#include <sys/time.h>
#include <string>
#include <memory>
#include <set>
#include <unordered_set>
#include <list>
#include <unordered_map>
#include <queue>
#include <re2/re2.h>
#include "Config.h"
#include "UserDB.h"
#include "ProcessInfo.h"
#include "ProcessDefines.h"

enum StringMatchType { MatchUndefined, MatchEquals, MatchStartsWith, MatchContains, MatchRegex };

struct cmdlineFilter {
    enum StringMatchType _matchType;
    std::string _matchValue;
    std::shared_ptr<re2::RE2> _matchRegex;
};

bool operator==(const cmdlineFilter& a, const cmdlineFilter& b);

struct ProcFilterSpec {
    ProcFilterSpec(uint32_t match_mask, int depth, int uid, int gid,
            std::vector<std::string>& syscalls, const std::string& exeMatchValue,
            const std::vector<cmdlineFilter>& cmdlineFilters)
    {
        _match_mask = match_mask;
        _depth = depth;
        _uid =  uid;
        _gid = gid;
        std::copy(syscalls.cbegin(), syscalls.cend(), std::inserter(_syscalls, _syscalls.end()));
        _exeMatchValue = exeMatchValue;
        if (match_mask & PFS_MATCH_EXE_REGEX) {
            re2::RE2::Options re2_opts;
            re2_opts.set_never_capture(true);
            _exeRegex = std::make_shared<re2::RE2>(exeMatchValue, re2_opts);
        }
        for (auto cf : cmdlineFilters) {
            if (cf._matchType == MatchRegex) {
                re2::RE2::Options re2_opts;
                re2_opts.set_never_capture(true);
                cf._matchRegex = std::make_shared<re2::RE2>(cf._matchValue, re2_opts);
            }
            _cmdlineFilters.emplace_back(cf);
        }
    }

    uint32_t _match_mask;
    int _depth;
    uint32_t _uid;
    uint32_t _gid;
    std::vector<std::string> _syscalls;
    std::string _exeMatchValue;
    std::shared_ptr<re2::RE2> _exeRegex;
    std::vector<cmdlineFilter> _cmdlineFilters;
};

struct ProcFilterSpecHash {
    std::size_t operator()(const ProcFilterSpec& pfs) const
    {
        size_t ret = std::hash<uint32_t>()(pfs._match_mask) +
            std::hash<int>()(pfs._depth) +
            std::hash<int>()(pfs._uid) +
            std::hash<int>()(pfs._gid) +
            std::hash<std::string>()(pfs._exeMatchValue);
        for (auto cf : pfs._cmdlineFilters) {
            ret += std::hash<std::string>()(cf._matchValue);
        }
        for (auto s : pfs._syscalls) {
            ret += std::hash<std::string>()(s);
        }
        return ret;
    }
};

struct ProcFilterSpecCompare {
    bool operator()(const ProcFilterSpec& lhs, const ProcFilterSpec& rhs) const
    {
        if (lhs._match_mask != rhs._match_mask || lhs._depth != rhs._depth || lhs._uid != rhs._uid ||
            lhs._gid != rhs._gid || lhs._exeMatchValue != rhs._exeMatchValue ||
            lhs._cmdlineFilters != rhs._cmdlineFilters || lhs._syscalls != rhs._syscalls) {
            return false;
        }

        return true;
    }
};

class ProcFilter {
public:
    ProcFilter(const std::shared_ptr<UserDB>& user_db): _user_db(user_db) {}
    ~ProcFilter() = default;

    bool ParseConfig(const Config& config);
    std::vector<ProcFilterSpec> _filters;

private:
    std::shared_ptr<UserDB> _user_db;

    // helper methods
    static bool is_number(const std::string& s);
};

#endif //AUOMS_PROC_FILTER_H
