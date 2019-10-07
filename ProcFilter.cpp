/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "ProcFilter.h"

#include "Logger.h"

#include <string>
#include <iostream>
#include <fstream>
#include <sys/stat.h> /* for stat() */
#include <dirent.h>
#include <algorithm>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

using namespace std;


#define RELOAD_INTERVAL 300 // 5 minutes

const std::string CONFIG_PARAM_NAME = "process_filters";
const uint32_t INVALID_ID = static_cast<uint32_t>(-1);


/*****************************************************************************
 ** ProcFilter
 *****************************************************************************/

// -------- helper functions -----------------------------
bool ProcFilter::is_number(const std::string& s)
{
    return !s.empty() &&
           std::find_if(s.begin(), s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
}

bool operator==(const cmdlineFilter& a, const cmdlineFilter& b) {                                                                                    return ((a._matchType == b._matchType) && (a._matchValue == b._matchValue));                                                                 }

// --------- end helper functions -------------------------

bool ProcFilter::ParseConfig(const Config& config) {
    if (config.HasKey(CONFIG_PARAM_NAME)) {
        auto doc = config.GetJSON(CONFIG_PARAM_NAME);
        if (!doc.IsArray()) {
            return false;
        }
        int idx = 0;
        for (auto it = doc.Begin(); it != doc.End(); ++it, idx++) {
            if (it->IsObject()) {
                uint32_t match_mask = 0;
                int depth = 0;
                uint32_t uid = INVALID_ID;
                uint32_t gid = INVALID_ID;
                std::string user;
                std::string group;
                std::vector<std::string> syscalls;
                std::string exeMatchValue;
                std::vector<cmdlineFilter> cmdlineFilters;

                rapidjson::Value::ConstMemberIterator mi;

                mi = it->FindMember("depth");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsInt()) {
                        int i = mi->value.GetInt();
                        if (i < -1) {
                            Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                            _filters.clear();
                            return false;
                        }
                        depth = i;
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }

                mi = it->FindMember("user");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        user = std::string(mi->value.GetString(), mi->value.GetStringLength());
                        if (is_number(user)) {
                            uid = (uint32_t)std::stol(user);
                        } else {
                            uid = (uint32_t)_user_db->UserNameToUid(user);
                        }
                        if (uid == INVALID_ID) {
                            Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                            _filters.clear();
                            return false;
                        }
                        match_mask |= PFS_MATCH_UID;
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }

                mi = it->FindMember("group");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        group = std::string(mi->value.GetString(), mi->value.GetStringLength());
                        if (is_number(group)) {
                            gid = (uint32_t)std::stol(group);
                        } else {
                            gid = (uint32_t)_user_db->GroupNameToGid(group);
                        }
                        if (gid == INVALID_ID) {
                            Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                            _filters.clear();
                            return false;
                        }
                        match_mask |= PFS_MATCH_GID;
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }

                mi = it->FindMember("syscalls");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsArray()) {
                        if (!syscalls.empty()) {
                            syscalls.clear();
                        }
                        bool includesExclude = false;
                        bool includesInclude = false;
                        for (auto it2 = mi->value.Begin(); it2 != mi->value.End(); ++it2) {
                            syscalls.emplace_back(std::string(it2->GetString(), it2->GetStringLength()));
                            if (it2->GetString()[0] == '!') {
                                includesExclude = true;
                            } else {
                                includesInclude = true;
                            }
                        }
                        // If all the syscalls are excludes (!syscall) then there is an implicit inclusion
                        // of all other syscalls.
                        // If there is a mixture of includes and excludes then includes are the default.
                        if (includesExclude && !includesInclude) {
                            syscalls.emplace_back(std::string("*"));
                        }
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }

                mi = it->FindMember("exeMatchType");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        if (!strcmp(mi->value.GetString(), "MatchEquals")) {
                            match_mask |= PFS_MATCH_EXE_EQUALS;
                        } else if (!strcmp(mi->value.GetString(), "MatchStartsWith")) {
                            match_mask |= PFS_MATCH_EXE_STARTSWITH;
                        } else if (!strcmp(mi->value.GetString(), "MatchContains")) {
                            match_mask |= PFS_MATCH_EXE_CONTAINS;
                        } else if (!strcmp(mi->value.GetString(), "MatchRegex")) {
                            match_mask |= PFS_MATCH_EXE_REGEX;
                        } else {
                            Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                            _filters.clear();
                            return false;
                        }
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }

                mi = it->FindMember("exeMatchValue");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsString()) {
                        exeMatchValue = std::string(mi->value.GetString(), mi->value.GetStringLength());
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }

                mi = it->FindMember("cmdlineFilters");
                if (mi != it->MemberEnd()) {
                    if (mi->value.IsArray()) {
                        if (!cmdlineFilters.empty()) {
                            cmdlineFilters.clear();
                        }
                        for (auto it2 = mi->value.Begin(); it2 != mi->value.End(); ++it2) {
                            if (it2->IsObject()) {
                                cmdlineFilter cf;
                                rapidjson::Value::ConstMemberIterator mi2;
                                mi2 = it2->FindMember("matchType");
                                if (mi2 != it2->MemberEnd()) {
                                    if (mi2->value.IsString()) {
                                        if (!strcmp(mi2->value.GetString(), "MatchEquals")) {
                                            cf._matchType = MatchEquals;
                                        } else if (!strcmp(mi2->value.GetString(), "MatchStartsWith")) {
                                            cf._matchType = MatchStartsWith;
                                        } else if (!strcmp(mi2->value.GetString(), "MatchContains")) {
                                            cf._matchType = MatchContains;
                                        } else if (!strcmp(mi2->value.GetString(), "MatchRegex")) {
                                            cf._matchType = MatchRegex;
                                        } else {
                                            Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                                            _filters.clear();
                                            return false;
                                        }
                                    } else {
                                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                                        _filters.clear();
                                        return false;
                                    }
                                } else {
                                    Logger::Error("Invalid entry (%s) at (%d) in config for '%s' is missing", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                                    _filters.clear();
                                    return false;
                                }

                                mi2 = it2->FindMember("matchValue");
                                if (mi2 != it2->MemberEnd()) {
                                    if (mi2->value.IsString()) {
                                        cf._matchValue = std::string(mi2->value.GetString(), mi2->value.GetStringLength());
                                    } else {
                                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                                        _filters.clear();
                                        return false;
                                    }
                                } else {
                                    Logger::Error("Invalid entry (%s) at (%d) in config for '%s' is missing", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                                    _filters.clear();
                                    return false;
                                }

                                cmdlineFilters.emplace_back(cf);
                            } else {
                                Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                                _filters.clear();
                                return false;
                            }
                        }
                    } else {
                        Logger::Error("Invalid entry (%s) at (%d) in config for '%s'", mi->name.GetString(), idx, CONFIG_PARAM_NAME.c_str());
                        _filters.clear();
                        return false;
                    }
                }

                if (syscalls.empty()) {
                    syscalls.emplace_back("*");
                }
                _filters.emplace_back(match_mask, depth, uid, gid, syscalls, exeMatchValue, cmdlineFilters);
            } else {
                Logger::Error("Invalid entry (%d) in config for '%s'", idx, CONFIG_PARAM_NAME.c_str());
                _filters.clear();
                return false;
            }
        }
    }
    return true;
}




