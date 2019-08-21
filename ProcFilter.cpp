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
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

using namespace std;


#define RELOAD_INTERVAL 300 // 5 minutes

const std::string CONFIG_PARAM_NAME = "process_filters";

//
// Helper macros used for parsing the Sysmon XML config
//
#define RULE_COMBINE_TYPE_FROM_STRING( a )\
    (0 == xmlStrcasecmp( a, (xmlChar*)"or")) ? RuleCombineOR :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"and")) ? RuleCombineOR : RuleCombineTypeInvalid;

#define RULE_TYPE_FROM_STRING( a )\
    (0 == xmlStrcasecmp( a, (xmlChar*)"include")) ? RuleTypeInclude :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"exclude")) ? RuleTypeExclude : RuleTypeInvalid;

#define RULE_MATCH_TYPE_FROM_STRING( a )\
    (0 == xmlStrcasecmp( a, (xmlChar*)"is"))    ? MatchEquals :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"isnot")) ? MatchUndefined :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"contains")) ? MatchUndefined :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"excludes")) ? MatchUndefined :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"begin with")) ? MatchStartsWith :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"end with")) ? MatchUndefined :\
    (0 == xmlStrcasecmp( a, (xmlChar*)"regex")) ? MatchRegex : MatchUndefined;

#define IS_EVENTFILTER_NODE( a )\
    (0 == xmlStrcasecmp( a->name, (xmlChar*)"eventfiltering"))

#define IS_RULEGROUP_NODE( a )\
    (0 == xmlStrcasecmp( a->name, (xmlChar*)"rulegroup"))

typedef enum
{
    RuleTypeInvalid=0,
    RuleTypeInclude = 1,
    RuleTypeExclude = 2,
    RuleTypeDefault = 2
} RuleType, *PRuleType;

typedef enum {
    RuleCombineTypeInvalid=0,
	RuleCombineOR = 1,
	RuleCombineAND = 2,
	RuleCombineDefault = 2
}  RuleCombineType, *PRuleCombimlneType;



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
                int uid = -1;
                int gid = -1;
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
                            uid = std::stoi(user);
                        } else {
                            uid = _user_db->UserNameToUid(user);
                        }
                        if (uid == -1) {
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
                            gid = std::stoi(group);
                        } else {
                            gid = _user_db->GroupNameToGid(group);
                        }
                        if (gid == -1) {
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
                        for (auto it2 = mi->value.Begin(); it2 != mi->value.End(); ++it2) {
                            syscalls.emplace_back(std::string(it2->GetString(), it2->GetStringLength()));
                            if (it2->GetString()[0] == '!') {
                                includesExclude = true;
                            }
                        }
                        if (includesExclude) {
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



bool ProcFilter::ParseSysmonConfig(std::string& xmlfile) 
{
    xmlDocPtr doc = NULL;
    xmlNodePtr rulesPtr = NULL;
    bool rc = false;

   // If we omit this, the parse will interpret the whitespace at the end of each line as an element called 'text'
   xmlKeepBlanksDefault(0);


    doc = xmlParseFile(xmlfile.c_str());
    if (NULL == doc) {

        Logger::Error("Failed to parse xml file\n");
        return rc;
    }

    // TODO: Validate against schema


    // Get the root element node
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (NULL == root || NULL == root->name || xmlStrcasecmp(root->name, (xmlChar*)"sysmon")) {

        Logger::Error("Invalid root node\n");

    } else {

        xmlNodePtr cur = NULL;
        for (cur = root->children; NULL != cur; cur=cur->next) {

            assert(NULL != cur->name);

            // We will walk the top level entries first then process the rule tree so use a cursor 
            // for the root of the rule node. 
            if (IS_EVENTFILTER_NODE(cur)) {

                rulesPtr = cur;
                continue;
            }

            /* TODO: Enable features and set hashing algorithm */
        }

        // Finished processing the root level nodes so now tackle the rules
        // These may or may not be nested inside a rulegroup
        if (NULL != rulesPtr) {

           // Assume sucess unless we hit a bad rule
           rc = true;

           // groupRelation attribute is optional. Set the default if not-used
           RuleCombineType combineType = RuleCombineDefault;

            cur = rulesPtr->children;

            while (NULL != cur) {

                // If this is a rulegroup node then check if the combineType has been overriden
                if (IS_RULEGROUP_NODE (cur)) {

                    xmlChar* groupRelation = xmlGetProp(cur, (xmlChar*)"groupRelation");
             
                    if (NULL != groupRelation) {
                       
                        combineType  = RULE_COMBINE_TYPE_FROM_STRING(groupRelation);
                        if (RuleCombineTypeInvalid == combineType) {

                            Logger::Error("Invalid combine type %s\n", groupRelation);
                            rc = false;
                            xmlFree(groupRelation);
                            break;
                        }

                       xmlFree(groupRelation);
                    }

                    // rules are nested inside the rulegroup so drop down the hierachy
                    cur = cur->children;
                    continue;
                }

                // Process the rule metadata for this event. RuleType (include or exclude) is optional
                RuleType ruleType = RuleTypeDefault;

                if (xmlHasProp(cur, (xmlChar*)"onmatch")) {

                    xmlChar *type = xmlGetProp(cur, (xmlChar*)"onmatch");
                    assert (NULL != type); 

                    ruleType = RULE_TYPE_FROM_STRING(type);
                    if (RuleTypeInvalid == ruleType) {

                        Logger::Error("Invalid rule type %s\n", type);
                        rc = false;
                        xmlFree(type);
                        break;
                    }

                    xmlFree(type);
                }

               // Now process the rules themselves..
               xmlNodePtr currentRule = NULL;
               StringMatchType matchType = MatchUndefined;
                
                for (currentRule = cur->children; NULL != currentRule; currentRule=currentRule->next) {
                    
                    xmlChar *condition = xmlGetProp(currentRule, (xmlChar*)"condition");
                    if (NULL == condition) {

                       Logger::Error("Failed to parse rule condition. Rule will be ignored\n");

                    } else {

                        StringMatchType matchType = RULE_MATCH_TYPE_FROM_STRING(condition);
                        if (MatchUndefined == matchType) {

                            Logger::Error("Invalid match condition %s\n", condition);
                            rc = false;
                            xmlFree(condition);
                            break;
                        }

                        xmlChar* value = xmlNodeGetContent(currentRule);

                        vector<string> syscalls;
                        string emptyString = "";
                        std::vector<cmdlineFilter> cmdlineFilters;

                        uint32_t match_mask;
                        switch(matchType) {
                            case MatchEquals:
                                match_mask |= PFS_MATCH_EXE_EQUALS;
                                break;
                            case MatchStartsWith:
                                match_mask |= PFS_MATCH_EXE_STARTSWITH;
                                break;
                            case MatchRegex:
                                match_mask |= PFS_MATCH_EXE_REGEX;
                                break;
                        }
                  
/*
                          _filters.emplace_back(-1,                             // depth
                                                emptyString,                    // User
                                                emptyString,                    // group
                                                syscalls,                       // syscall vector
                                                matchType,                      // image matchType {Equals, StartsWith etc}
                                                string((const char*)value),     // image match string
                                                matchType,                      // args match type
                                                string((const char*)value));    // args match string
*/

                          _filters.emplace_back(match_mask,                     // match mask
                                                -1,                             // depth
                                                -1,                             // User
                                                -1,                             // group
                                                syscalls,                       // syscall vector
                                                string((const char*)value),     // image match string
                                                cmdlineFilters);                 // cmdline filters

                        xmlFree(value);
                        xmlFree(condition);
                    }
                }

                cur = cur->next;
            }
        }
    } 

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return rc;
}




