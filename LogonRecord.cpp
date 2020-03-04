/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include "LogonRecord.h"

#include <string>
#include <unordered_map>
#include <list>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include <rapidjson/writer.h>
#include <rapidjson/reader.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <iostream>
#include <fstream>

using namespace std;
using namespace rapidjson;

const uint64_t seconds30d = 60 * 60 * 24 * 30;
//const uint64_t saveIntervalSeconds = 3600;
const uint64_t saveIntervalSeconds = 1;

string LogonRecord::Add(int uid, string logonSource, uint64_t logonSeconds)
{
    string result;
    int uidSourceCount = 0;
    int uidTotal = 0;
    int allTotal = 0;
    uint64_t now = chrono::time_point_cast<chrono::seconds>(chrono::system_clock::now()).time_since_epoch().count();

    // add the new logon event
    _logonEvents.emplace_front(uid, logonSource, logonSeconds);
    allTotal = _logonEvents.size();

    // increment counts
    auto logonDetails = _logonDetails.find(uid);
    if (logonDetails == _logonDetails.end()) {
        // uid not already in map
        LogonDetails newLogonDetails(logonSource);
        _logonDetails.insert({uid, newLogonDetails});
        uidSourceCount = 1;
        uidTotal = 1;
    } else {
        // update counts
        logonDetails->second._total++;
        uidTotal = logonDetails->second._total;

        auto logonCounts = logonDetails->second._logonCounts;
        auto logonCount = logonCounts.find(logonSource);
        if (logonCount == logonCounts.end()) {
            // logonSource not already in map
            logonDetails->second._logonCounts[logonSource] = 1;
            uidSourceCount = 1;
        } else {
            // update count
            logonCount->second++;
            uidSourceCount = logonCount->second;
        }

    }

    // make result string
    result = logonSource + " ( " + to_string(uidSourceCount) + " / " + to_string(uidTotal) + " / " + to_string(allTotal) + ")";
    printf("%s\n", result.c_str());

    // remove old events and update counts
    uint64_t iterTime = now - seconds30d;
    RemoveOldEvents(iterTime);

    if (now - lastSaveSeconds > saveIntervalSeconds) {
        Save();
        lastSaveSeconds = now;
    }

    return result;
}

void LogonRecord::RemoveOldEvents(uint64_t logonSeconds)
{
    if (_logonEvents.empty()) {
        return;
    }

    auto it = _logonEvents.rbegin();
    while ((it != _logonEvents.rend()) && (it->_logonSeconds < logonSeconds)) {
        // decrement counts
        auto logonDetails = _logonDetails.find(it->_uid);
        if (logonDetails != _logonDetails.end()) {
            if (logonDetails->second._total > 0) {
                logonDetails->second._total--;
            }
            if (logonDetails->second._total == 0) {
                _logonDetails.erase(logonDetails);
            } else {
                auto logonCounts = logonDetails->second._logonCounts;
                auto logonCount = logonCounts.find(it->_logonSource);
                if (logonCount != logonCounts.end()) {
                    if (logonCount->second > 0) {
                        logonCount->second--;
                    }
                    if (logonCount->second == 0) {
                        logonCounts.erase(logonCount);
                    }
                }
            }
        }

        it++;
        _logonEvents.pop_back();
    }
}

void LogonRecord::Load()
{
    _logonEvents.clear();
    _logonDetails.clear();

    stringstream buffer;
    try {
        ifstream inputfile(_filename);
        buffer << inputfile.rdbuf();
        inputfile.close();
    }
    catch (int e) {
        printf("Cannot open/read logon events file\n");
        return;
    }

    rapidjson::Document doc;
    doc.Parse(buffer.str().c_str());
    if (!doc.IsObject()) {
        printf("doc is not object\n");
        return;
    }

    int idx = 0;
    rapidjson::Value::ConstMemberIterator mi, mi2, mi3;

    mi = doc.FindMember("logonEvents");
    if (mi == doc.MemberEnd()) {
        printf("logonEvents is missing\n");
        return;
    }

    if (!mi->value.IsArray()) {
        printf("logonEvents is not an array\n");
        return;
    }

    for (auto it = mi->value.Begin(); it != mi->value.End(); it++) {
        if (!it->IsObject()) {
            printf("logonEvents array contains non-object\n");
            return;
        }

        int uid;
        string logonSource;
        uint64_t logonSeconds;

        mi2 = it->FindMember("uid");
        if (mi2 == it->MemberEnd()) {
            printf("logonEvents object missing uid field\n");
            return;
        }
        if (!mi2->value.IsInt()) {
            printf("logonEvents object uid field not int\n");
            return;
        }
        uid = mi2->value.GetInt();

        mi2 = it->FindMember("logonSource");
        if (mi2 == it->MemberEnd()) {
            printf("logonEvents object missing logonSource field\n");
            return;
        }
        if (!mi2->value.IsString()) {
            printf("logonEvents object logonSource field not string\n");
            return;
        }
        logonSource = string(mi2->value.GetString(), mi2->value.GetStringLength());

        mi2 = it->FindMember("logonSeconds");
        if (mi2 == it->MemberEnd()) {
            printf("logonEvents object missing logonSeconds field\n");
            return;
        }
        if (!mi2->value.IsInt64()) {
            printf("logonEvents object logonSeconds field not int64\n");
            return;
        }
        logonSeconds = mi2->value.GetInt64();

        _logonEvents.emplace_back(uid, logonSource, logonSeconds);
    }

    mi = doc.FindMember("logonDetails");
    if (mi == doc.MemberEnd()) {
        printf("logonDetails is missing\n");
        return;
    }

    if (!mi->value.IsArray()) {
        printf("logonDetails is not an array\n");
        return;
    }

    for (auto it = mi->value.Begin(); it != mi->value.End(); it++) {
        if (!it->IsObject()) {
            printf("logonDetails array contains non-object\n");
            return;
        }

        int uid, total;

        mi2 = it->FindMember("uid");
        if (mi2 == it->MemberEnd()) {
            printf("logonDetails object missing uid field\n");
            return;
        }
        if (!mi2->value.IsInt()) {
            printf("logonDetails object uid field not int\n");
            return;
        }
        uid = mi2->value.GetInt();

        mi2 = it->FindMember("total");
        if (mi2 == it->MemberEnd()) {
            printf("logonDetails object missing total field\n");
            return;
        }
        if (!mi2->value.IsInt()) {
            printf("logonDetails object total field not int\n");
            return;
        }
        total = mi2->value.GetInt();

        LogonDetails logonDetails(total);

        mi2 = it->FindMember("details");
        if (mi2 == it->MemberEnd()) {
            printf("logonDetails object missing details field\n");
            return;
        }
        if (!mi2->value.IsArray()) {
            printf("logonDetails object details field not array\n");
            return;
        }

        for (auto it2 = mi2->value.Begin(); it2 != mi2->value.End(); it2++) {
            if (!it2->IsObject()) {
                printf("logonDetails details array contains non-object\n");
                return;
            }

            string logonSource;
            int count;

            mi3 = it2->FindMember("logonSource");
            if (mi3 == it2->MemberEnd()) {
                printf("logonDetails object missing logonSource field\n");
                return;
            }
            if (!mi3->value.IsString()) {
                printf("logonDetails object logonSource field not string\n");
                return;
            }
            logonSource = string(mi3->value.GetString(), mi3->value.GetStringLength());

            mi3 = it2->FindMember("count");
            if (mi3 == it2->MemberEnd()) {
                printf("logonDetails object missing count field\n");
                return;
            }
            if (!mi3->value.IsInt()) {
                printf("logonDetails object count field not int\n");
                return;
            }
            count = mi3->value.GetInt();

            logonDetails._logonCounts[logonSource] = count;
        }

        _logonDetails.insert({uid, logonDetails});
    }
}

void LogonRecord::Save()
{
    StringBuffer s;
    Writer<StringBuffer> writer(s);

    writer.StartObject();
    writer.Key("logonEvents");
    writer.StartArray();
    for (auto it = _logonEvents.begin(); it != _logonEvents.end(); it++) {
        writer.StartObject();
        writer.Key("uid");
        writer.Int(it->_uid);
        writer.Key("logonSource");
        writer.String(it->_logonSource.c_str(), it->_logonSource.length(), true);
        writer.Key("logonSeconds");
        writer.Int64(it->_logonSeconds);
        writer.EndObject();
    }
    writer.Key("logonDetails");
    writer.StartArray();
    for (auto logonDetails : _logonDetails) {
        writer.StartObject();
        writer.Key("uid");
        writer.Int(logonDetails.first);
        writer.Key("total");
        writer.Int(logonDetails.second._total);
        writer.Key("details");
        writer.StartArray();
        for (auto counts : logonDetails.second._logonCounts) {
            writer.StartObject();
            writer.Key("logonSource");
            writer.String(counts.first.c_str(), counts.first.length(), true);
            writer.Key("count");
            writer.Int(counts.second);
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();

    ofstream outputfile;
    outputfile.open(_filename);
    outputfile << s.GetString() << endl;
    outputfile.close();
}



