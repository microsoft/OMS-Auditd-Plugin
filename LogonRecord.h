/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_LOGONRECORD_H
#define AUOMS_LOGONRECORD_H

#include "UserDB.h"

#include <string>
#include <unordered_map>
#include <queue>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <bits/stdc++.h>

class LogonDetails {
public:
    LogonDetails(std::string logonSource): _total(1)
    {
        _logonCounts[logonSource] = 1;
    }
    LogonDetails(int total): _total(total) {}

    int _total;
    std::unordered_map<std::string, int> _logonCounts; // maps logon source to counts
};

class LogonEvent {
public:
    LogonEvent(int uid, std::string logonSource, uint64_t logonSeconds):
        _uid(uid), _logonSource(logonSource), _logonSeconds(logonSeconds) {}

    int _uid;
    std::string _logonSource;
    uint64_t _logonSeconds;
};

class LogonRecord {
public:
    LogonRecord(std::string filename): _filename(filename)
    {
        Load();
    }

    std::string Add(int uid, std::string logonSource, uint64_t logonSeconds);

private:
    void Load();
    void Save();
    void RemoveOldEvents(uint64_t logonSeconds);

    uint64_t lastSaveSeconds;
    std::unordered_map<int, LogonDetails> _logonDetails; // maps uid to logon details

    std::string _filename;
    std::list<LogonEvent> _logonEvents; // list of logon events, up to 30 days

};


#endif //AUOMS_LOGONRECORD_H
