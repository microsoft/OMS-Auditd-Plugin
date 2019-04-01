/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_OMSEVENTTRANSFORMERCONFIG_H
#define AUOMS_OMSEVENTTRANSFORMERCONFIG_H

#include "Config.h"

struct ProcSyscallFilterSpec {
    ProcSyscallFilterSpec(const std::string& exe, const std::string& args, const std::string& user, const std::vector<std::string>& syscalls, int depth) {
        _exe = std::regex(exe, std::regex::optimize);
        _args = std::regex(args, std::regex::optimize);
        _user = user;
        std::copy(syscalls.cbegin(), syscalls.cend(), std::inserter(_syscalls, _syscalls.end()));
        _depth = depth;
    }

    std::regex _exe;
    std::regex _args;
    std::string _user;
    std::vector<std::string> _syscalls;
    int _depth;
};


class OMSEventWriterConfig {
public:
    explicit OMSEventWriterConfig()
    {
        IncludeFullRawText = true;
        RawTextFieldName = "raw";
        TimestampFieldName = "Timestamp";
        SerialFieldName = "SerialNumber";
        MsgTypeFieldName = "MessageType";
        RecordTypeFieldName = "RecordTypeCode";
        RecordTypeNameFieldName = "RecordType";
        RecordsFieldName = "records";
        FieldSuffix = "_r";
        ProcessFlagsFieldName = "ProcessFlags";
        FilterFlagsMask = 0;
    }

    bool LoadFromConfig(const Config& config);

    bool IncludeFullRawText; // Include the full raw text of the event (or record) in the message
    std::string RawTextFieldName; // Default "raw"

    std::string TimestampFieldName;
    std::string SerialFieldName;
    std::string MsgTypeFieldName;
    std::string RecordTypeFieldName;
    std::string RecordTypeNameFieldName;
    std::string RecordsFieldName;
    std::string ProcessFlagsFieldName;

    std::string FieldSuffix; // The suffix to add to the interpreted field name

    std::unordered_map<int, std::string> RecordTypeNameOverrideMap;
    std::unordered_map<std::string, std::string> FieldNameOverrideMap;
    std::unordered_map<std::string, std::string> InterpFieldNameMap;
    std::unordered_set<std::string> FilterRecordTypeSet;
    std::unordered_set<std::string> FilterFieldNameSet;
    std::vector<ProcSyscallFilterSpec> FilterProcSyscall;
    uint32_t FilterFlagsMask;

};


#endif //AUOMS_OMSEVENTTRANSFORMERCONFIG_H
