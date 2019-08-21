/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_OMSEVENTWRITERCONFIG_H
#define AUOMS_OMSEVENTWRITERCONFIG_H

#include "Config.h"
#include "ProcFilter.h"
#include "FiltersEngine.h"

class TextEventWriterConfig {
public:
    explicit TextEventWriterConfig()
    {
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

    void LoadFromConfig(std::string name, const Config& config, std::shared_ptr<UserDB> user_db, std::shared_ptr<FiltersEngine> filtersEngine, std::shared_ptr<ProcessTree> processTree);

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
    std::bitset<FILTER_BITSET_SIZE> FilterFlagsMask;

    std::shared_ptr<ProcFilter> proc_filter = NULL;
    std::shared_ptr<FiltersEngine> _filtersEngine;
    std::shared_ptr<ProcessTree> _processTree;
};


#endif //AUOMS_OMSEVENTWRITERCONFIG_H
