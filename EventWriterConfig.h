/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_EVENTWRITERCONFIG_H
#define AUOMS_EVENTWRITERCONFIG_H

#include "Config.h"
#include "ProcFilter.h"
#include "FiltersEngine.h"

class EventWriterConfig {
public:
    explicit EventWriterConfig()
    {
        SchemaVersionFieldName = "SchemaVersion";
        SchemaVersion = "1";
        TimestampFieldName = "Timestamp";
        SerialFieldName = "SerialNumber";
        RecordTypeFieldName = "RecordTypeCode";
        RecordTypeNameFieldName = "RecordType";
        RecordsFieldName = "records";
        FieldSuffix = "_r";
        ComputerFieldName = "Computer";
        AuditIDFieldName = "AuditID";
        RecordTextFieldName = "RecordText";
        OtherFieldsFieldName = "OtherFields";

        char hostname[HOST_NAME_MAX];
        gethostname(hostname, HOST_NAME_MAX);
        HostnameValue = hostname;
        IncludeRecordTextField = false;
        RecordFilterInclusiveMode = false;
        FieldFilterInclusiveMode = false;
        OtherFieldsMode = false;
    }

    void LoadFromConfig(std::string name, const Config& config);

    inline bool IsRecordFiltered(const std::string& name) {
        if (FilterRecordTypeSet.count(name) != 0) {
            return !RecordFilterInclusiveMode;
        } else {
            return RecordFilterInclusiveMode;
        }
    }

    inline bool IsFieldFiltered(const std::string& name) {
        if (FilterFieldNameSet.count(name) != 0) {
            return !FieldFilterInclusiveMode;
        } else {
            return FieldFilterInclusiveMode;
        }
    }

    inline bool IsFieldAlwaysFiltered(const std::string& name) {
        return (AlwaysFilterFieldNameSet.count(name) != 0);
    }

    std::string SchemaVersionFieldName;
    std::string SchemaVersion;
    std::string TimestampFieldName;
    std::string SerialFieldName;
    std::string MsgTypeFieldName;
    std::string RecordTypeFieldName;
    std::string RecordTypeNameFieldName;
    std::string RecordsFieldName;
    std::string ProcessFlagsFieldName;
    std::string ComputerFieldName;
    std::string AuditIDFieldName;
    std::string RecordTextFieldName;
    std::string HostnameValue;
    std::string OtherFieldsFieldName;

    bool IncludeRecordTextField;
    bool FieldFilterInclusiveMode;
    bool RecordFilterInclusiveMode;
    bool OtherFieldsMode;

    std::string FieldSuffix; // The suffix to add to the interpreted field name

    std::unordered_map<int, std::string> RecordTypeNameOverrideMap;
    std::unordered_map<std::string, std::string> FieldNameOverrideMap;
    std::unordered_map<std::string, std::string> InterpFieldNameMap;
    std::unordered_set<std::string> FilterRecordTypeSet;
    std::unordered_set<std::string> FilterFieldNameSet;
    std::unordered_set<std::string> AlwaysFilterFieldNameSet;
    std::unordered_map<std::string, std::string> AdditionalFieldsMap;
};


#endif //AUOMS_EVENTWRITERCONFIG_H
