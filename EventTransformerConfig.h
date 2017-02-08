/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_EVENT_TRANSFORMER_CONFIG_H
#define AUOMS_EVENT_TRANSFORMER_CONFIG_H

#include "Config.h"


class EventTransformerConfig {
public:
    typedef enum {
        EMIT_RAW = 0x1,
        EMIT_INTERP = 0x2,
        EMIT_BOTH = 0x3
    } field_emit_mode_t;

    typedef enum {
        PREFIX_RECORD_INDEX = 0x0,
        PREFIX_RECORD_TYPE_NUMBER = 0x1,
        PREFIX_RECORD_TYPE_NAME = 0x2
    } field_prefix_mode_t;

    explicit EventTransformerConfig(bool msgPerRecord)
    {
        MsgPerRecord = msgPerRecord;
        IncludeFullRawText = true;
        RawTextFieldName = "raw";
        FieldEmitMode = EMIT_BOTH;
        FieldNameSeparator = "-";
        FieldPrefixMode = PREFIX_RECORD_TYPE_NAME;
        TimestampFieldName = "timestamp";
        SerialFieldName = "serial";
        MsgTypeFieldName = "type";
        RecordCountFieldName = "record-count";
        if (msgPerRecord) {
            RecordTypeFieldName = "record-type";
            RecordNameFieldName = "record-name";
        } else {
            RecordTypeFieldName = "record-types";
            RecordNameFieldName = "record-names";
        }
        FieldNameDedupIndexOneBased = true;
        FieldNameDedupIndexGlobal = false;
        FieldNameDedupSuffixRawField = false;
        FieldSuffix = "-i";
        DecodeEscapedFieldValues = true;
    }

    bool LoadFromConfig(const Config& config);

    bool MsgPerRecord; // If true, each event record is emitted as a separate message
    bool IncludeFullRawText; // Include the full raw text of the event (or record) in the message
    std::string RawTextFieldName; // Default "raw"

    field_emit_mode_t FieldEmitMode;

    std::string FieldNameSeparator;
    field_prefix_mode_t FieldPrefixMode;

    std::string TimestampFieldName;
    std::string SerialFieldName;
    std::string MsgTypeFieldName;

    std::string RecordCountFieldName;

    // If MsgPerRecord is true, this is the name of the field that will hold the record type name.
    // If MsgPerRecord is false, this is the name of the field that will hold the comma delimited array of record type names.
    std::string RecordNameFieldName;

    // If MsgPerRecord is true, this is the name of the field that will hold the record type.
    // If MsgPerRecord is false, this is the name of the field that will hold the comma delimited array of record types.
    std::string RecordTypeFieldName;

    // When there are multiple records of the same type and MsgPerRecord is false, the field names for the
    // records must be deduped. This involves adding a field name suffix in the form of a number.
    // The number can be 0, or 1 based. And the number can be based on the global record index,
    // or it can be based on the order it appeared within the set for that record type.
    bool FieldNameDedupIndexOneBased;
    bool FieldNameDedupIndexGlobal;

    // If FieldEmitMode = AEP_EMIT_BOTH, then one of the two values needs a suffix.
    // If FieldNameDedupSuffixRawField == false, then FieldSuffix is appended to the field name for the interp field
    // If FieldNameDedupSuffixRawField == true, then FieldSuffix is appended to the field name for the raw field
    bool FieldNameDedupSuffixRawField;
    std::string FieldSuffix; // The suffix to add to the raw field name

    // Some audit field values might be escaped (HEX encoded).
    // If DecodeEscapedFieldValues is true, then decode the HEX and escapes any non-ASCII (c >= 0x80) chars
    bool DecodeEscapedFieldValues;

    std::unordered_map<int, std::string> RecordTypeNameOverrideMap;
    std::unordered_map<std::string, std::string> FieldNameOverrideMap;
    std::unordered_map<std::string, std::string> InterpFieldNameMap;
};

#endif //AUOMS_EVENT_TRANSFORMER_CONFIG_H
