/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_TRANSLATE_H
#define AUOMS_TRANSLATE_H

#include "MachineType.h"
#include "RecordType.h"
#include "FieldType.h"

#include <string>
#include <string_view>
#include <cstdint>

MachineType DetectMachine();
MachineType ArchNameToMachine(const std::string_view& arch);
bool MachineToName(MachineType mach, std::string& str);
uint32_t ArchNameToArch(const std::string_view& arch);
MachineType ArchToMachine(uint32_t arch);
uint32_t MachineToArch(MachineType mach);
std::string ArchToName(uint32_t arch);

bool SyscallToName(MachineType mtype, int syscall, std::string& str);
std::string SyscallToName(MachineType mtype, int syscall);
int SyscallNameToNumber(MachineType mtype, const std::string_view& syscall_name);

std::string_view RecordTypeToName(RecordType code, std::string& unknown_str);
std::string RecordTypeToName(RecordType code);
RecordType RecordNameToType(const std::string_view& name);
std::string RecordTypeCategoryToName(RecordTypeCategory code);
RecordTypeCategory RecordTypeCategoryNameToCategory(const std::string_view& name);

field_type_t FieldNameToType(const std::string_view& name);
field_type_t FieldNameToType(RecordType rtype, const std::string_view& name, const std::string_view& val);

std::string FieldIdToName(int field);
int FieldNameToId(const std::string_view& name);

std::string ErrnoToName(int field);
int NameToErrno(const std::string_view& name);

#endif //AUOMS_TRANSLATE_H
