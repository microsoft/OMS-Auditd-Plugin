/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <linux/audit.h>

#include "Translate.h"
#include "StringTable.h"

static StringTable<int> s_field_name_table(-1, {
	{"pid", 0},
	{"uid", 1},
	{"euid", 2},
	{"suid", 3},
	{"fsuid", 4},
	{"gid", 5},
	{"egid", 6},
	{"sgid", 7},
	{"fsgid", 8},
	{"auid", 9},
	{"loginuid", 9},
	{"pers", 10},
	{"arch", 11},
	{"msgtype", 12},
	{"subj_user", 13},
	{"subj_role", 14},
	{"subj_type", 15},
	{"subj_sen", 16},
	{"subj_clr", 17},
	{"ppid", 18},
	{"obj_user", 19},
	{"obj_role", 20},
	{"obj_type", 21},
	{"obj_lev_low", 22},
	{"obj_lev_high", 23},
	{"sessionid", 25},
	{"devmajor", 100},
	{"devminor", 101},
	{"inode", 102},
	{"exit", 103},
	{"success", 104},
	{"path", 105},
	{"perm", 106},
	{"dir", 107},
	{"filetype", 108},
	{"obj_uid", 109},
	{"obj_gid", 110},
	{"field_compare", 111},
	{"a0", 200},
	{"a1", 201},
	{"a2", 202},
	{"a3", 203},
	{"key", 210},
	{"exe", 112},
});

std::string FieldIdToName(int field) {
    auto str = std::string(s_field_name_table.ToString(field));
    if (str.empty()) {
        str = "f" + std::to_string(field);
    }
    return str;
}

int FieldNameToId(const std::string_view& name) {
    return s_field_name_table.ToInt(name);
}
