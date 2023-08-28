/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_AUDITRULES_H
#define AUOMS_AUDITRULES_H

#include <linux/audit.h>
#include <cstdint>
#include <array>
#include <cstring>
#include <vector>
#include <functional>
#include <unordered_set>
#include <string>
#include <stdexcept>

#ifndef AUDIT_MESSAGE_TEXT_MAX
#define AUDIT_MESSAGE_TEXT_MAX  8560
#endif

#ifndef AUDIT_SESSIONID
#define AUDIT_SESSIONID 25
#endif

#ifndef AUDIT_OBJ_UID
#define AUDIT_OBJ_UID 109
#endif
#ifndef AUDIT_OBJ_GID
#define AUDIT_OBJ_GID 110
#endif
#ifndef AUDIT_FIELD_COMPARE
#define AUDIT_FIELD_COMPARE 111
#endif

#ifndef AUDIT_EXE
#define AUDIT_EXE 112
#endif

#ifndef AUDIT_COMPARE_UID_TO_OBJ_UID
#define AUDIT_COMPARE_UID_TO_OBJ_UID   1
#endif
#ifndef AUDIT_COMPARE_GID_TO_OBJ_GID
#define AUDIT_COMPARE_GID_TO_OBJ_GID   2
#endif
#ifndef AUDIT_COMPARE_EUID_TO_OBJ_UID
#define AUDIT_COMPARE_EUID_TO_OBJ_UID  3
#endif
#ifndef AUDIT_COMPARE_EGID_TO_OBJ_GID
#define AUDIT_COMPARE_EGID_TO_OBJ_GID  4
#endif
#ifndef AUDIT_COMPARE_AUID_TO_OBJ_UID
#define AUDIT_COMPARE_AUID_TO_OBJ_UID  5
#endif
#ifndef AUDIT_COMPARE_SUID_TO_OBJ_UID
#define AUDIT_COMPARE_SUID_TO_OBJ_UID  6
#endif
#ifndef AUDIT_COMPARE_SGID_TO_OBJ_GID
#define AUDIT_COMPARE_SGID_TO_OBJ_GID  7
#endif
#ifndef AUDIT_COMPARE_FSUID_TO_OBJ_UID
#define AUDIT_COMPARE_FSUID_TO_OBJ_UID 8
#endif
#ifndef AUDIT_COMPARE_FSGID_TO_OBJ_GID
#define AUDIT_COMPARE_FSGID_TO_OBJ_GID 9
#endif
#ifndef AUDIT_COMPARE_UID_TO_AUID
#define AUDIT_COMPARE_UID_TO_AUID      10
#endif
#ifndef AUDIT_COMPARE_UID_TO_EUID
#define AUDIT_COMPARE_UID_TO_EUID      11
#endif
#ifndef AUDIT_COMPARE_UID_TO_FSUID
#define AUDIT_COMPARE_UID_TO_FSUID     12
#endif
#ifndef AUDIT_COMPARE_UID_TO_SUID
#define AUDIT_COMPARE_UID_TO_SUID      13
#endif
#ifndef AUDIT_COMPARE_AUID_TO_FSUID
#define AUDIT_COMPARE_AUID_TO_FSUID    14
#endif
#ifndef AUDIT_COMPARE_AUID_TO_SUID
#define AUDIT_COMPARE_AUID_TO_SUID     15
#endif
#ifndef AUDIT_COMPARE_AUID_TO_EUID
#define AUDIT_COMPARE_AUID_TO_EUID     16
#endif
#ifndef AUDIT_COMPARE_EUID_TO_SUID
#define AUDIT_COMPARE_EUID_TO_SUID     17
#endif
#ifndef AUDIT_COMPARE_EUID_TO_FSUID
#define AUDIT_COMPARE_EUID_TO_FSUID    18
#endif
#ifndef AUDIT_COMPARE_SUID_TO_FSUID
#define AUDIT_COMPARE_SUID_TO_FSUID    19
#endif
#ifndef AUDIT_COMPARE_GID_TO_EGID
#define AUDIT_COMPARE_GID_TO_EGID      20
#endif
#ifndef AUDIT_COMPARE_GID_TO_FSGID
#define AUDIT_COMPARE_GID_TO_FSGID     21
#endif
#ifndef AUDIT_COMPARE_GID_TO_SGID
#define AUDIT_COMPARE_GID_TO_SGID      22
#endif
#ifndef AUDIT_COMPARE_EGID_TO_FSGID
#define AUDIT_COMPARE_EGID_TO_FSGID    23
#endif
#ifndef AUDIT_COMPARE_EGID_TO_SGID
#define AUDIT_COMPARE_EGID_TO_SGID     24
#endif
#ifndef AUDIT_COMPARE_SGID_TO_FSGID
#define AUDIT_COMPARE_SGID_TO_FSGID    25
#endif

#ifndef AUDIT_FILTER_FS
#define AUDIT_FILTER_FS 0x06
#endif

#define AUOMS_RULE_KEY "auoms"
#define AUGENRULES_BIN "/sbin/augenrules"

class AuditRule {
public:
    static bool IsDataValid(const void* data, size_t len);

    AuditRule(): _data(), _value_offsets(), is_delete_rule(false) {
        _data.fill(0);
        _value_offsets.fill(0);
    }

    AuditRule(const void* data, size_t len): _data(), _value_offsets(), is_delete_rule(false) {
        _data.fill(0);
        if (len > _data.size()) {
            throw std::out_of_range("len too large");
        }
        ::memcpy(_data.data(), data, len);
        fill_value_offsets();
    }

    const void* Data() const { return _data.data(); }
    size_t Size() const { return sizeof(audit_rule_data) + ruleptr()->buflen; }

    // Will return true on success, false (error empty) if not a rule, false (error not empty) on parse error
    bool Parse(const std::string& text, std::string& error);

    // Rule text minus mergable parts (perms syscalls, keys)
    std::string CanonicalMergeKey() const;

    // Full Rule test
    std::string CanonicalText() const;

    std::string RawText() const;

    void Clean() {
        ::memset(&_data[Size()], 0, _data.size()-Size());
    }

    bool IsValid() const;

    bool IsWatch() const;

    // Return true if the rule is supported on the current system
    bool IsLoadable() const;

    std::unordered_set<char> GetPerms() const;
    // Is a no-op if PERM field not already present in rule
    void AddPerm(char perm);
    void AddPerms(const std::unordered_set<char>& perms);
    void SetPerms(const std::unordered_set<char>& perms);

    // Will return empty set if no syscalls, or syscall ALL
    std::unordered_set<int> GetSyscalls() const;
    bool IsSyscallAll() const;
    void SetSyscallAll();

    // Is no-op if syscall is out of range
    void AddSyscall(int syscall);
    void AddSyscalls(const std::unordered_set<int>& syscalls);
    void SetSyscalls(const std::unordered_set<int>& syscalls);

    std::unordered_set<std::string> GetKeys() const;
    void AddKey(const std::string& key);
    void AddKeys(const std::unordered_set<std::string>& keys);
    void SetKeys(const std::unordered_set<std::string>& keys);

    bool operator==(const AuditRule& rule) const;
    bool operator!=(const AuditRule& rule) const {
        return !(*this == rule);
    }

protected:
    inline audit_rule_data* ruleptr() {
        return reinterpret_cast<audit_rule_data*>(_data.data());
    }

    inline const audit_rule_data* ruleptr() const {
        return reinterpret_cast<const audit_rule_data*>(_data.data());
    }

    void fill_value_offsets();

    bool has_field(uint32_t field) const;
    uint32_t get_arch() const;

    bool parse_add_a_arg(const std::string& val, std::string& error);
    bool parse_add_w_arg(const std::string& val, std::string& error);
    bool parse_add_p_arg(const std::string& val, std::string& error);
    bool parse_add_S_arg(const std::string& val, std::string& error);
    bool parse_add_F_arg(const std::string& val, std::string& error);
    bool parse_add_C_arg(const std::string& val, std::string& error);
    bool parse_add_k_arg(const std::string& val, std::string& error);

    int add_field(uint32_t field, uint32_t op, uint32_t value);
    int add_str_field(uint32_t field, uint32_t op, const std::string& value);
    void remove_field(int idx);

    std::string get_str_field(uint32_t field) const;

    void append_action(std::string& out) const;
    void append_flag(std::string& out) const;
    void append_field_name(std::string& out, int field) const;
    void append_op(std::string& out, int op) const;
    void append_field(std::string& out, int idx, bool is_watch) const;
    void append_syscalls(std::string& out) const;

private:
    std::array<uint8_t, AUDIT_MESSAGE_TEXT_MAX> _data;
    std::array<uint32_t, AUDIT_MAX_FIELDS> _value_offsets;
    bool is_delete_rule;
};

void ReplaceSection(std::vector<std::string>& lines, const std::vector<std::string>& replacement, const std::string& start_marker,  const std::string& end_marker);
void RemoveSection(std::vector<std::string>& lines, const std::string& start_marker,  const std::string& end_marker);

// If errors is null, then ParseRules will throiw an exception if there is a parse error
// If errors is not null, then ParseRules willa append each parse error to errors and return only the parsed rules.
std::vector<AuditRule> ParseRules(const std::vector<std::string>& lines, std::vector<std::string>* errors);

std::vector<AuditRule> MergeRules(const std::vector<AuditRule>& rules1);
std::vector<AuditRule> MergeRules(const std::vector<AuditRule>& rules1, const std::vector<AuditRule>& rules2);

// Return set of rules that when added to actual, at least represents the desired
// If rule in actual has a key matching match_key, and that rule matches the canonical(-F) of a desired byt not the perm/syscall
// Then the returned rules will include new rule plus delete rule
std::vector<AuditRule> DiffRules(const std::vector<AuditRule>& actual, const std::vector<AuditRule>& desired, const std::string& match_key);

bool HasAuditdRulesFiles();

// Read all *.rules files from dir, parse, merge then return them.
std::vector<AuditRule> ReadAuditRulesFromDir(const std::string& dir, std::vector<std::string>* errors);

// Read rules from auditd rules (excluding auoms rules)
std::vector<AuditRule> ReadActualAuditdRules(bool exclude_auoms, std::vector<std::string>* errors);

// Adds auoms's desired rules to auditd config
// Returns true if augenrules needs to be run
bool WriteAuditdRules(const std::vector<AuditRule>& rules);

// Remove auoms's desired rules to auditd config
// Returns true if augenrules needs to be run
bool RemoveAuomsRulesAuditdFiles();


#endif //AUOMS_AUDITRULES_H
