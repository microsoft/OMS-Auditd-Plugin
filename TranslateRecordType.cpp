/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Translate.h"
#include "StringTable.h"
#include "StringUtils.h"

static StringTable<RecordType> s_record_type_table(RecordType ::UNKNOWN, {
        {"GET",RecordType::GET},
        {"SET",RecordType::SET},
        {"LIST",RecordType::LIST},
        {"ADD",RecordType::ADD},
        {"DEL",RecordType::DEL},
        {"USER",RecordType::USER},
        {"LOGIN",RecordType::LOGIN},
        {"WATCH_INS",RecordType::WATCH_INS},
        {"WATCH_REM",RecordType::WATCH_REM},
        {"WATCH_LIST",RecordType::WATCH_LIST},
        {"SIGNAL_INFO",RecordType::SIGNAL_INFO},
        {"ADD_RULE",RecordType::ADD_RULE},
        {"DEL_RULE",RecordType::DEL_RULE},
        {"LIST_RULES",RecordType::LIST_RULES},
        {"TRIM",RecordType::TRIM},
        {"MAKE_EQUIV",RecordType::MAKE_EQUIV},
        {"TTY_GET",RecordType::TTY_GET},
        {"TTY_SET",RecordType::TTY_SET},
        {"SET_FEATURE",RecordType::SET_FEATURE},
        {"GET_FEATURE",RecordType::GET_FEATURE},
        {"USER_AUTH",RecordType::USER_AUTH},
        {"USER_ACCT",RecordType::USER_ACCT},
        {"USER_MGMT",RecordType::USER_MGMT},
        {"CRED_ACQ",RecordType::CRED_ACQ},
        {"CRED_DISP",RecordType::CRED_DISP},
        {"USER_START",RecordType::USER_START},
        {"USER_END",RecordType::USER_END},
        {"USER_AVC",RecordType::USER_AVC},
        {"USER_CHAUTHTOK",RecordType::USER_CHAUTHTOK},
        {"USER_ERR",RecordType::USER_ERR},
        {"CRED_REFR",RecordType::CRED_REFR},
        {"USYS_CONFIG",RecordType::USYS_CONFIG},
        {"USER_LOGIN",RecordType::USER_LOGIN},
        {"USER_LOGOUT",RecordType::USER_LOGOUT},
        {"ADD_USER",RecordType::ADD_USER},
        {"DEL_USER",RecordType::DEL_USER},
        {"ADD_GROUP",RecordType::ADD_GROUP},
        {"DEL_GROUP",RecordType::DEL_GROUP},
        {"DAC_CHECK",RecordType::DAC_CHECK},
        {"CHGRP_ID",RecordType::CHGRP_ID},
        {"TEST",RecordType::TEST},
        {"TRUSTED_APP",RecordType::TRUSTED_APP},
        {"USER_SELINUX_ERR",RecordType::USER_SELINUX_ERR},
        {"USER_CMD",RecordType::USER_CMD},
        {"USER_TTY",RecordType::USER_TTY},
        {"CHUSER_ID",RecordType::CHUSER_ID},
        {"GRP_AUTH",RecordType::GRP_AUTH},
        {"SYSTEM_BOOT",RecordType::SYSTEM_BOOT},
        {"SYSTEM_SHUTDOWN",RecordType::SYSTEM_SHUTDOWN},
        {"SYSTEM_RUNLEVEL",RecordType::SYSTEM_RUNLEVEL},
        {"SERVICE_START",RecordType::SERVICE_START},
        {"SERVICE_STOP",RecordType::SERVICE_STOP},
        {"GRP_MGMT",RecordType::GRP_MGMT},
        {"GRP_CHAUTHTOK",RecordType::GRP_CHAUTHTOK},
        {"MAC_CHECK",RecordType::MAC_CHECK},
        {"ACCT_LOCK",RecordType::ACCT_LOCK},
        {"ACCT_UNLOCK",RecordType::ACCT_UNLOCK},
        {"DAEMON_START",RecordType::DAEMON_START},
        {"DAEMON_END",RecordType::DAEMON_END},
        {"DAEMON_ABORT",RecordType::DAEMON_ABORT},
        {"DAEMON_CONFIG",RecordType::DAEMON_CONFIG},
        {"DAEMON_RECONFIG",RecordType::DAEMON_RECONFIG},
        {"DAEMON_ROTATE",RecordType::DAEMON_ROTATE},
        {"DAEMON_RESUME",RecordType::DAEMON_RESUME},
        {"DAEMON_ACCEPT",RecordType::DAEMON_ACCEPT},
        {"DAEMON_CLOSE",RecordType::DAEMON_CLOSE},
        {"DAEMON_ERR",RecordType::DAEMON_ERR},
        {"SYSCALL",RecordType::SYSCALL},
        {"PATH",RecordType::PATH},
        {"IPC",RecordType::IPC},
        {"SOCKETCALL",RecordType::SOCKETCALL},
        {"CONFIG_CHANGE",RecordType::CONFIG_CHANGE},
        {"SOCKADDR",RecordType::SOCKADDR},
        {"CWD",RecordType::CWD},
        {"EXECVE",RecordType::EXECVE},
        {"IPC_SET_PERM",RecordType::IPC_SET_PERM},
        {"MQ_OPEN",RecordType::MQ_OPEN},
        {"MQ_SENDRECV",RecordType::MQ_SENDRECV},
        {"MQ_NOTIFY",RecordType::MQ_NOTIFY},
        {"MQ_GETSETATTR",RecordType::MQ_GETSETATTR},
        {"KERNEL_OTHER",RecordType::KERNEL_OTHER},
        {"FD_PAIR",RecordType::FD_PAIR},
        {"OBJ_PID",RecordType::OBJ_PID},
        {"TTY",RecordType::TTY},
        {"EOE",RecordType::EOE},
        {"BPRM_FCAPS",RecordType::BPRM_FCAPS},
        {"CAPSET",RecordType::CAPSET},
        {"MMAP",RecordType::MMAP},
        {"NETFILTER_PKT",RecordType::NETFILTER_PKT},
        {"NETFILTER_CFG",RecordType::NETFILTER_CFG},
        {"SECCOMP",RecordType::SECCOMP},
        {"PROCTITLE",RecordType::PROCTITLE},
        {"FEATURE_CHANGE",RecordType::FEATURE_CHANGE},
        {"REPLACE",RecordType::REPLACE},
        {"KERN_MODULE",RecordType::KERN_MODULE},
        {"FANOTIFY",RecordType::FANOTIFY},
        {"AVC",RecordType::AVC},
        {"SELINUX_ERR",RecordType::SELINUX_ERR},
        {"AVC_PATH",RecordType::AVC_PATH},
        {"MAC_POLICY_LOAD",RecordType::MAC_POLICY_LOAD},
        {"MAC_STATUS",RecordType::MAC_STATUS},
        {"MAC_CONFIG_CHANGE",RecordType::MAC_CONFIG_CHANGE},
        {"MAC_UNLBL_ALLOW",RecordType::MAC_UNLBL_ALLOW},
        {"MAC_CIPSOV4_ADD",RecordType::MAC_CIPSOV4_ADD},
        {"MAC_CIPSOV4_DEL",RecordType::MAC_CIPSOV4_DEL},
        {"MAC_MAP_ADD",RecordType::MAC_MAP_ADD},
        {"MAC_MAP_DEL",RecordType::MAC_MAP_DEL},
        {"MAC_IPSEC_ADDSA",RecordType::MAC_IPSEC_ADDSA},
        {"MAC_IPSEC_DELSA",RecordType::MAC_IPSEC_DELSA},
        {"MAC_IPSEC_ADDSPD",RecordType::MAC_IPSEC_ADDSPD},
        {"MAC_IPSEC_DELSPD",RecordType::MAC_IPSEC_DELSPD},
        {"MAC_IPSEC_EVENT",RecordType::MAC_IPSEC_EVENT},
        {"MAC_UNLBL_STCADD",RecordType::MAC_UNLBL_STCADD},
        {"MAC_UNLBL_STCDEL",RecordType::MAC_UNLBL_STCDEL},
        {"MAC_CALIPSO_ADD",RecordType::MAC_CALIPSO_ADD},
        {"MAC_CALIPSO_DEL",RecordType::MAC_CALIPSO_DEL},
        {"AA",RecordType::AA},
        {"APPARMOR_AUDIT",RecordType::APPARMOR_AUDIT},
        {"APPARMOR_ALLOWED",RecordType::APPARMOR_ALLOWED},
        {"APPARMOR_DENIED",RecordType::APPARMOR_DENIED},
        {"APPARMOR_HINT",RecordType::APPARMOR_HINT},
        {"APPARMOR_STATUS",RecordType::APPARMOR_STATUS},
        {"APPARMOR_ERROR",RecordType::APPARMOR_ERROR},
        {"ANOM_PROMISCUOUS",RecordType::ANOM_PROMISCUOUS},
        {"ANOM_ABEND",RecordType::ANOM_ABEND},
        {"ANOM_LINK",RecordType::ANOM_LINK},
        {"INTEGRITY_DATA",RecordType::INTEGRITY_DATA},
        {"INTEGRITY_METADATA",RecordType::INTEGRITY_METADATA},
        {"INTEGRITY_STATUS",RecordType::INTEGRITY_STATUS},
        {"INTEGRITY_HASH",RecordType::INTEGRITY_HASH},
        {"INTEGRITY_PCR",RecordType::INTEGRITY_PCR},
        {"INTEGRITY_RULE",RecordType::INTEGRITY_RULE},
        {"INTEGRITY_EVM_XATTR",RecordType::INTEGRITY_EVM_XATTR},
        {"INTEGRITY_POLICY_RULE",RecordType::INTEGRITY_POLICY_RULE},
        {"ANOM_LOGIN_FAILURES",RecordType::ANOM_LOGIN_FAILURES},
        {"ANOM_LOGIN_TIME",RecordType::ANOM_LOGIN_TIME},
        {"ANOM_LOGIN_SESSIONS",RecordType::ANOM_LOGIN_SESSIONS},
        {"ANOM_LOGIN_ACCT",RecordType::ANOM_LOGIN_ACCT},
        {"ANOM_LOGIN_LOCATION",RecordType::ANOM_LOGIN_LOCATION},
        {"ANOM_MAX_DAC",RecordType::ANOM_MAX_DAC},
        {"ANOM_MAX_MAC",RecordType::ANOM_MAX_MAC},
        {"ANOM_AMTU_FAIL",RecordType::ANOM_AMTU_FAIL},
        {"ANOM_RBAC_FAIL",RecordType::ANOM_RBAC_FAIL},
        {"ANOM_RBAC_INTEGRITY_FAIL",RecordType::ANOM_RBAC_INTEGRITY_FAIL},
        {"ANOM_CRYPTO_FAIL",RecordType::ANOM_CRYPTO_FAIL},
        {"ANOM_ACCESS_FS",RecordType::ANOM_ACCESS_FS},
        {"ANOM_EXEC",RecordType::ANOM_EXEC},
        {"ANOM_MK_EXEC",RecordType::ANOM_MK_EXEC},
        {"ANOM_ADD_ACCT",RecordType::ANOM_ADD_ACCT},
        {"ANOM_DEL_ACCT",RecordType::ANOM_DEL_ACCT},
        {"ANOM_MOD_ACCT",RecordType::ANOM_MOD_ACCT},
        {"ANOM_ROOT_TRANS",RecordType::ANOM_ROOT_TRANS},
        {"RESP_ANOMALY",RecordType::RESP_ANOMALY},
        {"RESP_ALERT",RecordType::RESP_ALERT},
        {"RESP_KILL_PROC",RecordType::RESP_KILL_PROC},
        {"RESP_TERM_ACCESS",RecordType::RESP_TERM_ACCESS},
        {"RESP_ACCT_REMOTE",RecordType::RESP_ACCT_REMOTE},
        {"RESP_ACCT_LOCK_TIMED",RecordType::RESP_ACCT_LOCK_TIMED},
        {"RESP_ACCT_UNLOCK_TIMED",RecordType::RESP_ACCT_UNLOCK_TIMED},
        {"RESP_ACCT_LOCK",RecordType::RESP_ACCT_LOCK},
        {"RESP_TERM_LOCK",RecordType::RESP_TERM_LOCK},
        {"RESP_SEBOOL",RecordType::RESP_SEBOOL},
        {"RESP_EXEC",RecordType::RESP_EXEC},
        {"RESP_SINGLE",RecordType::RESP_SINGLE},
        {"RESP_HALT",RecordType::RESP_HALT},
        {"USER_ROLE_CHANGE",RecordType::USER_ROLE_CHANGE},
        {"ROLE_ASSIGN",RecordType::ROLE_ASSIGN},
        {"ROLE_REMOVE",RecordType::ROLE_REMOVE},
        {"LABEL_OVERRIDE",RecordType::LABEL_OVERRIDE},
        {"LABEL_LEVEL_CHANGE",RecordType::LABEL_LEVEL_CHANGE},
        {"USER_LABELED_EXPORT",RecordType::USER_LABELED_EXPORT},
        {"USER_UNLABELED_EXPORT",RecordType::USER_UNLABELED_EXPORT},
        {"DEV_ALLOC",RecordType::DEV_ALLOC},
        {"DEV_DEALLOC",RecordType::DEV_DEALLOC},
        {"FS_RELABEL",RecordType::FS_RELABEL},
        {"USER_MAC_POLICY_LOAD",RecordType::USER_MAC_POLICY_LOAD},
        {"ROLE_MODIFY",RecordType::ROLE_MODIFY},
        {"USER_MAC_CONFIG_CHANGE",RecordType::USER_MAC_CONFIG_CHANGE},
        {"CRYPTO_TEST_USER",RecordType::CRYPTO_TEST_USER},
        {"CRYPTO_PARAM_CHANGE_USER",RecordType::CRYPTO_PARAM_CHANGE_USER},
        {"CRYPTO_LOGIN",RecordType::CRYPTO_LOGIN},
        {"CRYPTO_LOGOUT",RecordType::CRYPTO_LOGOUT},
        {"CRYPTO_KEY_USER",RecordType::CRYPTO_KEY_USER},
        {"CRYPTO_FAILURE_USER",RecordType::CRYPTO_FAILURE_USER},
        {"CRYPTO_REPLAY_USER",RecordType::CRYPTO_REPLAY_USER},
        {"CRYPTO_SESSION",RecordType::CRYPTO_SESSION},
        {"CRYPTO_IKE_SA",RecordType::CRYPTO_IKE_SA},
        {"CRYPTO_IPSEC_SA",RecordType::CRYPTO_IPSEC_SA},
        {"VIRT_CONTROL",RecordType::VIRT_CONTROL},
        {"VIRT_RESOURCE",RecordType::VIRT_RESOURCE},
        {"VIRT_MACHINE_ID",RecordType::VIRT_MACHINE_ID},
        {"VIRT_INTEGRITY_CHECK",RecordType::VIRT_INTEGRITY_CHECK},
        {"VIRT_CREATE",RecordType::VIRT_CREATE},
        {"VIRT_DESTROY",RecordType::VIRT_DESTROY},
        {"VIRT_MIGRATE_IN",RecordType::VIRT_MIGRATE_IN},
        {"VIRT_MIGRATE_OUT",RecordType::VIRT_MIGRATE_OUT},
        {"VIRT_MIGRATE_OUT",RecordType::VIRT_MIGRATE_OUT},
        {"AUOMS_PROCESS_INVENTORY", RecordType::AUOMS_PROCESS_INVENTORY},
        {"AUOMS_SYSCALL", RecordType::AUOMS_SYSCALL},
        {"AUOMS_SYSCALL_FRAGMENT", RecordType::AUOMS_SYSCALL_FRAGMENT},
        {"AUOMS_COLLECTOR_REPORT", RecordType::AUOMS_COLLECTOR_REPORT},
        {"AUOMS_DROPPED_RECORDS", RecordType::AUOMS_DROPPED_RECORDS},
        {"AUOMS_STATUS", RecordType::AUOMS_STATUS},
        {"AUOMS_METRIC", RecordType::AUOMS_METRIC},
        {"AUOMS_AGGREGATE", RecordType::AUOMS_AGGREGATE},
        {"AUOMS_EXECVE", RecordType::AUOMS_EXECVE},
});

static StringTable<RecordTypeCategory> s_record_type_category_table(RecordTypeCategory::UNKNOWN, {
        {"UNKNOWN", RecordTypeCategory::UNKNOWN},
        {"KERNEL", RecordTypeCategory::KERNEL},
        {"USER_MSG", RecordTypeCategory::USER_MSG},
        {"DAEMON", RecordTypeCategory::DAEMON},
        {"EVENT", RecordTypeCategory::EVENT},
        {"SELINUX", RecordTypeCategory::SELINUX},
        {"APPARMOR", RecordTypeCategory::APPARMOR},
        {"KERN_CRYPTO_MSG", RecordTypeCategory::KERN_CRYPTO_MSG},
        {"KERN_ANOM_MSG", RecordTypeCategory::KERN_ANOM_MSG},
        {"INTEGRITY_MSG", RecordTypeCategory::INTEGRITY_MSG},
        {"ANOM_MSG", RecordTypeCategory::ANOM_MSG},
        {"ANOM_RESP", RecordTypeCategory::ANOM_RESP},
        {"USER_LSPP_MSG", RecordTypeCategory::USER_LSPP_MSG},
        {"CRYPTO_MSG", RecordTypeCategory::CRYPTO_MSG},
        {"VIRT_MSG", RecordTypeCategory::VIRT_MSG},
        {"USER_MSG2", RecordTypeCategory::USER_MSG2},
        {"AUOMS_MSG", RecordTypeCategory::AUOMS_MSG},
});

std::string_view RecordTypeToName(RecordType code, std::string& unknown_str) {
    auto str = s_record_type_table.ToString(code);
    if (str.empty()) {
        unknown_str = "UNKNOWN[" + std::to_string(static_cast<int>(code)) + "]";
        str = unknown_str;
    }
    return str;
}

std::string RecordTypeToName(RecordType code) {
    std::string str(s_record_type_table.ToString(code));
    if (str.empty()) {
        str = "UNKNOWN[" + std::to_string(static_cast<int>(code)) + "]";
    }
    return str;
}

RecordType RecordNameToType(const std::string_view& name) {
    using namespace std::string_view_literals;

    static auto SV_UNKNOWN = "UNKNOWN["sv;

    if (name.size() > 9 && starts_with(name, SV_UNKNOWN) && name[name.size()-1] == ']') {
        try {
            auto id = std::stoul(std::string(name.substr(8, name.size()-9)));
            RecordType rc = static_cast<RecordType>(id);
            if (s_record_type_table.ToString(rc).empty()) {
                return RecordType::UNKNOWN;
            }
            return rc;
        } catch (std::exception&) {
            return RecordType::UNKNOWN;
        }
    } else {
        return s_record_type_table.ToInt(name);
    }
}

std::string RecordTypeCategoryToName(RecordTypeCategory code) {
    std::string str(s_record_type_category_table.ToString(code));
    if (str.empty()) {
        str = "UNKNOWN";
    }
    return str;
}

RecordTypeCategory RecordTypeCategoryNameToCategory(const std::string_view& name) {
    return s_record_type_category_table.ToInt(name);
}
