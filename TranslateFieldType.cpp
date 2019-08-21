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

#include <algorithm>

static StringTable<field_type_t> s_field_table(field_type_t::UNCLASSIFIED, {
        {"auid", field_type_t::UID},
        {"uid", field_type_t::UID},
        {"euid", field_type_t::UID},
        {"suid", field_type_t::UID},
        {"fsuid", field_type_t::UID},
        {"ouid", field_type_t::UID},
        {"oauid", field_type_t::UID},
        {"old-auid", field_type_t::UID},
        {"iuid", field_type_t::UID},
        {"id", field_type_t::UID},
        {"inode_uid", field_type_t::UID},
        {"sauid", field_type_t::UID},
        {"obj_uid", field_type_t::UID},
        {"obj_gid", field_type_t::GID},
        {"gid", field_type_t::GID},
        {"egid", field_type_t::GID},
        {"sgid", field_type_t::GID},
        {"fsgid", field_type_t::GID},
        {"ogid", field_type_t::GID},
        {"igid", field_type_t::GID},
        {"inode_gid", field_type_t::GID},
        {"new_gid", field_type_t::GID},
        {"syscall", field_type_t::SYSCALL},
        {"arch", field_type_t::ARCH},
        {"exit", field_type_t::EXIT},
        {"path", field_type_t::ESCAPED},
        {"comm", field_type_t::ESCAPED},
        {"exe", field_type_t::ESCAPED},
        {"file", field_type_t::ESCAPED},
        {"name", field_type_t::ESCAPED},
        {"watch", field_type_t::ESCAPED},
        {"cwd", field_type_t::ESCAPED},
        {"cmd", field_type_t::ESCAPED},
        {"acct", field_type_t::ESCAPED},
        {"dir", field_type_t::ESCAPED},
        {"key", field_type_t::ESCAPED_KEY},
        {"vm", field_type_t::ESCAPED},
        {"old-chardev", field_type_t::ESCAPED},
        {"new-chardev", field_type_t::ESCAPED},
        {"old-disk", field_type_t::ESCAPED},
        {"new-disk", field_type_t::ESCAPED},
        {"old-fs", field_type_t::ESCAPED},
        {"new-fs", field_type_t::ESCAPED},
        {"old-net", field_type_t::ESCAPED},
        {"new-net", field_type_t::ESCAPED},
        {"device", field_type_t::ESCAPED},
        {"cgroup", field_type_t::ESCAPED},
        {"perm", field_type_t::PERM},
        {"perm_mask", field_type_t::PERM},
        {"mode", field_type_t::MODE},
        {"saddr", field_type_t::SOCKADDR},
        {"prom", field_type_t::PROMISC},
        {"old_prom", field_type_t::PROMISC},
        {"capability", field_type_t::CAPABILITY},
        {"res", field_type_t::SUCCESS},
        {"result", field_type_t::SUCCESS},
        {"a0", field_type_t::A0},
        {"a1", field_type_t::A1},
        {"a2", field_type_t::A2},
        {"a3", field_type_t::A3},
        {"sig", field_type_t::SIGNAL},
        {"list", field_type_t::LIST},
        {"data", field_type_t::TTY_DATA},
        {"ses", field_type_t::SESSION},
        {"old-ses", field_type_t::SESSION},
        {"cap_pi", field_type_t::CAP_BITMAP},
        {"cap_pe", field_type_t::CAP_BITMAP},
        {"cap_pp", field_type_t::CAP_BITMAP},
        {"cap_fi", field_type_t::CAP_BITMAP},
        {"cap_fp", field_type_t::CAP_BITMAP},
        {"fp", field_type_t::CAP_BITMAP},
        {"fi", field_type_t::CAP_BITMAP},
        {"fe", field_type_t::CAP_BITMAP},
        {"old_pp", field_type_t::CAP_BITMAP},
        {"old_pi", field_type_t::CAP_BITMAP},
        {"old_pe", field_type_t::CAP_BITMAP},
        {"new_pp", field_type_t::CAP_BITMAP},
        {"new_pi", field_type_t::CAP_BITMAP},
        {"new_pe", field_type_t::CAP_BITMAP},
        {"family", field_type_t::NFPROTO},
        {"icmptype", field_type_t::ICMPTYPE},
        {"proto", field_type_t::PROTOCOL},
        {"addr", field_type_t::ADDR},
        {"apparmor", field_type_t::ESCAPED},
        {"operation", field_type_t::ESCAPED},
        {"denied_mask", field_type_t::ESCAPED},
        {"info", field_type_t::ESCAPED},
        {"profile", field_type_t::ESCAPED},
        {"requested_mask", field_type_t::ESCAPED},
        {"per", field_type_t::PERSONALITY},
        {"code", field_type_t::SECCOMP},
        {"old-rng", field_type_t::ESCAPED},
        {"new-rng", field_type_t::ESCAPED},
        {"oflag", field_type_t::OFLAG},
        {"ocomm", field_type_t::ESCAPED},
        {"flags", field_type_t::MMAP},
        {"sigev_signo", field_type_t::SIGNAL},
        {"subj", field_type_t::MAC_LABEL},
        {"obj", field_type_t::MAC_LABEL},
        {"scontext", field_type_t::MAC_LABEL},
        {"tcontext", field_type_t::MAC_LABEL},
        {"vm-ctx", field_type_t::MAC_LABEL},
        {"img-ctx", field_type_t::MAC_LABEL},
        {"proctitle", field_type_t::PROCTITLE},
        {"grp", field_type_t::ESCAPED},
        {"new_group", field_type_t::ESCAPED},
        {"hook", field_type_t::HOOK},
        {"action", field_type_t::NETACTION},
        {"macproto", field_type_t::MACPROTO},
        {"invalid_context", field_type_t::ESCAPED},
        {"ioctlcmd", field_type_t::IOCTL_REQ},
        {"SV_INTEGRITY_HASH", field_type_t::ESCAPED},
});

field_type_t FieldNameToType(const std::string_view& name) {
    return s_field_table.ToInt(name);
}

field_type_t FieldNameToType(RecordType rtype, const std::string_view& name, const std::string_view& val) {
    using namespace std::string_view_literals;

    static auto SV_ARGC = "argc"sv;
    static auto SV__LEN = "_len"sv;
    static auto SV_SADDR = "saddr"sv;
    static auto SV_MSG = "msg"sv;
    static auto SV_FLAGS = "flags"sv;
    static auto SV_MODE = "mode"sv;
    static auto SV_FP = "fp"sv;
    static auto SV_ID = "id"sv;
    static auto SV_ACCT = "acct"sv;

    field_type_t ftype = field_type_t::UNKNOWN;
    switch (rtype) {
        case RecordType::EXECVE:
            if (name[0] == 'a' && !starts_with(name, SV_ARGC) && !ends_with(name, SV__LEN)) {
                ftype = field_type_t::ESCAPED;
            }
            break;
        case RecordType::AVC:
            if (name == SV_SADDR) {
                ftype = field_type_t::UNCLASSIFIED;
            }
            break;
        case RecordType::USER_TTY:
            if (name == SV_MSG) {
                ftype = field_type_t::ESCAPED;
            }
            break;
        case RecordType::NETFILTER_PKT:
            if (name == SV_SADDR) {
                ftype = field_type_t::ADDR;
            }
            break;
        case RecordType::PATH:
            if (name == SV_FLAGS) {
                ftype = field_type_t::FLAGS;
            }
            break;
        case RecordType::MQ_OPEN:
            if (name == SV_MODE) {
                ftype = field_type_t::MODE_SHORT;
            }
            break;
        case RecordType::CRYPTO_KEY_USER:
            if (name == SV_FP) {
                ftype = field_type_t::UNCLASSIFIED;
            }
            break;
        case RecordType::ADD_GROUP:
            // fallthrough
        case RecordType::GRP_MGMT:
            // fallthrough
        case RecordType::DEL_GROUP:
            if (name == SV_ID) {
                ftype = field_type_t::GID;
            }
            break;
        default:
            if (name == SV_ACCT) {
                if (val[0] == '"' || std::all_of(val.begin(), val.end(), [](unsigned char c) { return std::isxdigit(c); })) {
                    ftype = field_type_t::ESCAPED;
                } else {
                    ftype = field_type_t::UNCLASSIFIED;
                }
            }
            break;
    }

    if (ftype == field_type_t::UNKNOWN) {
        ftype = FieldNameToType(name);
    }

    return ftype;
}
