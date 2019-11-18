/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "TestEventData.h"
#include "RecordType.h"

const std::string passwd_file_text = R"passwd(
root:x:0:0:root:/root:/bin/bash
_chrony:x:123:132:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
user:x:1000:1000:User,,,:/home/user:/bin/bash
)passwd";

const std::string group_file_text = R"group(
root:x:0:
adm:x:4:user
_chrony:x:132:
nogroup:x:65534:
user:x:1000:
)group";

std::vector<const char*> raw_test_events = {
        // Test normal EXECVE transform
        R"event(type=SYSCALL msg=audit(1521757638.392:262332): arch=c000003e syscall=59 success=yes exit=0 a0=55d782c96198 a1=55d782c96120 a2=55d782c96158 a3=1 items=2 ppid=26595 pid=26918 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=842 comm="logger" exe="/usr/bin/logger" key=61756F6D7301657865637665
type=EXECVE msg=audit(1521757638.392:262332): argc=6 a0="logger" a1="-t" a2="zfs-backup" a3="-p" a4="daemon.err" a5=7A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
type=CWD msg=audit(1521757638.392:262332):  cwd="/"
type=PATH msg=audit(1521757638.392:262332): item=0 name="/usr/bin/logger" inode=312545 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1521757638.392:262332): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=370637 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1521757638.392:262332): proctitle=6C6F67676572002D74007A66732D6261636B7570002D70006461656D6F6E2E657272007A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
type=EOE msg=audit(1521757638.392:262332):
)event",
        // Test fragment part 1
        R"event(type=SYSCALL msg=audit(1521757638.392:262333): arch=c000003e syscall=59 success=yes exit=0 a0=55d782c96198 a1=55d782c96120 a2=55d782c96158 a3=1 items=2 ppid=26595 pid=26918 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=842 comm="logger" exe="/usr/bin/logger" key=(null)
type=EXECVE msg=audit(1521757638.392:262333): argc=6 a0="logger" a1="-t" a2="zfs-backup" a3="-p" a4="daemon.err" a5=7A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
)event",
        // Test fragment part 2 (must follow immediatly after part 1)
        R"event(type=EXECVE msg=audit(1521757638.392:262334): argc=6 a0="logger" a1="-t" a2="zfs-backup" a3="-p" a4="daemon.err" a5=7A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
node=test type=CWD msg=audit(1521757638.392:262334): cwd="/"
type=PATH msg=audit(1521757638.392:262334): item=0 name="/usr/bin/logger" inode=312545 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1521757638.392:262334): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=370637 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1521757638.392:262334): proctitle=6C6F67676572002D74007A66732D6261636B7570002D70006461656D6F6E2E657272007A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
type=EOE msg=audit(1521757638.392:262334):
)event",
        // Test to make sure pid gets reset from previous event
        R"event(type=BPRM_FCAPS msg=audit(1521773704.435:270957): fver=0 fp=0000000000000000 fi=0000000000000000 fe=0 old_pp=0000000000000000 old_pi=0000000000000000 old_pe=0000000000000000 new_pp=0000003fffffffff new_pi=0000000000000000 new_pe=0000003fffffffff
)event",
        R"event(type=USER_LOGIN msg=audit(1562867403.686:4179743): pid=26475 uid=0 auid=1000 ses=91158 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=131.107.147.6 addr=131.107.147.6 terminal=/dev/pts/0 res=success'
)event",
        R"event(type=LOGIN msg=audit(1521757801.424:262683): pid=27127 uid=0 old-auid=4294967295 auid=0 old-ses=4294967295 ses=844 res=1
)event",
        R"event(type=SYSCALL msg=audit(1563459621.014:574): arch=c000003e syscall=159 success=yes exit=0 a0=7ffc9aa65d80 a1=0 a2=270b a3=7ffc9aa65e40 items=0 ppid=1 pid=1655 auid=4294967295 uid=123 gid=132 euid=123 suid=123 fsuid=123 egid=132 sgid=132 fsgid=132 tty=(none) ses=4294967295 comm="chronyd" exe="/usr/sbin/chronyd" key="time-change"
type=PROCTITLE msg=audit(1563459621.014:574): proctitle="/usr/sbin/chronyd"
)event",
        R"event(type=SYSCALL msg=audit(1563470055.872:7605215): arch=c000003e syscall=59 success=yes exit=0 a0=ad1150 a1=ad03d0 a2=ad0230 a3=fc2c9fc5 items=2 ppid=16244 pid=91098 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="iptables" exe="/usr/sbin/xtables-multi" key="auoms"
type=EXECVE msg=audit(1563470055.872:7605215): argc=5 a0="iptables" a1="-w" a2="-t" a3="security" a4="--flush"
type=CWD msg=audit(1563470055.872:7605215):  cwd="/var/lib/waagent"
type=PATH msg=audit(1563470055.872:7605215): item=0 name="/usr/sbin/iptables" inode=1579593 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1563470055.872:7605215): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=1048670 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=UNKNOWN[1327] msg=audit(1563470055.872:7605215): proctitle=2F62696E2F7368002D630069707461626C6573202D77202D74207365637572697479202D2D666C757368
)event",
        R"event(type=NETFILTER_CFG msg=audit(1563470055.876:7605216): table=security family=2 entries=4
type=SYSCALL msg=audit(1563470055.876:7605216): arch=c000003e syscall=54 success=yes exit=0 a0=4 a1=0 a2=40 a3=c31600 items=0 ppid=16244 pid=91098 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="iptables" exe="/usr/sbin/xtables-multi" key=(null)
type=UNKNOWN[1327] msg=audit(1563470055.876:7605216): proctitle=2F62696E2F7368002D630069707461626C6573202D77202D74207365637572697479202D2D666C757368
)event",
        R"event(type=SYSCALL audit(1572298453.690:5717): arch=c00000b7 syscall=222 success=yes exit=281129964019712 a0=0 a1=16a048 a2=5 a3=802 items=0 ppid=1 pid=1450 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="agetty" exe="/usr/sbin/agetty" key=(null)
type=INTEGRITY_POLICY_RULE audit(1572298453.690:5717): IPE=ctx ( op: [execute] dmverity_verified: [false] boot_verified: [true] audit_pathname: [/usr/lib/libc-2.28.so] )  [ action = allow ] [ boot_verified = true ]
)event",
};

const std::vector<TestEvent> test_events {
        {1521757638, 392, 262332, 1, 26918, {
            {static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", {
                // SYSCALL
                {"arch", "c000003e", "x86_64", field_type_t::ARCH},
                {"syscall", "59", "execve", field_type_t::SYSCALL},
                {"success", "yes", nullptr, field_type_t::UNCLASSIFIED},
                {"exit", "0", nullptr, field_type_t::EXIT},
                {"a0", "55d782c96198", nullptr, field_type_t::A0},
                {"a1", "55d782c96120", nullptr, field_type_t::A1},
                {"a2", "55d782c96158", nullptr, field_type_t::A2},
                {"a3", "1", nullptr, field_type_t::A3},
                {"ppid", "26595", nullptr, field_type_t::UNCLASSIFIED},
                {"pid", "26918", nullptr, field_type_t::UNCLASSIFIED},
                {"auid", "0", "root", field_type_t::UID},
                {"uid", "0", "root", field_type_t::UID},
                {"gid", "0", "root", field_type_t::GID},
                {"euid", "0", "root", field_type_t::UID},
                {"suid", "0", "root", field_type_t::UID},
                {"fsuid", "0", "root", field_type_t::UID},
                {"egid", "0", "root", field_type_t::GID},
                {"sgid", "0", "root", field_type_t::GID},
                {"fsgid", "0", "root", field_type_t::GID},
                {"tty", "(none)", nullptr, field_type_t::UNCLASSIFIED},
                {"ses", "842", nullptr, field_type_t::SESSION},
                {"comm", "\"logger\"", nullptr, field_type_t::ESCAPED},
                {"exe", "\"/usr/bin/logger\"", nullptr, field_type_t::ESCAPED},
                {"key", "61756F6D7301657865637665", "auoms,execve", field_type_t::ESCAPED_KEY},
                // CWD
                {"cwd", "\"/\"", nullptr, field_type_t::ESCAPED},
                // PATH
                {"name", "\"/usr/bin/logger\"", nullptr, field_type_t::ESCAPED},
                {"inode", "312545", nullptr, field_type_t::UNCLASSIFIED},
                {"dev", "00:13", nullptr, field_type_t::UNCLASSIFIED},
                {"mode", "0100755", "file,755", field_type_t::MODE},
                {"ouid", "0", "root", field_type_t::UID},
                {"ogid", "0", "root", field_type_t::GID},
                {"rdev", "00:00", nullptr, field_type_t::UNCLASSIFIED},
                {"nametype", "NORMAL", nullptr, field_type_t::UNCLASSIFIED},
                {"path_name", "[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_nametype", "[\"NORMAL\",\"NORMAL\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_mode", "[\"0100755\",\"0100755\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_ouid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_ogid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                // EXECVE
                {"argc", "6", nullptr, field_type_t::UNCLASSIFIED},
                {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, field_type_t::UNESCAPED},
            }}}
        },
        {1521757638, 392, 262333, 1, 26918, {
            {static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", {
                // SYSCALL
                {"arch", "c000003e", "x86_64", field_type_t::ARCH},
                {"syscall", "59", "execve", field_type_t::SYSCALL},
                {"success", "yes", nullptr, field_type_t::UNCLASSIFIED},
                {"exit", "0", nullptr, field_type_t::EXIT},
                {"a0", "55d782c96198", nullptr, field_type_t::A0},
                {"a1", "55d782c96120", nullptr, field_type_t::A1},
                {"a2", "55d782c96158", nullptr, field_type_t::A2},
                {"a3", "1", nullptr, field_type_t::A3},
                {"ppid", "26595", nullptr, field_type_t::UNCLASSIFIED},
                {"pid", "26918", nullptr, field_type_t::UNCLASSIFIED},
                {"auid", "0", "root", field_type_t::UID},
                {"uid", "0", "root", field_type_t::UID},
                {"gid", "0", "root", field_type_t::GID},
                {"euid", "0", "root", field_type_t::UID},
                {"suid", "0", "root", field_type_t::UID},
                {"fsuid", "0", "root", field_type_t::UID},
                {"egid", "0", "root", field_type_t::GID},
                {"sgid", "0", "root", field_type_t::GID},
                {"fsgid", "0", "root", field_type_t::GID},
                {"tty", "(none)", nullptr, field_type_t::UNCLASSIFIED},
                {"ses", "842", nullptr, field_type_t::SESSION},
                {"comm", "\"logger\"", nullptr, field_type_t::ESCAPED},
                {"exe", "\"/usr/bin/logger\"", nullptr, field_type_t::ESCAPED},
                {"key", "(null)", nullptr, field_type_t::ESCAPED_KEY},
                // EXECVE
                {"argc", "6", nullptr, field_type_t::UNCLASSIFIED},
                {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, field_type_t::UNESCAPED},
            }}}
        },
        {1521757638, 392, 262334, 1, -1, {
            {static_cast<uint32_t>(RecordType::AUOMS_SYSCALL_FRAGMENT), "AUOMS_SYSCALL_FRAGMENT", "", {
                // CWD
                {"cwd", "\"/\"", nullptr, field_type_t::ESCAPED},
                // PATH
                {"name", "\"/usr/bin/logger\"", nullptr, field_type_t::ESCAPED},
                {"inode", "312545", nullptr, field_type_t::UNCLASSIFIED},
                {"dev", "00:13", nullptr, field_type_t::UNCLASSIFIED},
                {"mode", "0100755", "file,755", field_type_t::MODE},
                {"ouid", "0", "root", field_type_t::UID},
                {"ogid", "0", "root", field_type_t::GID},
                {"rdev", "00:00", nullptr, field_type_t::UNCLASSIFIED},
                {"nametype", "NORMAL", nullptr, field_type_t::UNCLASSIFIED},
                {"path_name", "[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_nametype", "[\"NORMAL\",\"NORMAL\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_mode", "[\"0100755\",\"0100755\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_ouid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_ogid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                // EXECVE
                {"argc", "6", nullptr, field_type_t::UNCLASSIFIED},
                {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, field_type_t::UNESCAPED},
            }}}
        },
        {1521773704, 435, 270957, 0, -1, {
            {1321, "BPRM_FCAPS", "type=BPRM_FCAPS msg=audit(1521773704.435:270957): fver=0 fp=0000000000000000 fi=0000000000000000 fe=0 old_pp=0000000000000000 old_pi=0000000000000000 old_pe=0000000000000000 new_pp=0000003fffffffff new_pi=0000000000000000 new_pe=0000003fffffffff", {
                {"fver", "0", nullptr, field_type_t::UNCLASSIFIED},
                {"fp", "0000000000000000", nullptr, field_type_t::CAP_BITMAP},
                {"fi", "0000000000000000", nullptr, field_type_t::CAP_BITMAP},
                {"fe", "0", nullptr, field_type_t::CAP_BITMAP},
                {"old_pp", "0000000000000000", nullptr, field_type_t::CAP_BITMAP},
                {"old_pi", "0000000000000000", nullptr, field_type_t::CAP_BITMAP},
                {"old_pe", "0000000000000000", nullptr, field_type_t::CAP_BITMAP},
                {"new_pp", "0000003fffffffff", nullptr, field_type_t::CAP_BITMAP},
                {"new_pi", "0000000000000000", nullptr, field_type_t::CAP_BITMAP},
                {"new_pe", "0000003fffffffff", nullptr, field_type_t::CAP_BITMAP},
            }}}
        },
        {1562867403, 686, 4179743, 0, 26475, {
            {1112, "USER_LOGIN", "type=USER_LOGIN msg=audit(1562867403.686:4179743): pid=26475 uid=0 auid=1000 ses=91158 msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=131.107.147.6 addr=131.107.147.6 terminal=/dev/pts/0 res=success'", {
                {"pid", "26475", nullptr, field_type_t::UNCLASSIFIED},
                {"uid", "0", "root", field_type_t::UID},
                {"auid", "1000", "user", field_type_t::UID},
                {"ses", "91158", nullptr, field_type_t::SESSION},
                {"op", "login", nullptr, field_type_t::UNCLASSIFIED},
                {"id", "1000", "user", field_type_t::UID},
                {"exe", "\"/usr/sbin/sshd\"", nullptr, field_type_t::ESCAPED},
                {"hostname", "131.107.147.6", nullptr, field_type_t::UNCLASSIFIED},
                {"addr", "131.107.147.6", nullptr, field_type_t::ADDR},
                {"terminal", "/dev/pts/0", nullptr, field_type_t::UNCLASSIFIED},
                {"res", "success", nullptr, field_type_t::SUCCESS},
            }}}
        },
        {1521757801, 424, 262683, 0, 27127, {
            {1006, "LOGIN", "type=LOGIN msg=audit(1521757801.424:262683): pid=27127 uid=0 old-auid=4294967295 auid=0 old-ses=4294967295 ses=844 res=1", {
                {"pid", "27127", nullptr, field_type_t::UNCLASSIFIED},
                {"uid", "0", "root", field_type_t::UID},
                {"old-auid", "4294967295", "unset", field_type_t::UID},
                {"auid", "0", "root", field_type_t::UID},
                {"old-ses", "4294967295", "unset", field_type_t::SESSION},
                {"ses", "844", nullptr, field_type_t::SESSION},
                {"res", "1", nullptr, field_type_t::SUCCESS},
            }}}
        },
        {1563459621, 14, 574, 1, 1655, {
            {static_cast<uint32_t>(RecordType::AUOMS_SYSCALL), "AUOMS_SYSCALL", "", {
                // SYSCALL
                {"arch", "c000003e", "x86_64", field_type_t::ARCH},
                {"syscall", "159", "adjtimex", field_type_t::SYSCALL},
                {"success", "yes", nullptr, field_type_t::UNCLASSIFIED},
                {"exit", "0", nullptr, field_type_t::EXIT},
                {"a0", "7ffc9aa65d80", nullptr, field_type_t::A0},
                {"a1", "0", nullptr, field_type_t::A1},
                {"a2", "270b", nullptr, field_type_t::A2},
                {"a3", "7ffc9aa65e40", nullptr, field_type_t::A3},
                {"ppid", "1", nullptr, field_type_t::UNCLASSIFIED},
                {"pid", "1655", nullptr, field_type_t::UNCLASSIFIED},
                {"auid", "4294967295", "unset", field_type_t::UID},
                {"uid", "123", "_chrony", field_type_t::UID},
                {"gid", "132", "_chrony", field_type_t::GID},
                {"euid", "123", "_chrony", field_type_t::UID},
                {"suid", "123", "_chrony", field_type_t::UID},
                {"fsuid", "123", "_chrony", field_type_t::UID},
                {"egid", "132", "_chrony", field_type_t::GID},
                {"sgid", "132", "_chrony", field_type_t::GID},
                {"fsgid", "132", "_chrony", field_type_t::GID},
                {"tty", "(none)", nullptr, field_type_t::UNCLASSIFIED},
                {"ses", "4294967295", "unset", field_type_t::SESSION},
                {"comm", "\"chronyd\"", nullptr, field_type_t::ESCAPED},
                {"exe", "\"/usr/sbin/chronyd\"", nullptr, field_type_t::ESCAPED},
                {"key", "\"time-change\"", "time-change", field_type_t::ESCAPED_KEY},
                {"proctitle", "/usr/sbin/chronyd", nullptr, field_type_t::PROCTITLE},
            }}}
        },
        {1563470055, 872, 7605215, 1, 91098, {
            {static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", {
                // SYSCALL
                {"arch", "c000003e", "x86_64", field_type_t::ARCH},
                {"syscall", "59", "execve", field_type_t::SYSCALL},
                {"success", "yes", nullptr, field_type_t::UNCLASSIFIED},
                {"exit", "0", nullptr, field_type_t::EXIT},
                {"a0", "ad1150", nullptr, field_type_t::A0},
                {"a1", "ad03d0", nullptr, field_type_t::A1},
                {"a2", "ad0230", nullptr, field_type_t::A2},
                {"a3", "fc2c9fc5", nullptr, field_type_t::A3},
                {"ppid", "16244", nullptr, field_type_t::UNCLASSIFIED},
                {"pid", "91098", nullptr, field_type_t::UNCLASSIFIED},
                {"auid", "4294967295", "unset", field_type_t::UID},
                {"uid", "0", "root", field_type_t::UID},
                {"gid", "0", "root", field_type_t::GID},
                {"euid", "0", "root", field_type_t::UID},
                {"suid", "0", "root", field_type_t::UID},
                {"fsuid", "0", "root", field_type_t::UID},
                {"egid", "0", "root", field_type_t::GID},
                {"sgid", "0", "root", field_type_t::GID},
                {"fsgid", "0", "root", field_type_t::GID},
                {"tty", "(none)", nullptr, field_type_t::UNCLASSIFIED},
                {"ses", "4294967295", "unset", field_type_t::SESSION},
                {"comm", "\"iptables\"", nullptr, field_type_t::ESCAPED},
                {"exe", "\"/usr/sbin/xtables-multi\"", nullptr, field_type_t::ESCAPED},
                {"key", "\"auoms\"", "auoms", field_type_t::ESCAPED_KEY},
                // CWD
                {"cwd", "\"/var/lib/waagent\"", nullptr, field_type_t::ESCAPED},
                // PATH
                {"name", "\"/usr/sbin/iptables\"", nullptr, field_type_t::ESCAPED},
                {"inode", "1579593", nullptr, field_type_t::UNCLASSIFIED},
                {"dev", "08:02", nullptr, field_type_t::UNCLASSIFIED},
                {"mode", "0100755", "file,755", field_type_t::MODE},
                {"ouid", "0", "root", field_type_t::UID},
                {"ogid", "0", "root", field_type_t::GID},
                {"rdev", "00:00", nullptr, field_type_t::UNCLASSIFIED},
                {"nametype", "NORMAL", nullptr, field_type_t::UNCLASSIFIED},
                {"path_name", "[\"/usr/sbin/iptables\",\"/lib64/ld-linux-x86-64.so.2\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_nametype", "[\"NORMAL\",\"NORMAL\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_mode", "[\"0100755\",\"0100755\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_ouid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                {"path_ogid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                // EXECVE
                {"argc", "5", nullptr, field_type_t::UNCLASSIFIED},
                {"cmdline", "iptables -w -t security --flush", nullptr, field_type_t::UNESCAPED},
            }}}
        },
        {1563470055, 876, 7605216, 1, 91098, {
            {static_cast<uint32_t>(RecordType::AUOMS_SYSCALL), "AUOMS_SYSCALL", "", {
                // SYSCALL
                {"arch", "c000003e", "x86_64", field_type_t::ARCH},
                {"syscall", "54", "setsockopt", field_type_t::SYSCALL},
                {"success", "yes", nullptr, field_type_t::UNCLASSIFIED},
                {"exit", "0", nullptr, field_type_t::EXIT},
                {"a0", "4", nullptr, field_type_t::A0},
                {"a1", "0", nullptr, field_type_t::A1},
                {"a2", "40", nullptr, field_type_t::A2},
                {"a3", "c31600", nullptr, field_type_t::A3},
                {"ppid", "16244", nullptr, field_type_t::UNCLASSIFIED},
                {"pid", "91098", nullptr, field_type_t::UNCLASSIFIED},
                {"auid", "4294967295", "unset", field_type_t::UID},
                {"uid", "0", "root", field_type_t::UID},
                {"gid", "0", "root", field_type_t::GID},
                {"euid", "0", "root", field_type_t::UID},
                {"suid", "0", "root", field_type_t::UID},
                {"fsuid", "0", "root", field_type_t::UID},
                {"egid", "0", "root", field_type_t::GID},
                {"sgid", "0", "root", field_type_t::GID},
                {"fsgid", "0", "root", field_type_t::GID},
                {"tty", "(none)", nullptr, field_type_t::UNCLASSIFIED},
                {"ses", "4294967295", "unset", field_type_t::SESSION},
                {"comm", "\"iptables\"", nullptr, field_type_t::ESCAPED},
                {"exe", "\"/usr/sbin/xtables-multi\"", nullptr, field_type_t::ESCAPED},
                {"key", "(null)", nullptr, field_type_t::ESCAPED_KEY},
                {"proctitle", "/bin/sh -c \"iptables -w -t security --flush\"", nullptr, field_type_t::PROCTITLE},
                {"NETFILTER_CFG_table", "security", nullptr, field_type_t::UNCLASSIFIED},
                {"NETFILTER_CFG_family", "2", nullptr, field_type_t::NFPROTO},
                {"NETFILTER_CFG_entries", "4", nullptr, field_type_t::UNCLASSIFIED},
            }}}
        },
        {1572298453, 690, 5717, 1, 1450, {
            {static_cast<uint32_t>(RecordType::AUOMS_SYSCALL), "AUOMS_SYSCALL", "", {
                // SYSCALL
                {"arch", "c00000b7", "aarch64", field_type_t::ARCH},
                {"syscall", "222", "mmap", field_type_t::SYSCALL},
                {"success", "yes", nullptr, field_type_t::UNCLASSIFIED},
                {"exit", "281129964019712", nullptr, field_type_t::EXIT},
                {"a0", "0", nullptr, field_type_t::A0},
                {"a1", "16a048", nullptr, field_type_t::A1},
                {"a2", "5", nullptr, field_type_t::A2},
                {"a3", "802", nullptr, field_type_t::A3},
                {"ppid", "1", nullptr, field_type_t::UNCLASSIFIED},
                {"pid", "1450", nullptr, field_type_t::UNCLASSIFIED},
                {"auid", "4294967295", "unset", field_type_t::UID},
                {"uid", "0", "root", field_type_t::UID},
                {"gid", "0", "root", field_type_t::GID},
                {"euid", "0", "root", field_type_t::UID},
                {"suid", "0", "root", field_type_t::UID},
                {"fsuid", "0", "root", field_type_t::UID},
                {"egid", "0", "root", field_type_t::GID},
                {"sgid", "0", "root", field_type_t::GID},
                {"fsgid", "0", "root", field_type_t::GID},
                {"tty", "(none)", nullptr, field_type_t::UNCLASSIFIED},
                {"ses", "4294967295", "unset", field_type_t::SESSION},
                {"comm", "\"agetty\"", nullptr, field_type_t::ESCAPED},
                {"exe", "\"/usr/sbin/agetty\"", nullptr, field_type_t::ESCAPED},
                {"key", "(null)", nullptr, field_type_t::ESCAPED_KEY},
                {"INTEGRITY_POLICY_RULE_unparsed_text", "IPE=ctx ( op: [execute] dmverity_verified: [false] boot_verified: [true] audit_pathname: [/usr/lib/libc-2.28.so] )  [ action = allow ] [ boot_verified = true ]", nullptr, field_type_t::UNESCAPED},
            }}}
        },
};
/*
const std::vector<const char*> oms_test_events = {
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262332,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"auoms,execve","key_r":"61756F6D7301657865637665","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262333,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"(null)","key_r":"(null)","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262334,"ProcessFlags":0,"records":[{"RecordTypeCode":10002,"RecordType":"AUOMS_SYSCALL_FRAGMENT","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1562867403.686,{"MessageType":"AUDIT_EVENT","Timestamp":"1562867403.686","SerialNumber":4179743,"ProcessFlags":0,"records":[{"RecordTypeCode":1112,"RecordType":"USER_LOGIN","pid":"26475","user":"root","uid":"0","audit_user":"user","auid":"1000","ses":"91158","op":"login","id":"user","id_r":"1000","exe":"/usr/sbin/sshd","hostname":"131.107.147.6","addr":"131.107.147.6","terminal":"/dev/pts/0","res":"success"}]}])event",
};
*/
const std::vector<const char*> oms_test_events = {
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262332,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","a0":"55d782c96198","a1":"55d782c96120","a2":"55d782c96158","a3":"1","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"auoms,execve","key_r":"61756F6D7301657865637665","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","path_name":"[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]","path_nametype":"[\"NORMAL\",\"NORMAL\"]","path_mode":"[\"0100755\",\"0100755\"]","path_ouid":"[\"0\",\"0\"]","path_ogid":"[\"0\",\"0\"]","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262333,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","a0":"55d782c96198","a1":"55d782c96120","a2":"55d782c96158","a3":"1","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"(null)","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262334,"ProcessFlags":0,"records":[{"RecordTypeCode":10002,"RecordType":"AUOMS_SYSCALL_FRAGMENT","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","path_name":"[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]","path_nametype":"[\"NORMAL\",\"NORMAL\"]","path_mode":"[\"0100755\",\"0100755\"]","path_ouid":"[\"0\",\"0\"]","path_ogid":"[\"0\",\"0\"]","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1562867403.686,{"MessageType":"AUDIT_EVENT","Timestamp":"1562867403.686","SerialNumber":4179743,"ProcessFlags":0,"records":[{"RecordTypeCode":1112,"RecordType":"USER_LOGIN","pid":"26475","user":"root","uid":"0","audit_user":"user","auid":"1000","ses":"91158","op":"login","id":"user","id_r":"1000","exe":"/usr/sbin/sshd","hostname":"131.107.147.6","addr":"131.107.147.6","terminal":"/dev/pts/0","res":"success"}]}])event",
        R"event([1563459621.014,{"MessageType":"AUOMS_EVENT","Timestamp":"1563459621.014","SerialNumber":574,"ProcessFlags":0,"records":[{"RecordTypeCode":10001,"RecordType":"AUOMS_SYSCALL","arch":"x86_64","syscall":"adjtimex","success":"yes","exit":"0","a0":"7ffc9aa65d80","a1":"0","a2":"270b","a3":"7ffc9aa65e40","ppid":"1","pid":"1655","audit_user":"unset","auid":"4294967295","user":"_chrony","uid":"123","group":"_chrony","gid":"132","effective_user":"_chrony","euid":"123","set_user":"_chrony","suid":"123","filesystem_user":"_chrony","fsuid":"123","effective_group":"_chrony","egid":"132","set_group":"_chrony","sgid":"132","filesystem_group":"_chrony","fsgid":"132","tty":"(none)","ses":"-1","comm":"chronyd","exe":"/usr/sbin/chronyd","key":"time-change","key_r":"\"time-change\"","proctitle":"/usr/sbin/chronyd"}]}])event",
        R"event([1563470055.872,{"MessageType":"AUOMS_EVENT","Timestamp":"1563470055.872","SerialNumber":7605215,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","a0":"ad1150","a1":"ad03d0","a2":"ad0230","a3":"fc2c9fc5","ppid":"16244","pid":"91098","audit_user":"unset","auid":"4294967295","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"-1","comm":"iptables","exe":"/usr/sbin/xtables-multi","key":"auoms","key_r":"\"auoms\"","cwd":"/var/lib/waagent","name":"/usr/sbin/iptables","inode":"1579593","dev":"08:02","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","path_name":"[\"/usr/sbin/iptables\",\"/lib64/ld-linux-x86-64.so.2\"]","path_nametype":"[\"NORMAL\",\"NORMAL\"]","path_mode":"[\"0100755\",\"0100755\"]","path_ouid":"[\"0\",\"0\"]","path_ogid":"[\"0\",\"0\"]","argc":"5","cmdline":"iptables -w -t security --flush"}]}])event",
        R"event([1563470055.876,{"MessageType":"AUOMS_EVENT","Timestamp":"1563470055.876","SerialNumber":7605216,"ProcessFlags":0,"records":[{"RecordTypeCode":10001,"RecordType":"AUOMS_SYSCALL","arch":"x86_64","syscall":"setsockopt","success":"yes","exit":"0","a0":"4","a1":"0","a2":"40","a3":"c31600","ppid":"16244","pid":"91098","audit_user":"unset","auid":"4294967295","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"-1","comm":"iptables","exe":"/usr/sbin/xtables-multi","key":"(null)","proctitle":"/bin/sh -c \"iptables -w -t security --flush\"","NETFILTER_CFG_table":"security","NETFILTER_CFG_family":"2","NETFILTER_CFG_entries":"4"}]}])event",
        R"event([1572298453.69,{"MessageType":"AUOMS_EVENT","Timestamp":"1572298453.690","SerialNumber":5717,"ProcessFlags":0,"records":[{"RecordTypeCode":10001,"RecordType":"AUOMS_SYSCALL","arch":"aarch64","syscall":"mmap","success":"yes","exit":"281129964019712","a0":"0","a1":"16a048","a2":"5","a3":"802","ppid":"1","pid":"1450","audit_user":"unset","auid":"4294967295","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"-1","comm":"agetty","exe":"/usr/sbin/agetty","key":"(null)","INTEGRITY_POLICY_RULE_unparsed_text":"IPE=ctx ( op: [execute] dmverity_verified: [false] boot_verified: [true] audit_pathname: [/usr/lib/libc-2.28.so] )  [ action = allow ] [ boot_verified = true ]"}]}])event",
};
