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

std::vector<const char*> raw_test_events = {
        // Test normal EXECVE transform
        R"event(type=SYSCALL msg=audit(1521757638.392:262332): arch=c000003e syscall=59 success=yes exit=0 a0=55d782c96198 a1=55d782c96120 a2=55d782c96158 a3=1 items=2 ppid=26595 pid=26918 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=842 comm="logger" exe="/usr/bin/logger" key=(null)
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
        R"event(type=LOGIN msg=audit(1521757801.424:262683): pid=27127 uid=0 old-auid=4294967295 auid=0 old-ses=4294967295 ses=844 res=1
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
                //{"path_name", "[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_nametype", "[\"NORMAL\",\"NORMAL\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_mode", "[\"0100755\",\"0100755\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_ouid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_ogid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                // EXECVE
                {"argc", "6", nullptr, field_type_t::UNCLASSIFIED},
                {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, field_type_t::UNCLASSIFIED},
            }}}
        },
        {1521757638, 392, 262333, 1, 26918, {
            {static_cast<uint32_t>(RecordType::AUOMS_EXECVE), "AUOMS_EXECVE", "", {
                // SYSCALL
                {"arch", "c000003e", "x86_64", field_type_t::ARCH},
                {"syscall", "59", "execve", field_type_t::SYSCALL},
                {"success", "yes", nullptr, field_type_t::UNCLASSIFIED},
                {"exit", "0", nullptr, field_type_t::EXIT},
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
                {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, field_type_t::UNCLASSIFIED},
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
                //{"path_name", "[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_nametype", "[\"NORMAL\",\"NORMAL\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_mode", "[\"0100755\",\"0100755\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_ouid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                //{"path_ogid", "[\"0\",\"0\"]", nullptr, field_type_t::UNCLASSIFIED},
                // EXECVE
                {"argc", "6", nullptr, field_type_t::UNCLASSIFIED},
                {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, field_type_t::UNCLASSIFIED},
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
};
/*
const std::vector<const char*> oms_test_events = {
    R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262332,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"(null)","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","path_name":"[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]","path_nametype":"[\"NORMAL\",\"NORMAL\"]","path_mode":"[\"0100755\",\"0100755\"]","path_ouid":"[\"0\",\"0\"]","path_ogid":"[\"0\",\"0\"]","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
    R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262333,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"(null)","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
    R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262334,"ProcessFlags":0,"records":[{"RecordTypeCode":10002,"RecordType":"AUOMS_SYSCALL_FRAGMENT","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","path_name":"[\"/usr/bin/logger\",\"/lib64/ld-linux-x86-64.so.2\"]","path_nametype":"[\"NORMAL\",\"NORMAL\"]","path_mode":"[\"0100755\",\"0100755\"]","path_ouid":"[\"0\",\"0\"]","path_ogid":"[\"0\",\"0\"]","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
};
*/
const std::vector<const char*> oms_test_events = {
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262332,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"(null)","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262333,"ProcessFlags":0,"records":[{"RecordTypeCode":14688,"RecordType":"AUOMS_EXECVE","arch":"x86_64","syscall":"execve","success":"yes","exit":"0","ppid":"26595","pid":"26918","audit_user":"root","auid":"0","user":"root","uid":"0","group":"root","gid":"0","effective_user":"root","euid":"0","set_user":"root","suid":"0","filesystem_user":"root","fsuid":"0","effective_group":"root","egid":"0","set_group":"root","sgid":"0","filesystem_group":"root","fsgid":"0","tty":"(none)","ses":"842","comm":"logger","exe":"/usr/bin/logger","key":"(null)","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
        R"event([1521757638.392,{"MessageType":"AUOMS_EVENT","Timestamp":"1521757638.392","SerialNumber":262334,"ProcessFlags":0,"records":[{"RecordTypeCode":10002,"RecordType":"AUOMS_SYSCALL_FRAGMENT","cwd":"/","name":"/usr/bin/logger","inode":"312545","dev":"00:13","mode":"file,755","o_user":"root","ouid":"0","owner_group":"root","ogid":"0","rdev":"00:00","nametype":"NORMAL","argc":"6","cmdline":"logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \""}]}])event",
};