//
// Created by tad on 3/22/18.
//

/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "AuditEventProcessor.h"
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "EventProcessorTests"
#include <boost/test/unit_test.hpp>

#include "Queue.h"
#include "Logger.h"
#include "TempDir.h"
#include <fstream>
#include <stdexcept>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

const std::string passwd_file_text = R"passwd(
root:x:0:0:root:/root:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
user:x:1000:1000:User,,,:/home/user:/bin/bash
)passwd";

const std::string group_file_text =
        "root:x:0:\n"
        "adm:x:4:user\n"
        "nogroup:x:65534:\n"
        "user:x:1000:\n";

void write_file(const std::string& path, const std::string& text) {
    std::ofstream out;
    out.exceptions(std::ofstream::failbit|std::ofstream::badbit|std::ofstream::eofbit);
    out.open(path);
    out << text;
    out.close();
}

class TestEventQueue: public IEventBuilderAllocator {
public:
    virtual int Allocate(void** data, size_t size) {
        _buffer.resize(size);
        *data = _buffer.data();
        return 1;
    }

    virtual int Commit() {
        _events.emplace_back(std::make_shared<std::vector<uint8_t>>(_buffer.begin(), _buffer.end()));
    }

    virtual int Rollback() {
        _buffer.resize(0);
    }

    size_t GetEventCount() {
        return _events.size();
    }

    Event GetEvent(int idx) {
        auto event = _events[idx];
        return Event(event->data(), event->size());
    }

private:
    std::vector<uint8_t> _buffer;
    std::vector<std::shared_ptr<std::vector<uint8_t>>> _events;
};

struct TestEventField {
    TestEventField(const char* name, const char* raw, const char* interp, event_field_type_t field_type) {
        _name = name;
        _raw = raw;
        _interp = interp;
        _field_type = field_type;
    }
    const char* _name;
    const char* _raw;
    const char* _interp;
    event_field_type_t _field_type;

    void Write(const std::shared_ptr<EventBuilder>& builder) {
        builder->AddField(_name, _raw, _interp, _field_type);
    }
};

struct TestEventRecord {
    TestEventRecord(uint32_t type, const char* name, const char* text, const std::vector<TestEventField>& fields): _fields(fields) {
        _type = type;
        _name = name;
        _text = text;
    }
    uint32_t _type;
    const char* _name;
    const char* _text;
    std::vector<TestEventField> _fields;

    void Write(const std::shared_ptr<EventBuilder>& builder) {
        builder->BeginRecord(_type, _name, _text, static_cast<uint16_t>(_fields.size()));
        for (auto field : _fields) {
            field.Write(builder);
        }
        builder->EndRecord();
    }
};

struct TestEvent {
    TestEvent(uint64_t seconds,
              uint32_t milliseconds,
              uint64_t serial,
              uint32_t flags,
              int32_t pid,
              const std::vector<TestEventRecord>& records): _records(records)
    {
        _seconds = seconds;
        _milliseconds = milliseconds;
        _serial = serial;
        _flags = flags;
        _pid = pid;
    }

    uint64_t _seconds;
    uint32_t _milliseconds;
    uint64_t _serial;

    uint32_t _flags;
    int32_t _pid;
    std::vector<TestEventRecord> _records;

    void Write(const std::shared_ptr<EventBuilder>& builder) {
        builder->BeginEvent(_seconds, _milliseconds, _serial, _records.size());
        builder->SetEventFlags(_flags);
        builder->SetEventPid(_pid);
        for (auto rec : _records) {
            rec.Write(builder);
        }
        builder->EndEvent();
    }
};

void diff_event(int idx, const Event& e, const Event& a) {
    std::stringstream msg;
    if (e.Seconds() != a.Seconds()) {
        msg << "Event["<<idx<<"] Seconds Mismatch: expected " << e.Seconds() << ", got " << a.Seconds();
        throw std::runtime_error(msg.str());
    }
    if (e.Milliseconds() != a.Milliseconds()) {
        msg << "Event["<<idx<<"] Milliseconds Mismatch: expected " << e.Milliseconds() << ", got " << a.Milliseconds();
        throw std::runtime_error(msg.str());
    }
    if (e.Serial() != a.Serial()) {
        msg << "Event["<<idx<<"] Serial Mismatch: expected " << e.Serial() << ", got " << a.Serial();
        throw std::runtime_error(msg.str());
    }
    if (e.Flags() != a.Flags()) {
        msg << "Event["<<idx<<"] Flags Mismatch: expected " << e.Flags() << ", got " << a.Flags();
        throw std::runtime_error(msg.str());
    }
    if (e.Pid() != a.Pid()) {
        msg << "Event["<<idx<<"] Pid Mismatch: expected " << e.Pid() << ", got " << a.Pid();
        throw std::runtime_error(msg.str());
    }

    if (e.NumRecords() != a.NumRecords()) {
        msg << "Event["<<idx<<"] NumRecords Mismatch: expected " << e.NumRecords() << ", got " << a.NumRecords();
        throw std::runtime_error(msg.str());
    }

    for (int r = 0; r < e.NumRecords(); ++r) {
        auto er = e.RecordAt(r);
        auto ar = a.RecordAt(r);

        if (er.RecordType() != ar.RecordType()) {
            msg << "Event["<<idx<<"].Record[" << r << "] RecordType Mismatch: expected " << er.RecordType() << ", got " << ar.RecordType();
            throw std::runtime_error(msg.str());
        }

        if (er.RecordTypeName() == nullptr || ar.RecordTypeName() == nullptr) {
            if (er.RecordTypeName() != ar.RecordTypeName()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected "
                    << (er.RecordTypeName() == nullptr ? "null" : er.RecordTypeName())
                    << ", got "
                    << (ar.RecordTypeName() == nullptr ? "null" : ar.RecordTypeName());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordTypeName(), ar.RecordTypeName()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected " << er.RecordTypeName() << ", got " << ar.RecordTypeName();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.RecordText() == nullptr || ar.RecordText() == nullptr) {
            if (er.RecordText() != ar.RecordText()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected "
                    << (er.RecordText() == nullptr ? "null" : er.RecordText())
                    << ", got "
                    << (ar.RecordText() == nullptr ? "null" : ar.RecordText());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordText(), ar.RecordText()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected " << er.RecordText() << ", got " << ar.RecordText();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.NumFields() != ar.NumFields()) {
            msg << "Event["<<idx<<"].Record[" << r << "] NumFields Mismatch: expected " << er.NumFields() << ", got " << ar.NumFields() << "\n";

            std::unordered_set<std::string> _en;
            std::unordered_set<std::string> _an;

            for (auto f : er) {
                _en.emplace(f.FieldName(), f.FieldNameSize());
            }

            for (auto f : ar) {
                _an.emplace(f.FieldName(), f.FieldNameSize());
            }

            for (auto name : _en) {
                if (_an.count(name) == 0) {
                    msg << "    Expected Field Name Not Found: " << name << "\n";
                }
            }

            for (auto name : _an) {
                if (_en.count(name) == 0) {
                    msg << "    Unxpected Field Name Found: " << name << "\n";
                }
            }

            throw std::runtime_error(msg.str());
        }

        for (int f = 0; f < er.NumFields(); ++f) {
            auto ef = er.FieldAt(f);
            auto af = ar.FieldAt(f);

            if (ef.FieldName() == nullptr || af.FieldName() == nullptr) {
                if (ef.FieldName() != af.FieldName()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected "
                        << (ef.FieldName() == nullptr ? "null" : ef.FieldName())
                        << ", got "
                        << (af.FieldName() == nullptr ? "null" : af.FieldName());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.FieldName(), af.FieldName()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected " << ef.FieldName() << ", got " << af.FieldName();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.RawValue() == nullptr || af.RawValue() == nullptr) {
                if (ef.RawValue() != af.RawValue()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected "
                        << (ef.RawValue() == nullptr ? "null" : ef.RawValue())
                        << ", got "
                        << (af.RawValue() == nullptr ? "null" : af.RawValue());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.RawValue(), af.RawValue()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected " << ef.RawValue() << ", got " << af.RawValue();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.InterpValue() == nullptr || af.InterpValue() == nullptr) {
                if (ef.InterpValue() != af.InterpValue()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] InterpValue Mismatch: expected "
                        << (ef.InterpValue() == nullptr ? "null" : ef.InterpValue())
                        << ", got "
                        << (af.InterpValue() == nullptr ? "null" : af.InterpValue());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.InterpValue(), af.InterpValue()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] InterpValue Mismatch: expected " << ef.InterpValue() << ", got " << af.InterpValue();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.FieldType() != af.FieldType()) {
                msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldType Mismatch: expected " << ef.FieldType() << ", got " << af.FieldType();
                throw std::runtime_error(msg.str());
            }
        }
    }
}

std::vector<const char*> raw_events = {
        // Test normal EXECVE transform
        R"event(type=SYSCALL msg=audit(1521757638.392:262332): arch=c000003e syscall=59 success=yes exit=0 a0=55d782c96198 a1=55d782c96120 a2=55d782c96158 a3=1 items=2 ppid=26595 pid=26918 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=842 comm="logger" exe="/usr/bin/logger" key=(null)
type=EXECVE msg=audit(1521757638.392:262332): argc=6 a0="logger" a1="-t" a2="zfs-backup" a3="-p" a4="daemon.err" a5=7A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
type=CWD msg=audit(1521757638.392:262332):  cwd="/"
type=PATH msg=audit(1521757638.392:262332): item=0 name="/usr/bin/logger" inode=312545 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1521757638.392:262332): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=370637 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1521757638.392:262332): proctitle=6C6F67676572002D74007A66732D6261636B7570002D70006461656D6F6E2E657272007A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
)event",
        // Test fragment part 1
        R"event(type=SYSCALL msg=audit(1521757638.392:262332): arch=c000003e syscall=59 success=yes exit=0 a0=55d782c96198 a1=55d782c96120 a2=55d782c96158 a3=1 items=2 ppid=26595 pid=26918 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=842 comm="logger" exe="/usr/bin/logger" key=(null)
type=EXECVE msg=audit(1521757638.392:262332): argc=6 a0="logger" a1="-t" a2="zfs-backup" a3="-p" a4="daemon.err" a5=7A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
)event",
        // Test fragment part 2 (must follow immediatly after part 1)
        R"event(type=EXECVE msg=audit(1521757638.392:262332): argc=6 a0="logger" a1="-t" a2="zfs-backup" a3="-p" a4="daemon.err" a5=7A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
type=CWD msg=audit(1521757638.392:262332):  cwd="/"
type=PATH msg=audit(1521757638.392:262332): item=0 name="/usr/bin/logger" inode=312545 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1521757638.392:262332): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=370637 dev=00:13 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1521757638.392:262332): proctitle=6C6F67676572002D74007A66732D6261636B7570002D70006461656D6F6E2E657272007A667320696E6372656D656E74616C206261636B7570206F662072706F6F6C2F6C7864206661696C65643A20
)event",
        // Test to make sure pid gets reset from previous event
        R"event(type=BPRM_FCAPS msg=audit(1521773704.435:270957): fver=0 fp=0000000000000000 fi=0000000000000000 fe=0 old_pp=0000000000000000 old_pi=0000000000000000 old_pe=0000000000000000 new_pp=0000003fffffffff new_pi=0000000000000000 new_pe=0000003fffffffff
)event"
        R"event(type=LOGIN msg=audit(1521757801.424:262683): pid=27127 uid=0 old-auid=4294967295 auid=0 old-ses=4294967295 ses=844 res=1
)event",
};

const std::vector<TestEvent> events {
        {1521757638, 392, 262332, 1, 26918, {
                {14688, "AUOMS_EXECVE", "", {
                        // SYSCALL
                        {"arch", "c000003e", "x86_64", FIELD_TYPE_ARCH},
                        {"syscall", "59", "execve", FIELD_TYPE_SYSCALL},
                        {"success", "yes", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"exit", "0", nullptr, FIELD_TYPE_EXIT},
                        {"ppid", "26595", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"pid", "26918", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"auid", "0", "root", FIELD_TYPE_UID},
                        {"uid", "0", "root", FIELD_TYPE_UID},
                        {"gid", "0", "root", FIELD_TYPE_GID},
                        {"euid", "0", "root", FIELD_TYPE_UID},
                        {"suid", "0", "root", FIELD_TYPE_UID},
                        {"fsuid", "0", "root", FIELD_TYPE_UID},
                        {"egid", "0", "root", FIELD_TYPE_GID},
                        {"sgid", "0", "root", FIELD_TYPE_GID},
                        {"fsgid", "0", "root", FIELD_TYPE_GID},
                        {"tty", "(none)", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"ses", "842", nullptr, FIELD_TYPE_SESSION},
                        {"comm", "\"logger\"", nullptr, FIELD_TYPE_ESCAPED},
                        {"exe", "\"/usr/bin/logger\"", nullptr, FIELD_TYPE_ESCAPED},
                        {"key", "(null)", nullptr, FIELD_TYPE_ESCAPED},
                        // EXECVE
                        {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        // CWD
                        {"cwd", "\"/\"", nullptr, FIELD_TYPE_ESCAPED},
                        // PATH
                        {"name", "\"/usr/bin/logger\"", nullptr, FIELD_TYPE_ESCAPED},
                        {"inode", "312545", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"dev", "00:13", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"mode", "0100755", "file,755", FIELD_TYPE_MODE},
                        {"ouid", "0", "root", FIELD_TYPE_UID},
                        {"ogid", "0", "root", FIELD_TYPE_GID},
                        {"rdev", "00:00", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"nametype", "NORMAL", nullptr, FIELD_TYPE_UNCLASSIFIED},
                    }
                },
            }
        },
        {1521757638, 392, 262332, 1, 26918, {
                {11309, "AUOMS_EXECVE_FRAGMENT", "", {
                        // SYSCALL
                        {"arch", "c000003e", "x86_64", FIELD_TYPE_ARCH},
                        {"syscall", "59", "execve", FIELD_TYPE_SYSCALL},
                        {"success", "yes", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"exit", "0", nullptr, FIELD_TYPE_EXIT},
                        {"ppid", "26595", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"pid", "26918", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"auid", "0", "root", FIELD_TYPE_UID},
                        {"uid", "0", "root", FIELD_TYPE_UID},
                        {"gid", "0", "root", FIELD_TYPE_GID},
                        {"euid", "0", "root", FIELD_TYPE_UID},
                        {"suid", "0", "root", FIELD_TYPE_UID},
                        {"fsuid", "0", "root", FIELD_TYPE_UID},
                        {"egid", "0", "root", FIELD_TYPE_GID},
                        {"sgid", "0", "root", FIELD_TYPE_GID},
                        {"fsgid", "0", "root", FIELD_TYPE_GID},
                        {"tty", "(none)", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"ses", "842", nullptr, FIELD_TYPE_SESSION},
                        {"comm", "\"logger\"", nullptr, FIELD_TYPE_ESCAPED},
                        {"exe", "\"/usr/bin/logger\"", nullptr, FIELD_TYPE_ESCAPED},
                        {"key", "(null)", nullptr, FIELD_TYPE_ESCAPED},
                        // EXECVE
                        {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, FIELD_TYPE_UNCLASSIFIED},
                    }
                },
            }
        },
        {1521757638, 392, 262332, 1, 26918, {
                {11309, "AUOMS_EXECVE_FRAGMENT", "", {
                        // EXECVE
                        {"cmdline", "logger -t zfs-backup -p daemon.err \"zfs incremental backup of rpool/lxd failed: \"", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        // CWD
                        {"cwd", "\"/\"", nullptr, FIELD_TYPE_ESCAPED},
                        // PATH
                        {"name", "\"/usr/bin/logger\"", nullptr, FIELD_TYPE_ESCAPED},
                        {"inode", "312545", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"dev", "00:13", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"mode", "0100755", "file,755", FIELD_TYPE_MODE},
                        {"ouid", "0", "root", FIELD_TYPE_UID},
                        {"ogid", "0", "root", FIELD_TYPE_GID},
                        {"rdev", "00:00", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"nametype", "NORMAL", nullptr, FIELD_TYPE_UNCLASSIFIED},
                    }
                },
            }
        },
        {1521773704, 435, 270957, 0, -1, {
                {1321, "BPRM_FCAPS", "type=BPRM_FCAPS msg=audit(1521773704.435:270957): fver=0 fp=0000000000000000 fi=0000000000000000 fe=0 old_pp=0000000000000000 old_pi=0000000000000000 old_pe=0000000000000000 new_pp=0000003fffffffff new_pi=0000000000000000 new_pe=0000003fffffffff", {
                        {"type", "BPRM_FCAPS", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"fver", "0", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"fp", "0000000000000000", "none", FIELD_TYPE_CAP_BITMAP},
                        {"fi", "0000000000000000", "none", FIELD_TYPE_CAP_BITMAP},
                        {"fe", "0", "none", FIELD_TYPE_CAP_BITMAP},
                        {"old_pp", "0000000000000000", "none", FIELD_TYPE_CAP_BITMAP},
                        {"old_pi", "0000000000000000", "none", FIELD_TYPE_CAP_BITMAP},
                        {"old_pe", "0000000000000000", "none", FIELD_TYPE_CAP_BITMAP},
                        {"new_pp", "0000003fffffffff", "chown,dac_override,dac_read_search,fowner,fsetid,kill,setgid,setuid,setpcap,linux_immutable,net_bind_service,net_broadcast,net_admin,net_raw,ipc_lock,ipc_owner,sys_module,sys_rawio,sys_chroot,sys_ptrace,sys_pacct,sys_admin,sys_boot,sys_nice,sys_resource,sys_time,sys_tty_config,mknod,lease,audit_write,audit_control,setfcap,mac_override,mac_admin,syslog,wake_alarm,block_suspend,audit_read", FIELD_TYPE_CAP_BITMAP},
                        {"new_pi", "0000000000000000", "none", FIELD_TYPE_CAP_BITMAP},
                        {"new_pe", "0000003fffffffff", "chown,dac_override,dac_read_search,fowner,fsetid,kill,setgid,setuid,setpcap,linux_immutable,net_bind_service,net_broadcast,net_admin,net_raw,ipc_lock,ipc_owner,sys_module,sys_rawio,sys_chroot,sys_ptrace,sys_pacct,sys_admin,sys_boot,sys_nice,sys_resource,sys_time,sys_tty_config,mknod,lease,audit_write,audit_control,setfcap,mac_override,mac_admin,syslog,wake_alarm,block_suspend,audit_read", FIELD_TYPE_CAP_BITMAP},
                    }
                },
            }
        },
        {1521757801, 424, 262683, 0, 27127, {
                {1006, "LOGIN", "type=LOGIN msg=audit(1521757801.424:262683): pid=27127 uid=0 old-auid=4294967295 auid=0 old-ses=4294967295 ses=844 res=1", {
                        {"type", "LOGIN", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"pid", "27127", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"uid", "0", "root", FIELD_TYPE_UID},
                        {"old-auid", "4294967295", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"auid", "0", "root", FIELD_TYPE_UID},
                        {"old-ses", "4294967295", nullptr, FIELD_TYPE_UNCLASSIFIED},
                        {"ses", "844", nullptr, FIELD_TYPE_SESSION},
                        {"res", "1", "yes", FIELD_TYPE_SUCCESS},
                    }
                },
            }
        },
};

BOOST_AUTO_TEST_CASE( basic_test ) {
    TempDir dir("/tmp/EventProcessorTests");

    write_file(dir.Path() + "/passwd", passwd_file_text);
    write_file(dir.Path() + "/group", group_file_text);

    auto user_db = std::make_shared<UserDB>(dir.Path());

    user_db->update();

    auto expected_queue = new TestEventQueue();
    auto actual_queue = new TestEventQueue();
    auto expected_allocator = std::shared_ptr<IEventBuilderAllocator>(expected_queue);
    auto actual_allocator = std::shared_ptr<IEventBuilderAllocator>(actual_queue);
    auto expected_builder = std::make_shared<EventBuilder>(expected_allocator);
    auto actual_builder = std::make_shared<EventBuilder>(actual_allocator);
    auto proc_filter = std::make_shared<ProcFilter>(user_db);

    for (auto e : events) {
        e.Write(expected_builder);
    }

    load_libaudit_symbols();

    AuditEventProcessor aep(actual_builder, user_db, proc_filter);

    aep.Initialize();

    for (auto raw_event : raw_events) {
        aep.ProcessData(raw_event, strlen(raw_event));
        aep.Flush();
    }

    BOOST_REQUIRE_EQUAL(expected_queue->GetEventCount(), actual_queue->GetEventCount());

    for (size_t idx = 0; idx < expected_queue->GetEventCount(); ++idx) {
        diff_event(idx, expected_queue->GetEvent(idx), actual_queue->GetEvent(idx));
    }
}
