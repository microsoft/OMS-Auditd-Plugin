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

#include "Queue.h"
#include "Logger.h"
#include "StringUtils.h"

#include <stdexcept>
#include <cassert>
#include <cctype>
#include <cstring>

#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <system_error>
#include <unordered_set>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/filereadstream.h>

// This include file can only be included in ONE translation unit
#include <auparse.h>
#include <asm/types.h> // Required by <linux/audit.h>
#include <linux/audit.h>

extern "C" {
#include <dlfcn.h>
}



/*****************************************************************************
 * Dynamicly load needed libaudit symbols
 *
 * There are two version of libaudit (libaudit0, and libaudit1) this makes it
 * impossible to build once then run on all supported distro versions.
 *
 * But, since libauparse is available on all supported distros, and it also
 * links to libaudit, all we need to do is call dlsym to get the function
 * pointer(s) we need.
 *
 *****************************************************************************/

static const char *(*audit_msg_type_to_name)(int msg_type);

void load_libaudit_symbols()
{
    char *error;
    void *ptr = dlsym(RTLD_DEFAULT, "audit_msg_type_to_name");
    if ((error = dlerror()) != nullptr) {
        Logger::Error("Failed to locate function audit_msg_type_to_name(): %s", error);
        exit(1);
    }
    *(void **) (&audit_msg_type_to_name) = ptr;
}

/*****************************************************************************
 ** field_type_from_auparse_type
 *****************************************************************************/

event_field_type_t field_type_from_auparse_type(int auparse_type)
{
    if (auparse_type >= MIN_FIELD_TYPE && auparse_type <= MAX_FIELD_TYPE) {
        return static_cast<event_field_type_t>(auparse_type);
    }
    return FIELD_TYPE_UNCLASSIFIED;
}

/*****************************************************************************
 **
 *****************************************************************************/


void interpret_escaped_field(const char* ptr, std::string& str) {

}

/*****************************************************************************
 ** AuditEventProcessor
 *****************************************************************************/

#define _state static_cast<auparse_state_t*>(_state_ptr)

AuditEventProcessor::~AuditEventProcessor()
{
    auparse_destroy(_state);
}

void AuditEventProcessor::Initialize()
{
    _state_ptr = auparse_init(AUSOURCE_FEED, nullptr);
    assert(_state != nullptr);
    auparse_add_callback(_state, reinterpret_cast<void (*)(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data)>(static_callback), this, nullptr);
}

void AuditEventProcessor::ProcessData(const char* data, size_t data_len)
{
    if (auparse_feed(_state, data, data_len) != 0) {
        throw std::runtime_error("auparse_feed() failed!");
    }
}

void AuditEventProcessor::Flush()
{
    if (auparse_flush_feed(_state) != 0) {
        throw std::runtime_error("auparse_flush_feed() failed!");
    }
}

void AuditEventProcessor::static_callback(void *au, dummy_enum_t cb_event_type, void *user_data)
{
    assert(user_data != nullptr);

    if (static_cast<auparse_cb_event_t>(cb_event_type) != AUPARSE_CB_EVENT_READY) {
        return;
    }

    AuditEventProcessor* processor = static_cast<AuditEventProcessor*>(user_data);
    processor->callback(au);
}

const char* auparse_find_field_in_record(auparse_state_t *state, const char* name)
{
    do {
        const char* fieldname = auparse_get_field_name(state);
        if (fieldname == nullptr) {
            continue;
        }
        if (strcmp(fieldname, name) == 0) {
            return auparse_get_field_str(state);
        }
    } while (auparse_next_field(state) == 1);

    return nullptr;
}

bool AuditEventProcessor::process_aggregate()
{
    int record_type;
    const char *record_name;

    if (auparse_first_record(_state) != 1) {
        return false;
    }

    switch (auparse_get_type(_state)) {
        case AUDIT_SYSCALL:
            record_type = SYSCALL_RECORD_TYPE;
            record_name = SYSCALL_RECORD_NAME;
            break;
        case AUDIT_EXECVE:
        case AUDIT_PATH:
        case AUDIT_CWD:
        case AUDIT_SOCKADDR:
            record_type = FRAGMENT_RECORD_TYPE;
            record_name = FRAGMENT_RECORD_NAME;
            break;
        default:
            return false;
    }

    int field_count = 0;
    bool has_cwd = false;
    bool has_path = false;
    bool has_sockaddr = false;
    bool has_execve = false;

    do {
        switch (auparse_get_type(_state)) {
            case AUDIT_EXECVE:
                has_execve = true;
                field_count++;
                break;
            case AUDIT_SYSCALL:
                // remove type, items, a0, a1, a2 and a3 
                field_count += auparse_get_num_fields(_state) - 6;
                has_sockaddr = true;
                break;
            case AUDIT_CWD:
                has_cwd = true;
                field_count++;
                break;
            case AUDIT_PATH: {
                if (has_path) {
                    continue;
                }
                const char* type = auparse_find_field_in_record(_state, "objtype");
                if (type == nullptr) {
                    auparse_first_field(_state);
                    type = auparse_find_field_in_record(_state, "nametype");
                }
                if (type == nullptr || strcmp(type, "PARENT") == 0) {
                    continue;
                }
                // remove type and item
                field_count += auparse_get_num_fields(_state) - 2;
                has_path = true;
                break;
            }
            case AUDIT_SOCKADDR:
                field_count++;
                break;
            default:
                break;
        }
    } while (auparse_next_record(_state) == 1);

    if (auparse_first_record(_state) != 1) {
        return false;
    }

    if (record_type == SYSCALL_RECORD_TYPE && !has_cwd && !has_sockaddr) {
        record_type = FRAGMENT_RECORD_TYPE;
        record_name = FRAGMENT_RECORD_NAME;
    }

    auto ret = _builder->BeginEvent(_current_event_sec, _current_event_msec, _current_event_serial, 1);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }

    ret = _builder->BeginRecord(record_type, record_name, "", field_count);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    bool syscall_success = false;
    has_path = false;

    do {
        int record_type = auparse_get_type(_state);

        switch (record_type) {
            case AUDIT_SYSCALL: {
                do {
                    const char* field = auparse_get_field_name(_state);
                    int number;
                    if (field != nullptr && strcmp(field, "type") != 0 && strcmp(field, "items") != 0 && sscanf(field, "a%d", &number) == 0) {
                        if (strcmp(field, "success") == 0) {
                            const char* val_ptr = auparse_get_field_str(_state);
                            if (val_ptr != nullptr && val_ptr[0] == 'y') {
                                syscall_success = true;
                            }
                        }
                        if (!process_field(field)) {
                            cancel_event();
                            return false;
                        }
                    }
                } while (auparse_next_field(_state) == 1);
                break;
            }
            case AUDIT_EXECVE: {
                _cmdline.clear();

                /*
                 * TODO: Deal with the case where one or more args are empty.
                 * For example "/bin/echo '' '' 'test' ''" will result in an EXECVE of: argc=5 a0="/bin/echo" a3="test""
                 * The resulting cmdline will be "/bin/echo test" when it should be "'' '' test ''".
                 */
                do {
                    int number;
                    const char* field = auparse_get_field_name(_state);

                    if (field == nullptr || sscanf(field, "a%d", &number) < 1) {
                        continue;
                    }

                    field = auparse_get_field_str(_state);
                    if (field == nullptr) {
                        continue;
                    }

                    unescape_raw_field(_unescaped_arg, field, strlen(field));

                    if (!_cmdline.empty()) {
                        _cmdline.push_back(' ');
                    }

                    bash_escape_string(_cmdline, _unescaped_arg.data(), _unescaped_arg.length());
                } while (auparse_next_field(_state) == 1);

                bool cmdline_truncated = false;
                if (_cmdline.size() > UINT16_MAX-1) {
                    _cmdline.resize(UINT16_MAX-1);
                    cmdline_truncated = true;
                }
                ret = _builder->AddField("cmdline", _cmdline.c_str(), NULL, FIELD_TYPE_UNCLASSIFIED);
                if (ret != 1) {
                    if (ret == Queue::CLOSED) {
                        throw std::runtime_error("Queue closed");
                    }
                    cancel_event();
                    return false;
                }
                if (cmdline_truncated) {
                    ret = _builder->AddField("cmdline_truncated", "true", NULL, FIELD_TYPE_UNCLASSIFIED);
                    if (ret != 1) {
                        if (ret == Queue::CLOSED) {
                            throw std::runtime_error("Queue closed");
                        }
                        cancel_event();
                        return false;
                    }
                }
                break;
            }
            case AUDIT_CWD: {
                const char* cwd = auparse_find_field_in_record(_state, "cwd");
                if (cwd == nullptr || !process_field("cwd")) {
                    continue;
                };
                break;
            }
            case AUDIT_PATH: {
                if (has_path) {
                    continue;
                }
                const char* type = auparse_find_field_in_record(_state, "objtype");
                if (type == nullptr) {
                    auparse_first_field(_state);
                    type = auparse_find_field_in_record(_state, "nametype");
                }
                if (type == nullptr || strcmp(type, "PARENT") == 0) {
                    continue;
                }

                auparse_first_field(_state);
                do {
                    const char* field = auparse_get_field_name(_state);
                    if (field != nullptr && strcmp(field, "type") != 0 && strcmp(field, "item") != 0 && !process_field(field)) {
                        cancel_event();
                        return false;
                    }
                } while (auparse_next_field(_state) == 1);
                has_path = true;
                break;
            }
            case AUDIT_SOCKADDR: {
                const char* saddr = auparse_find_field_in_record(_state, "saddr");
                if (saddr == nullptr || !process_field("name")) {
                    continue;
                }
                break;
            }
            case 0:
                Logger::Warn("auparse_get_type() failed!");
                break;
            default:
                break;
        }
    } while (auparse_next_record(_state) == 1);

    if (_builder->GetFieldCount() != field_count) {
        cancel_event();
        return false;
    }

    if (_pid != 0) {
        _builder->SetEventPid(_pid);
    }

    ret = _builder->EndRecord();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        cancel_event();
        return false;
    }

    end_event();
    return true;
}

void AuditEventProcessor::callback(void *ptr)
{
    assert(_state_ptr == ptr);
    assert(audit_msg_type_to_name != nullptr);

    // Process the event
    const au_event_t *e = auparse_get_timestamp(_state);

    // Only reset the _pid and _ppid if this events time/serial is different from the previous event.
    if (_current_event_sec != static_cast<uint64_t>(e->sec) ||
        _current_event_msec != static_cast<uint32_t>(e->milli) ||
        _current_event_serial != static_cast<uint64_t>(e->serial))
    {
        _current_event_sec = static_cast<uint64_t>(e->sec);
        _current_event_msec = static_cast<uint32_t>(e->milli);
        _current_event_serial = static_cast<uint64_t>(e->serial);
        _pid = 0;
        _ppid = 0;
    }

    _num_records = auparse_get_num_records(_state);
    if (_num_records == 0) {
        Logger::Warn("auparse_get_num_records() returned 0!");
        return;
    }

    if (process_aggregate()) {
        return;
    }

    if (auparse_first_record(_state) != 1) {
        Logger::Warn("auparse_first_record() failed!");
        return;
    }

    if (!begin_event()) {
        return;
    }

    uint16_t num_non_eoe_records = 0;
    do {
        auto record_type = auparse_get_type(_state);
        if (record_type == 0) {
            Logger::Warn("auparse_get_type() failed!");
        }

        // Ignore the end-of-event (EOE) record
        if (record_type != AUDIT_EOE) {
            num_non_eoe_records++;
        }

        std::string record_type_name;
        const char* name_ptr = audit_msg_type_to_name(record_type);
        if (name_ptr != nullptr) {
            record_type_name = name_ptr;
        } else {
            record_type_name = std::string("UNKNOWN[") + std::to_string(record_type) + "]";
        }

        const char *text = auparse_get_record_text(_state);
        if (text == nullptr) {
            Logger::Warn("auparse_get_record_text() failed!");
            cancel_event();
            return;
        }

        auto ret = _builder->BeginRecord(record_type, record_type_name.c_str(), text,
                                         auparse_get_num_fields(_state));
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return;
        }

        if (auparse_first_field(_state) != 1) {
            Logger::Warn("auparse_first_field() failed!");
            return;
        }

        do {
            if (!process_field()) {
                cancel_event();
                return;
            }
        } while (auparse_next_field(_state) == 1);

        if (_pid != 0) {
            _builder->SetEventPid(_pid);
        }

        ret = _builder->EndRecord();
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return;
        }
    } while (auparse_next_record(_state) == 1);

    // Sometimes the event will only have the EOE record
    // Only end/emit the event if it's not empty
    if (num_non_eoe_records > 0) {
        end_event();
    } else {
        cancel_event();
    }

}

bool AuditEventProcessor::begin_event()
{
    auto ret = _builder->BeginEvent(_current_event_sec, _current_event_msec, _current_event_serial, _num_records);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }
    return true;
}

void AuditEventProcessor::end_event()
{
    auto ret = _builder->EndEvent();
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
    }
}

void AuditEventProcessor::cancel_event()
{
    if (_builder->CancelEvent() != 1) {
        throw std::runtime_error("Queue Closed");
    }
}

// Assumes x86 (little-endian)
inline bool NAME_EQUAL_PID(const char *name) {
    return *reinterpret_cast<const uint32_t*>(name) == 0x00646970;
}
inline bool NAME_EQUAL_PPID(const char *name) {
    return *reinterpret_cast<const uint32_t*>(name) == 0x64697070 && name[4] == '\0';
}

bool AuditEventProcessor::process_field(const char *name_ptr)
{
    const char* val_ptr = auparse_get_field_str(_state);
    if (val_ptr == nullptr) {
        return false;
    }

    auto field_type = field_type_from_auparse_type(auparse_get_field_type(_state));

    std::string interp_str;
    const char* interp_ptr = nullptr;

    switch (field_type) {
        case FIELD_TYPE_UNCLASSIFIED: {
            interp_ptr = auparse_interpret_field(_state);

            if (_pid == 0 && NAME_EQUAL_PID(name_ptr)) {
                _pid = atoi(val_ptr);
            } else if (_ppid == 0 && NAME_EQUAL_PPID(name_ptr)) {
                _ppid = atoi(val_ptr);
            }

            if (strcmp(val_ptr, interp_ptr) == 0) {
                interp_ptr = nullptr;
            }
            break;
        }
        case FIELD_TYPE_UID: {
            int uid = static_cast<int>(strtoul(val_ptr, NULL, 10));
            if (uid < 0) {
                interp_str = "unset";
            } else {
                interp_str = _user_db->GetUserName(uid);
            }
            if (interp_str.size() == 0) {
                interp_str = "unknown(" + std::to_string(uid) + ")";
            }
            interp_ptr = interp_str.c_str();
            break;
        }
        case FIELD_TYPE_GID: {
            int gid = static_cast<int>(strtoul(val_ptr, NULL, 10));
            if (gid < 0) {
                interp_str = "unset";
            } else {
                interp_str = _user_db->GetGroupName(gid);
            }
            if (interp_str.size() == 0) {
                interp_str = "unknown(" + std::to_string(gid) + ")";
            }
            interp_ptr = interp_str.c_str();
            break;
        }
        case FIELD_TYPE_ESCAPED:
            // interp_ptr remains NULL
            break;
        case FIELD_TYPE_PROCTITLE:
            // interp_ptr remains NULL
            break;
        default: {
            interp_ptr = auparse_interpret_field(_state);
            break;
        }
    }

    auto ret = _builder->AddField(name_ptr, val_ptr, interp_ptr, field_type);
    if (ret != 1) {
        if (ret == Queue::CLOSED) {
            throw std::runtime_error("Queue closed");
        }
        return false;
    }
    return true;
}

bool AuditEventProcessor::process_field()
{
    const char* name_ptr = auparse_get_field_name(_state);
    if (name_ptr == nullptr) {
        return false;
    }
    return process_field(name_ptr);
}


