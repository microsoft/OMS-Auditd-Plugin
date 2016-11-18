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

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/filereadstream.h>

// This include file can only be included in ONE translation unit
#include <auparse.h>

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

void AuditEventProcessor::Reset()
{
    auparse_destroy(_state);
    _state_ptr = auparse_init(AUSOURCE_FEED, nullptr);
    assert(_state != nullptr);
    auparse_add_callback(_state, reinterpret_cast<void (*)(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data)>(static_callback), this, nullptr);
}

void AuditEventProcessor::Close()
{
    Flush();
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

void AuditEventProcessor::callback(void *ptr)
{
    assert(_state_ptr == ptr);
    assert(audit_msg_type_to_name != nullptr);

    // Process the event
    _pid_found = false;
    _event_flags = 0;
    const au_event_t *e = auparse_get_timestamp(_state);
    _current_event_sec = static_cast<uint64_t>(e->sec);
    _current_event_msec = static_cast<uint32_t>(e->milli);
    _current_event_serial = static_cast<uint64_t>(e->serial);

    _num_records = auparse_get_num_records(_state);
    if (_num_records == 0) {
        Logger::Warn("auparse_get_num_records() returned 0!");
        cancel_event();
        return;
    }

    if (auparse_first_record(_state) != 1) {
        Logger::Warn("auparse_first_record() failed!");
        return;
    }

    if (!begin_event()) {
        return;
    }

    do {
        auto record_type = auparse_get_type(_state);
        if (record_type == 0) {
            Logger::Warn("auparse_get_type() failed!");
        }

        switch (record_type) {
            case 1300: //SYSCALL
                _event_flags |= EVENT_FLAG_HAS_EXE_FIELD & EVENT_FLAG_HAS_COMM_FIELD;
                break;
            case 1327: //PROCTITLE
                _event_flags |= EVENT_FLAG_HAS_PROCTITLE_FIELD;
                break;
        }

        std::string record_name;
        const char* name_ptr = audit_msg_type_to_name(record_type);
        if (name_ptr != nullptr) {
            record_name = name_ptr;
        } else {
            record_name = std::string("UNKNOWN[") + std::to_string(record_type) + "]";
        }

        const char * text = auparse_get_record_text(_state);
        if (text == nullptr) {
            Logger::Warn("auparse_get_record_text() failed!");
            cancel_event();
            return;
        }

        auto ret = _builder->BeginRecord(record_type, record_name.c_str(), text, auparse_get_num_fields(_state));
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return;
        }

        do {
            if (!process_field()) {
                cancel_event();
                return;
            }
        } while (auparse_next_field(_state) == 1);

        ret = _builder->EndRecord();
        if (ret != 1) {
            if (ret == Queue::CLOSED) {
                throw std::runtime_error("Queue closed");
            }
            cancel_event();
            return;
        }

    } while (auparse_next_record(_state) == 1);

    end_event();
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
    _builder->SetEventFlags(_event_flags);
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

// Assumes x86 (little-endian)
inline bool NAME_EQUAL_EXE(const char *name) {
    return *reinterpret_cast<const uint32_t*>(name) == 0x00657865;
}

// Assumes x86 (little-endian)
inline bool NAME_EQUAL_COMM(const char *name) {
    return *reinterpret_cast<const uint32_t*>(name) == 0x6D6D6F63 && name[4] == 0;
}

bool AuditEventProcessor::process_field()
{
    const char* name_ptr = auparse_get_field_name(_state);
    if (name_ptr == nullptr) {
        return false;
    }

    if ((_event_flags & EVENT_FLAG_HAS_EXE_FIELD) == 0 && NAME_EQUAL_EXE(name_ptr)) {
        _event_flags |= EVENT_FLAG_HAS_EXE_FIELD;
    }

    if ((_event_flags & EVENT_FLAG_HAS_COMM_FIELD) == 0 && NAME_EQUAL_COMM(name_ptr)) {
        _event_flags |= EVENT_FLAG_HAS_COMM_FIELD;
    }

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

            if (!_pid_found && NAME_EQUAL_PID(name_ptr)) {
                int64_t pid = atoll(val_ptr);
                if (pid != 0) {
                    _builder->SetEventPid(pid);
                }
            }
            break;
        }
        case FIELD_TYPE_UID: {
            int uid = atoi(val_ptr);
            interp_str = _user_db->GetUserName(uid);
            if (interp_str.size() > 0) {
                interp_ptr = interp_str.c_str();
            }
            break;
        }
        case FIELD_TYPE_GID: {
            int gid = atoi(val_ptr);
            interp_str = _user_db->GetGroupName(gid);
            if (interp_str.size() > 0) {
                interp_ptr = interp_str.c_str();
            }
            break;
        }
        case FIELD_TYPE_ESCAPED: {
            interp_ptr = nullptr;
            break;
        }
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
