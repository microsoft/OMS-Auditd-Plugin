/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_AUDIT_EVENT_PROCESSOR_H
#define AUOMS_AUDIT_EVENT_PROCESSOR_H

#include "Event.h"
#include "UserDB.h"

#include <string>
#include <memory>
#include <sys/types.h>

typedef enum {DUMMY_ENUM} dummy_enum_t;

extern void load_libaudit_symbols();

event_field_type_t field_type_from_auparse_type(int auparse_type);

class AuditEventProcessor {
public:
    AuditEventProcessor(const std::shared_ptr<EventBuilder>& builder, const std::shared_ptr<UserDB>& user_db):
            _builder(builder), _user_db(user_db), _state_ptr(nullptr) {};
    ~AuditEventProcessor();

    void Initialize();
    void ProcessData(const char* data, size_t data_len);
    void Flush();

private:
    static void static_callback(void *au, dummy_enum_t cb_event_type, void *user_data);

    void callback(void *ptr);

    bool begin_event();
    void end_event();
    void cancel_event();
    bool is_execve();
    void process_execve();
    bool process_field(const char *name_ptr);
    bool process_field();

    std::shared_ptr<EventBuilder> _builder;
    std::shared_ptr<UserDB> _user_db;
    void* _state_ptr;
    int _num_records;
    uint64_t _current_event_sec;
    uint32_t _current_event_msec;
    uint64_t _current_event_serial;
    uint32_t _event_flags;
    pid_t _pid;
    pid_t _ppid;
};

#endif //AUOMS_AUDIT_EVENT_PROCESSOR_H
