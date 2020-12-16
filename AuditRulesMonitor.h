/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_AUDITRULESMONITOR_H
#define AUOMS_AUDITRULESMONITOR_H

#include "RunBase.h"
#include "Netlink.h"
#include "OperationalStatus.h"

#include <vector>

class AuditRulesMonitor: public RunBase {
public:
    AuditRulesMonitor(const std::string& audit_rules_dir, uint32_t backlog_limit, uint32_t backlog_wait_time, std::shared_ptr<OperationalStatus> op_status):
            _audit_rules_dir(audit_rules_dir), _backlog_limit(backlog_limit), _backlog_wait_time(backlog_wait_time), _op_status(op_status),
            _last_audit_file_check(), _last_auoms_file_check(), _desired_rules(), _rules_immutable(false) {}

protected:
    void run() override;
    void on_stop() override;

private:
    void get_desired_rules();
    void check_file_rules();
    bool check_kernel_rules();
    void check_audit_status();

    Netlink _netlink;
    std::string _audit_rules_dir;
    uint32_t _backlog_limit;
    uint32_t _backlog_wait_time;
    std::shared_ptr<OperationalStatus> _op_status;
    std::chrono::steady_clock::time_point _last_audit_file_check;
    std::chrono::steady_clock::time_point _last_auoms_file_check;
    std::vector<AuditRule> _desired_rules;
    bool _rules_immutable;
};


#endif //AUOMS_AUDITRULESMONITOR_H
