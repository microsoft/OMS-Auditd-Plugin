/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_OPERATIONALSTATUS_H
#define AUOMS_OPERATIONALSTATUS_H

#include "UnixDomainListener.h"
#include "RunBase.h"
#include "EventQueue.h"
#include "PriorityQueue.h"
#include "CmdlineRedactor.h"
#include "AuditRules.h"

#include <string>
#include <vector>
#include <functional>

/*
 * Statuses
 *      No collection
 *          auditd installed but not running
 *          auditd not installed, other process collecting
 *      -e 2 is set and desired rules not loaded
 *          auditd present
 *          auditd absent
 *      Could not update auditd rules
 *      Could not update kernel rules
 */

enum class ErrorCategory {
    DATA_COLLECTION,
    DESIRED_RULES,
    AUDIT_RULES_KERNEL,
    AUDIT_RULES_FILE,
    MISSING_REDACTION_RULES,
};

class OperationalStatusListener: public RunBase {
public:
    explicit OperationalStatusListener(const std::string socket_path, std::function<std::string()>&& status_fn): _listener(socket_path), _status_fn(status_fn) {}

    bool Initialize();

protected:
    void on_stopping() override;
    void run() override;

private:
    void handle_connection(int fd);

    UnixDomainListener _listener;
    std::function<std::string()> _status_fn;
};

class OperationalStatus: public RunBase {
public:
    explicit OperationalStatus(const std::string socket_path, std::shared_ptr<PriorityQueue> queue):
            _listener(socket_path, [this]() -> std::string { return get_status_str();}),
            _error_conditions(), _builder(std::make_shared<EventQueue>(std::move(queue)), nullptr) {}

    bool Initialize();

    std::vector<std::pair<ErrorCategory, std::string>> GetErrors();

    void SetErrorCondition(ErrorCategory category, const std::string& error_msg);
    void ClearErrorCondition(ErrorCategory category);

    void SetDesiredAuditRules(const std::vector<AuditRule>& rules);
    void SetLoadedAuditRules(const std::vector<AuditRule>& rules);
    void SetRedactionRules(const std::vector<std::shared_ptr<const CmdlineRedactionRule>>& rules);

protected:
    void on_stopping() override;
    void run() override;

private:
    std::string get_status_str();
    std::string get_json_status();
    bool send_status();

    OperationalStatusListener _listener;
    std::unordered_map<ErrorCategory, std::string> _error_conditions;
    EventBuilder _builder;
    std::string _desired_audit_rules;
    std::string _loaded_audit_rules;
    std::string _redaction_rules;
};


#endif //AUOMS_OPERATIONALSTATUS_H
