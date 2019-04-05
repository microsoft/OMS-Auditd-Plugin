//
// Created by tad on 3/18/19.
//

#ifndef AUOMS_OPERATIONALSTATUS_H
#define AUOMS_OPERATIONALSTATUS_H

#include "UnixDomainListener.h"
#include "RunBase.h"

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
    AUDIT_RULES_KERNEL,
    AUDIT_RULES_FILE,
};

class OperationalStatus: public RunBase {
public:
    explicit OperationalStatus(const std::string socket_path): _listener(socket_path), _error_conditions() {}

    bool Initialize();

    std::vector<std::pair<ErrorCategory, std::string>> GetErrors();

    void SetErrorCondition(ErrorCategory category, const std::string& error_msg);
    void ClearErrorCondition(ErrorCategory category, const std::string& error_msg);

protected:
    void on_stopping() override;
    void run() override;

private:
    void handle_connection(int fd);

    UnixDomainListener _listener;
    std::unordered_map<ErrorCategory, std::string> _error_conditions;
};


#endif //AUOMS_OPERATIONALSTATUS_H
