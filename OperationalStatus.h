//
// Created by tad on 3/18/19.
//

#ifndef AUOMS_OPERATIONALSTATUS_H
#define AUOMS_OPERATIONALSTATUS_H

#include "UnixDomainListener.h"
#include "RunBase.h"
#include "EventQueue.h"
#include "PriorityQueue.h"

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
            _error_conditions(), _builder(std::make_shared<EventQueue>(std::move(queue))) {}

    bool Initialize();

    std::vector<std::pair<ErrorCategory, std::string>> GetErrors();

    void SetErrorCondition(ErrorCategory category, const std::string& error_msg);
    void ClearErrorCondition(ErrorCategory category);

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
};


#endif //AUOMS_OPERATIONALSTATUS_H
