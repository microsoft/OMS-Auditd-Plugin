//
// Created by tad on 2/13/19.
//

#ifndef AUOMS_COLLECTIONMONITOR_H
#define AUOMS_COLLECTIONMONITOR_H

#include "RunBase.h"
#include "Netlink.h"

#include <chrono>

class CollectionMonitor: public RunBase {
public:
    CollectionMonitor(const std::string& auditd_path, const std::string& collector_path, const std::string& collector_config_path): _auditd_path(auditd_path), _collector_path(collector_path), _collector_config_path(collector_config_path), _collector_pid(0), _audit_pid(0), _disable_collector_check(false), _last_audit_pid_report(), _last_rules_check() {}

protected:
    void run() override;
    void on_stopping() override;
    void on_stop() override;

private:
    // Return true if child is alive, false if not. If wait is true and child is alive, will wait forever for child to exit.
    bool check_child(bool wait);
    void start_collector();
    void signal_collector(int signal);
    bool is_auditd_present();
    bool is_collector_alive();
    void send_audit_pid_report(int pid);
    void check_rules();
    void remove_rules();

    Netlink _netlink;
    std::string _auditd_path;
    std::string _collector_path;
    std::string _collector_config_path;
    int _collector_pid;
    uint32_t _audit_pid;
    bool _disable_collector_check;
    std::chrono::steady_clock::time_point _last_audit_pid_report;
    std::chrono::steady_clock::time_point _last_rules_check;
};


#endif //AUOMS_COLLECTIONMONITOR_H
