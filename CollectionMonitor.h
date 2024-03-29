/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_COLLECTIONMONITOR_H
#define AUOMS_COLLECTIONMONITOR_H

#include "RunBase.h"
#include "Netlink.h"
#include "EventQueue.h"
#include "ExecUtil.h"

#include <chrono>
#include <set>

class CollectionMonitor: public RunBase {
public:
    static constexpr int COLLECTOR_RESTART_WINDOW = 30;
    static constexpr int MAX_COLLECTOR_RESTARTS = 15; // The maximum times the collector will be restarted within COLLECTOR_RESTART_WINDOW seconds before restarts are disabled.

    CollectionMonitor(std::shared_ptr<PriorityQueue> queue,
                      const std::string& auditd_path,
                      const std::string& collector_path,
                      const std::string& collector_config_path)
            : _builder(std::make_shared<EventQueue>(std::move(queue)), nullptr),
              _auditd_path(auditd_path), _collector_path(collector_path), _collector_config_path(collector_config_path),
              _collector(collector_path, collector_args(collector_config_path), Cmd::PIPE_STDIN), _audit_pid(0), _pause_collector_check(false), _pause_time(), _last_audit_pid_report(), _collector_restarts() {}

protected:
    void run() override;
    void on_stop() override;

private:
    std::vector<std::string> collector_args(const std::string& collector_config_path) {
        std::vector<std::string> args;
        args.emplace_back("-n");
        if (!collector_config_path.empty()) {
            args.emplace_back("-c");
            args.emplace_back(collector_config_path);
        }
        return args;
    }


    // Return true if child is alive, false if not. If wait is true and child is alive, will wait forever for child to exit.
    bool check_child(bool wait);
    void start_collector();
    void signal_collector(int signal);
    bool is_auditd_present();
    bool is_collector_alive();
    void send_audit_pid_report(int pid);
    bool is_auditd_enabled_systemd();
    bool is_auditd_enabled_sysv();
    bool is_auditd_enabled_upstart();

    Netlink _netlink;
    EventBuilder _builder;
    std::string _auditd_path;
    std::string _collector_path;
    std::string _collector_config_path;
    Cmd _collector;
    uint32_t _audit_pid;
    bool _pause_collector_check;
    std::chrono::steady_clock::time_point _pause_time;
    std::chrono::steady_clock::time_point _last_audit_pid_report;
    std::set<std::chrono::steady_clock::time_point> _collector_restarts;
};


#endif //AUOMS_COLLECTIONMONITOR_H
