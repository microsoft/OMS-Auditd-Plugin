/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "CollectionMonitor.h"
#include "ProcessInfo.h"
#include "Logger.h"
#include "RecordType.h"
#include "Translate.h"
#include "FileUtils.h"

#include <cstring>
#include <chrono>
#include <thread>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <cstdlib>
#include <fstream>


void CollectionMonitor::run() {
    Logger::Info("CollectionMonitor started");

    if (_netlink.Open(nullptr) != 0) {
        Logger::Error("CollectionMonitor: Could not open NETLINK connect, exiting");
        return;
    }

    do {
        auto now = std::chrono::steady_clock::now();

        if (_pause_collector_check && now - _pause_time > std::chrono::seconds(3600)) {
            _pause_collector_check = false;
        }

        uint32_t audit_pid = 0;
        auto ret = NetlinkRetry([this,&audit_pid]() { return _netlink.AuditGetPid(audit_pid); });
        if (ret != 0) {
            // Treat NETLINK errors as unrecoverable.
            if (!IsStopping()) {
                Logger::Warn("CollectionMonitor: Failed to get audit pid from audit NETLINK: %s", std::strerror(-ret));
            }
            audit_pid = 0;
        }
        if (!PathExists("/proc/"+std::to_string(audit_pid))) {
            audit_pid = 0;
        }

        // Always get collector aliveness. This will ensure the child is reaped if it exits and won't be restarted.
        bool is_alive = is_collector_alive();

        if (!_pause_collector_check && !is_auditd_present() && !is_alive && audit_pid == 0) {
            start_collector();

            int netlink_errno = 0;
            while (!IsStopping() && audit_pid <= 0 && !_sleep(500) && std::chrono::steady_clock::now() - now < std::chrono::seconds(10)) {
                auto ret = NetlinkRetry([this,&audit_pid]() { return _netlink.AuditGetPid(audit_pid); });
                if (ret != 0) {
                    // Treat NETLINK errors as unrecoverable.
                    if (!IsStopping()) {
                        netlink_errno = -ret;
                    }
                    audit_pid = 0;
                } else {
                    netlink_errno = 0;
                    if (!PathExists("/proc/"+std::to_string(audit_pid))) {
                        audit_pid = 0;
                    }
                }
            }
            if (IsStopping()) {
                break;
            }
            if (netlink_errno != 0) {
                Logger::Warn("CollectionMonitor: Failed to get audit pid from audit NETLINK: %s", std::strerror(netlink_errno));
            } else {
                if (audit_pid == 0) {
                    if (check_child(false)) {
                        Logger::Warn("CollectionMonitor: Collector has not set itself as the audit pid after 10 seconds");
                    }
                }
            }
        }

        if (!IsStopping()) {
            if (audit_pid != _audit_pid || now - _last_audit_pid_report > std::chrono::seconds(3600)) {
                _last_audit_pid_report = now;
                _audit_pid = audit_pid;
                send_audit_pid_report(audit_pid);
            }
        }
    } while(!_sleep(10000));
    Logger::Info("CollectionMonitor stopping");
}

void CollectionMonitor::on_stop() {
    _collector.Wait(false);
    if (_collector.Pid() > 0) {
        Logger::Info("Signaling collector process to exit");
        signal_collector(SIGTERM);
        // Give the collector 2 second to exit normally
        for(int i = 0; i < 20 && check_child(false); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (check_child(false)) {
            Logger::Info("Timeout waiting for collector process to exit, terminating with SIGKILL");
            signal_collector(SIGKILL);
        }
        check_child(true);
    }
    _netlink.Close();
    Logger::Info("CollectionMonitor stopped");
}

void report_proc_exit_status(Cmd& cmd) {
    if (cmd.ExitCode() > -1) {
        Logger::Info("Collector process exited with exit code %d", cmd.ExitCode());
    } else if (cmd.Signal() > -1) {
        Logger::Info("Collector process terminated with SIGNAL %d", cmd.Signal());
    } else {
        Logger::Info("Collector process terminated with unknown status");
    }
}

bool CollectionMonitor::check_child(bool wait) {
    if (_collector.Pid() <= 0) {
        return false;
    }

    auto ret = _collector.Wait(wait);
    if (ret < 0) {
        Logger::Warn("CollectionMonitor::check_child: waitpid() failed: %s", std::strerror(errno));
        _pause_collector_check = true;
        _pause_time = std::chrono::steady_clock::now();
        return false;
    } else if (ret == 1) {
        report_proc_exit_status(_collector);
        return false;
    } else {
        return true;
    }
}

void CollectionMonitor::start_collector() {
    // Remove start times that are outside the window
    while (!_collector_restarts.empty() && std::chrono::steady_clock::now() - *_collector_restarts.begin() > std::chrono::seconds(COLLECTOR_RESTART_WINDOW)) {
        _collector_restarts.erase(_collector_restarts.begin());
    }
    // Disable collector start if num starts exceeds max allowed.
    if (_collector_restarts.size() > MAX_COLLECTOR_RESTARTS) {
        _pause_collector_check = true;
        _pause_time = std::chrono::steady_clock::now();
        Logger::Warn("NETLINK collector started more than %d times in the last %d seconds. Collector will not be started again for one hour.", MAX_COLLECTOR_RESTARTS, COLLECTOR_RESTART_WINDOW);
        return;
    }
    _collector_restarts.emplace(std::chrono::steady_clock::now());

    Logger::Info("Starting audit NETLINK collector \"%s\"", _collector_path.c_str());
    auto ret = _collector.Start();
    if (ret != 0) {
        Logger::Error("CollectionMonitor::start_collector(): %s", _collector.FailMsg().c_str());
    }
}

void CollectionMonitor::signal_collector(int sig) {
    _collector.Wait(false); // Maybe reap child first in case it has already exited.
    if (_collector.Pid() > 0) {
        auto ret = _collector.Kill(sig);
        // The child might have already died, so only report an error, if kill didn't return errno == ESRCH (process not found)
        if(ret != 0 && ret != -ESRCH) {
            Logger::Warn("CollectionMonitor: kill(%d, %d) failed: %s", _collector.Pid(), sig, std::strerror(errno));
            _pause_collector_check = true;
            _pause_time = std::chrono::steady_clock::now();
        }
    }
}

bool CollectionMonitor::is_auditd_enabled_systemd() {
    int isEnabledStatus = std::system("systemctl is-enabled auditd.service > /dev/null 2>&1");
    return (PathExists(_auditd_path) && (isEnabledStatus == 0));
}

bool CollectionMonitor::is_auditd_enabled_sysv() {
    int isEnabledStatus = std::system("chkconfig --list auditd | grep -q ':on' > /dev/null 2>&1");
    return (isEnabledStatus == 0);
}

bool CollectionMonitor::is_auditd_enabled_upstart() {
    int isEnabledStatus = 0;
    std::ifstream file("/etc/init/auditd.conf");
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Check if the line contains 'start on' indicating service is enabled
        if (line.find("start on") != std::string::npos) {
            isEnabledStatus = 1;
            break;
        }
    }
    file.close();
    return (isEnabledStatus);
}

bool CollectionMonitor::is_auditd_present() {
    if (is_auditd_enabled_systemd() || is_auditd_enabled_sysv() || is_auditd_enabled_upstart()) {
        return true;
    }
    return false;
}

bool CollectionMonitor::is_collector_alive() {
    return check_child(false);
}

void CollectionMonitor::send_audit_pid_report(int pid) {
    static std::string_view SV_EMPTY;

    auto pinfo = ProcessInfo::OpenPid(pid, 0);
    std::string exe;
    int ppid = -1;
    if (pinfo) {
        exe = pinfo->exe();
        ppid = pinfo->ppid();
    }

    struct timeval tv;
    gettimeofday(&tv, nullptr);

    uint64_t sec = static_cast<uint64_t>(tv.tv_sec);
    uint32_t msec = static_cast<uint32_t>(tv.tv_usec)/1000;

    if (!_builder.BeginEvent(sec, msec, 0, 1)) {
        return;
    }
    if (!_builder.BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_COLLECTOR_REPORT), RecordTypeToName(RecordType::AUOMS_COLLECTOR_REPORT), "", 3)) {
        return;
    }
    if (!_builder.AddField("pid", std::to_string(pid), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
        return;
    }
    if(!_builder.AddField("ppid", std::to_string(ppid), SV_EMPTY, field_type_t::UNCLASSIFIED)) {
        return;
    }
    if(!_builder.AddField("exe", exe, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
        return;
    }
    if(!_builder.EndRecord()) {
        return;
    }
    _builder.EndEvent();
}
