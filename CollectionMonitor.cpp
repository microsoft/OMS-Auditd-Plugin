//
// Created by tad on 2/13/19.
//

#include "CollectionMonitor.h"
#include "Logger.h"

#include <cstring>
#include <chrono>
#include <thread>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

void CollectionMonitor::run() {
    Logger::Info("CollectionMonitor started");

    _netlink.Open(nullptr);

    while(!_sleep(1000)) {
        auto now = std::chrono::steady_clock::now();

        uint32_t audit_pid = -1;
        auto ret = _netlink.AuditGetPid(audit_pid);
        if (ret != Netlink::SUCCESS) {
            // Treat NETLINK errors as unrecoverable.
            if (!IsStopping()) {
                Logger::Warn("CollectionMonitor: Failed to get audit pid from audit NETLINK");
            }
            Logger::Info("CollectionMonitor stopping");
            return;
        }

        if (!_disable_collector_check && !is_auditd_present() && !is_collector_alive() && audit_pid == 0) {
            start_collector();

            while (audit_pid <= 0 && !_sleep(100) && std::chrono::steady_clock::now() - now < std::chrono::seconds(10)) {
                auto ret = _netlink.AuditGetPid(audit_pid);
                if (ret != Netlink::SUCCESS) {
                    // Treat NETLINK errors as unrecoverable.
                    if (!IsStopping()) {
                        Logger::Warn("CollectionMonitor: Failed to get audit pid from audit NETLINK");
                    }
                    Logger::Info("CollectionMonitor stopping");
                    return;
                }
            }
            if (IsStopping()) {
                break;
            }
            if (audit_pid == 0) {
                if (check_child(false)) {
                    Logger::Warn("CollectionMonitor: Collector has not set itself as the audit pid after 10 seconds");
                }
            }
        }

        if (audit_pid != _audit_pid || now - _last_audit_pid_report > std::chrono::seconds(3600)) {
            _last_audit_pid_report = now;
            _audit_pid = audit_pid;
            send_audit_pid_report(audit_pid);
        }

        if (now - _last_rules_check > std::chrono::seconds(60)) {
            _last_rules_check = now;
            check_rules();
        }
    }
    Logger::Info("CollectionMonitor stopping");
}

void CollectionMonitor::on_stopping() {
    _netlink.Close();
}

void CollectionMonitor::on_stop() {
    remove_rules();

    if (_collector_pid > 0) {
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
    Logger::Info("CollectionMonitor stopped");
}

void report_proc_exit_status(int wstatus) {
    if (WIFEXITED(wstatus)) {
        Logger::Info("Collector process exited with exit code %d", WEXITSTATUS(wstatus));
    } else if (WIFSIGNALED(wstatus)) {
        Logger::Info("Collector process terminated with SIGNAL %d", WTERMSIG(wstatus));
    } else {
        Logger::Info("Collector process terminated with unknown status 0x%X", wstatus);
    }
}

bool CollectionMonitor::check_child(bool wait) {
    if (_collector_pid <= 0) {
        return false;
    }

    int wstatus = 0;
    errno = 0;
    auto ret = waitpid(_collector_pid, &wstatus, WNOHANG);
    if (ret < 0) {
        Logger::Warn("CollectionMonitor::check_child: waitpid(%d) failed: %s", _collector_pid, std::strerror(errno));
        _collector_pid = 0;
        _disable_collector_check = true;
        return false;
    }

    if (ret != 0) {
        if (ret != _collector_pid) {
            Logger::Warn("CollectionMonitor::check_child: waitpid(%d) returned ann unexpected pid(%d)", _collector_pid, ret);
            _disable_collector_check = true;
            _collector_pid = 0;
            return false;
        }
        _collector_pid = 0;
        report_proc_exit_status(wstatus);
        return false;
    } else {
        if (wait) {
            ret = waitpid(_collector_pid, &wstatus, 0);
            if (ret < 0) {
                Logger::Warn("CollectionMonitor::check_child: waitpid(%d) failed: %s", _collector_pid, std::strerror(errno));
                _collector_pid = 0;
                _disable_collector_check = true;
                return false;
            }
            if (ret != _collector_pid) {
                Logger::Warn("CollectionMonitor::check_child: waitpid(%d) returned ann unexpected pid(%d)", _collector_pid, ret);
                _collector_pid = 0;
                _disable_collector_check = true;
                return false;
            }
            _collector_pid = 0;
            report_proc_exit_status(wstatus);
            return false;
        }
        return true;
    }
}

void CollectionMonitor::start_collector() {
    Logger::Info("Starting audit NETLINK collector \"%s\"", _collector_path.c_str());
    auto pid = fork();
    if (pid < 0) {
        _disable_collector_check = true;
        Logger::Error("CollectionMonitor::start_collector(): fork() failed: %s", std::strerror(errno));
        return;
    }

    if (pid == 0) {
        char arg1[_collector_path.size()+1];
        _collector_path.copy(arg1, std::string::npos);
        arg1[_collector_path.size()] = 0;
        char arg2[] = "-n";
        char arg3[] = "-c";
        char arg4[_collector_config_path.size()+1];
        _collector_config_path.copy(arg4, std::string::npos);
        arg4[_collector_config_path.size()] = 0;
        char* args[] = {
            arg1,
            arg2,
            arg3,
            arg4,
            nullptr
        };

        ::execve(_collector_path.c_str(), args, environ);
        Logger::Error("CollectionMonitor::start_collector(): execve() failed: %s", std::strerror(errno));
        exit(errno);
    } else {
        _collector_pid = pid;
    }
}

void CollectionMonitor::signal_collector(int sig) {
    if (_collector_pid > 0) {
        if(kill(_collector_pid, sig) != 0) {
            Logger::Warn("CollectionMonitor: kill(%d, %d) failed: %s", _collector_pid, sig, std::strerror(errno));
            _disable_collector_check = true;
        }
    }
}

bool CollectionMonitor::is_auditd_present() {
    struct stat buf;
    auto ret = stat(_auditd_path.c_str(), &buf);
    if (ret == 0) {
        return true;
    }
    return false;
}

bool CollectionMonitor::is_collector_alive() {
    return check_child(false);
}

void CollectionMonitor::send_audit_pid_report(int pid) {
Logger::Info("CollectionMonitor: Audit Pid: %d", pid);
}

void CollectionMonitor::check_rules() {
    Logger::Info("CollectionMonitor: Checking Audit Rules");
}

void CollectionMonitor::remove_rules() {
    Logger::Info("CollectionMonitor: Removing auoms audit rules");
}
