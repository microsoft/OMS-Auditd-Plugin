/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "auoms_version.h"

#include "Netlink.h"
#include "Logger.h"
#include "Signals.h"
#include "AuditRules.h"
#include "StringUtils.h"
#include "UnixDomainWriter.h"
#include "ExecUtil.h"
#include "FileUtils.h"
#include "Defer.h"
#include "Gate.h"
#include "Translate.h"
#include "UnixDomainListener.h"
#include "Event.h"

#include <iostream>

#include <unistd.h>
#include <cstring>


#define SERVICE_NAME "auoms"
#define SERVICE_BIN "/opt/microsoft/auoms/bin/auoms"
#define SYSTEMD_SERVICE_FILE "/opt/microsoft/auoms/auoms.service"
#define SYSTEMCTL_PATH "/bin/systemctl"

void usage()
{
    std::cerr <<
              "Usage:\n"
              "auomsctl [options]\n"
              "\n"
              "-l [<key>]            - List kernel audit rules.\n"
              "-s                    - List kernel audit settings.\n"
              "-D [<key>]            - Delete kernel audit rules.\n"
              "-R <rules file>       - Set kernel audit rules from files.\n"
              "-v                    - Print auoms version.\n"
              "merge <rules files>   - Merge then print rules files.\n"
              "diff <rules file>     - Diff then print two rules files.\n"
              "desired [-c <config>] - List desired rules as understood by auoms\n"
              "is-enabled            - Report enabled/disabled status ot auoms service\n"
              "enable                - Enable the auoms service (will start auoms if it is not running)\n"
              "disable               - Disable the auoms service (will stop auoms if it is running)\n"
              "status                - Show auoms status\n"
            ;
}

int show_audit_status() {
    if (geteuid() != 0) {
        std::cerr << "Must be root to request audit status" << std::endl;
        return 1;
    }

    Signals::Init();
    Signals::Start();

    Netlink netlink;
    netlink.SetQuite();

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket");
        return 1;
    }

    audit_status status;
    ret = netlink.AuditGet(status);

    netlink.Close();

    if (ret != 0) {
        Logger::Error("Failed to retrieve audit status: %s\n", strerror(-ret));
        return 1;
    }

    std::cout << "enabled " << status.enabled << std::endl;
    std::cout << "failure " << status.failure << std::endl;
    std::cout << "pid " << status.pid << std::endl;
    std::cout << "rate_limit " << status.rate_limit << std::endl;
    std::cout << "backlog_limit " << status.backlog_limit << std::endl;
    std::cout << "lost " << status.lost << std::endl;
    std::cout << "backlog " << status.backlog << std::endl;

    return 0;
}

int list_rules(bool raw_fmt, const std::string& key) {
    if (geteuid() != 0) {
        std::cerr << "Must be root to request audit rules" << std::endl;
        return 1;
    }

    Signals::Init();
    Signals::Start();

    Netlink netlink;
    netlink.SetQuite();

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket: %s", strerror(-ret));
        return 1;
    }

    std::vector<AuditRule> rules;
    ret = netlink.AuditListRules(rules);
    netlink.Close();

    if (ret != 0) {
        Logger::Error("Failed to retrieve audit rules: %s\n", strerror(-ret));
        return 1;
    }

    if (rules.empty()) {
        std::cout << "No rules" << std::endl;
    }

    for (auto& rule: rules) {
        if (key.empty() || rule.GetKeys().count(key) > 0) {
            if (raw_fmt) {
                std::cout << rule.RawText() << std::endl;
            } else {
                std::cout << rule.CanonicalText() << std::endl;
            }
        }
    }

    return 0;
}

int delete_rules(const std::string& key) {
    if (geteuid() != 0) {
        std::cerr << "Must be root to delete audit rules" << std::endl;
        return 1;
    }

    Signals::Init();
    Signals::Start();

    Netlink netlink;
    netlink.SetQuite();

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket");
        return 1;
    }

    uint32_t enabled = 0;
    ret = netlink.AuditGetEnabled(enabled);
    if (ret != 0) {
        Logger::Error("Failed to get audit status");
        return 1;
    }

    if (enabled == 2) {
        Logger::Error("Audit rules are locked");
        return 2;
    }

    std::vector<AuditRule> rules;
    ret = netlink.AuditListRules(rules);

    if (ret != 0) {
        Logger::Error("Failed to retrieve audit rules: %s\n", strerror(errno));
        return 1;
    }

    int exit_code = 0;
    for (auto& rule: rules) {
        if (key.empty() || rule.GetKeys().count(key) > 0) {
            ret = netlink.AuditDelRule(rule);
            if (ret != 0) {
                Logger::Error("Failed to delete audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
                exit_code = 1;
            }
        }
    }

    netlink.Close();

    return exit_code;
}

int load_rules(const std::string& path) {
    if (geteuid() != 0) {
        std::cerr << "Must be root to load audit rules" << std::endl;
        return 1;
    }

    int exit_code = 0;
    try {
        auto lines = ReadFile(path);
        auto rules = ParseRules(lines);

        Signals::Init();
        Signals::Start();

        Netlink netlink;
        netlink.SetQuite();

        auto ret = netlink.Open(nullptr);
        if (ret != 0) {
            Logger::Error("Failed to open Netlink socket");
            return 1;
        }

        uint32_t enabled = 0;
        ret = netlink.AuditGetEnabled(enabled);
        if (ret != 0) {
            Logger::Error("Failed to get audit status");
            return 1;
        }

        if (enabled == 2) {
            Logger::Error("Audit rules are locked");
            return 2;
        }

        for (auto& rule: rules) {
            ret = netlink.AuditAddRule(rule);
            if (ret != 0) {
                Logger::Error("Failed to add audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
                exit_code = 1;
            }
        }

        netlink.Close();
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return exit_code;
}

int print_rules(const std::string& path) {
    try {
        auto lines = ReadFile(path);
        auto rules = ParseRules(lines);
        for (auto& rule: rules) {
            std::cout << rule.CanonicalText() << std::endl;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

int merge_rules(const std::string& file1, const std::string& file2) {
    try {
        auto rules1 = ParseRules(ReadFile(file1));
        auto rules2 = ParseRules(ReadFile(file2));
        auto merged_rules = MergeRules(rules1, rules2);
        for (auto& rule: merged_rules) {
            std::cout << rule.CanonicalText() << std::endl;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

int diff_rules(const std::string& file1, const std::string& file2) {
    try {
        auto rules1 = MergeRules(ParseRules(ReadFile(file1)));
        auto rules2 = MergeRules(ParseRules(ReadFile(file2)));
        auto diffed_rules = DiffRules(rules1, rules2, "");
        for (auto& rule: diffed_rules) {
            std::cout << rule.CanonicalText() << std::endl;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

int show_auoms_status() {
    if (geteuid() != 0) {
        std::cerr << "Must be root to request auoms status" << std::endl;
        return 1;
    }

    Signals::Init();
    Signals::Start();

    UnixDomainWriter io("/var/run/auoms/status.socket");
    if (!io.Open()) {
        std::cout << "auoms is not running" << std::endl;
        return 1;
    }

    char buf[1024];
    while(true) {
        auto nr = io.Read(buf, sizeof(buf), 100, []() { return !Signals::IsExit(); });
        if (nr <= 0) {
            break;
        }
        std::cout << std::string(buf, nr);
    }
    return 0;
}

std::string get_service_util_path() {
    std::string path = "/sbin/service";
    if (!PathExists(path)) {
        path = "/usr/sbin/service";
        if (!PathExists(path)) {
            throw std::runtime_error("Could not find path to 'service' utility");
        }
    }
    return path;
}

bool is_service_sysv_enabled() {
    std::string service_name(SERVICE_NAME);
    int count = 0;
    for (auto& dir: GetDirList("/etc")) {
        if (dir.size() == 5 && starts_with(dir, "rc") && ends_with(dir, ".d")) {
            for (auto& file: GetDirList("/etc/" + dir)) {
                if (file.size() == 3+service_name.size() && file[0] == 'S' && ends_with(file, service_name)) {
                    count += 1;
                }
            }
        }
    }
    return count > 0;
}

bool is_service_enabled() {
    std::string service_name(SERVICE_NAME);
    std::string path = SYSTEMCTL_PATH;
    if (!PathExists(path)) {
        return is_service_sysv_enabled();
    }

    std::vector<std::string> args;
    args.emplace_back("is-enabled");
    args.emplace_back(service_name);

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + path + " is-enabled " + service_name + "': " + out);
    } else if (ret != 0) {
        return false;
    }
    return true;
}

void enable_service() {
    std::string path = SYSTEMCTL_PATH;
    std::vector<std::string> args;

    if (PathExists(path)) {
        args.emplace_back("enable");
        args.emplace_back(SYSTEMD_SERVICE_FILE);
    } else if (PathExists("/sbin/chkconfig")) {
        args.emplace_back("--add");
        args.emplace_back(SERVICE_NAME);
    } else if (PathExists("/usr/sbin/update-rc.d")) {
        args.emplace_back(SERVICE_NAME);
        args.emplace_back("defaults");
    } else {
        throw std::runtime_error("Failed to locate service control utility");
    }

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        throw std::runtime_error("Failed to enable service with command '" + cmd_str + "': " + out);
    }
}

void disable_service() {
    std::string path = SYSTEMCTL_PATH;
    std::vector<std::string> args;

    if (PathExists(path)) {
        args.emplace_back("disable");
        args.emplace_back(SERVICE_NAME);
    } else if (PathExists("/sbin/chkconfig")) {
        args.emplace_back("--del");
        args.emplace_back(SERVICE_NAME);
    } else if (PathExists("/usr/sbin/update-rc.d")) {
        args.emplace_back("-f");
        args.emplace_back(SERVICE_NAME);
        args.emplace_back("remove");
    } else {
        throw std::runtime_error("Failed to locate service control utility");
    }

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        throw std::runtime_error("Failed to disable service with command '" + cmd_str + "': " + out);
    }
}

bool is_auoms_running() {
    std::string path = "/usr/bin/pgrep";
    std::vector<std::string> args;
    args.emplace_back("-x");
    args.emplace_back("-f");
    args.emplace_back("-U");
    args.emplace_back("0");
    args.emplace_back(SERVICE_BIN);

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        return false;
    }
    return true;
}

bool kill_auoms() {
    std::string path = "/usr/bin/pkill";
    std::vector<std::string> args;
    args.emplace_back("-KILL");
    args.emplace_back("-x");
    args.emplace_back("-f");
    args.emplace_back("-U");
    args.emplace_back("0");
    args.emplace_back(SERVICE_BIN);

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        return false;
    }
    return true;
}

bool start_service() {
    if (is_auoms_running()) {
        return true;
    }

    std::string path = get_service_util_path();
    std::vector<std::string> args;
    args.emplace_back(SERVICE_NAME);
    args.emplace_back("start");

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        throw std::runtime_error("Failed to start service with command '" + cmd_str + "': " + out);
    }

    return is_auoms_running();
}

bool stop_service() {
    if (!is_auoms_running()) {
        return true;
    }

    std::string path = get_service_util_path();
    std::vector<std::string> args;
    args.emplace_back(SERVICE_NAME);
    args.emplace_back("stop");

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        throw std::runtime_error("Failed to start service with command '" + cmd_str + "': " + out);
    }

    return !is_auoms_running();
}

int enable_auoms() {
    if (geteuid() != 0) {
        std::cerr << "Must be root to enable auoms" << std::endl;
        return 1;
    }

    // Return
    //      0 on success
    //      1 if service could not be enabled
    //      2 if service did not start
    try {
        bool is_enabled = is_service_enabled();
        bool is_running = is_auoms_running();
        if (is_enabled && is_running) {
            return 0;
        }

        if (!is_enabled) {
            enable_service();
        }

        if (!is_running) {
            if (!start_service()) {
                return 2;
            }
        }

        if (is_auoms_running()) {
            return 0;
        } else {
            return 2;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}

int remove_rules_from_audit_files() {
    if (RemoveAuomsRulesAuditdFiles()) {
        Cmd cmd(AUGENRULES_BIN, {}, Cmd::NULL_STDIN|Cmd::COMBINE_OUTPUT);
        std::string output;
        auto ret = cmd.Run(output);
        if (ret != 0) {
            std::cerr << "augenrules failed: " << cmd.FailMsg() << std::endl;
            std::cerr << "augenrules output: " << output << std::endl;
            return 1;
        }
    }
    return 0;
}

int disable_auoms() {
    if (geteuid() != 0) {
        std::cerr << "Must be root to disable auoms" << std::endl;
        return 1;
    }

    // Return
    //      0 on success
    //      1 if service could not be disabled

    try {
        bool is_enabled = is_service_enabled();
        bool is_running = is_auoms_running();

        if (is_running) {
            if (!stop_service()) {
                kill_auoms();
            }
        }

        if (is_enabled) {
            disable_service();
        }

        if (is_auoms_running()) {
            kill_auoms();
        }

        auto dret = delete_rules(AUOMS_RULE_KEY);
        auto fret = remove_rules_from_audit_files();
        if (dret != 0 || fret != 0) {
            return 1;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}

int tap_audit() {
    if (geteuid() != 0) {
        std::cerr << "Must be root to collect audit events" << std::endl;
        return 1;
    }

    Netlink netlink;
    Gate _stop_gate;

    std::function handler = [](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        if (type >= AUDIT_FIRST_USER_MSG) {
            std::cout << "type=" << RecordTypeToName(static_cast<RecordType>(type)) << " " << std::string_view(reinterpret_cast<const char*>(data), len) << std::endl;
        }
        return false;
    };

    Signals::Init();
    Signals::Start();

    Logger::Info("Connecting to AUDIT NETLINK socket");
    auto ret = netlink.Open(handler);
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return 1;
    }
    Defer _close_netlink([&netlink]() { netlink.Close(); });

    uint32_t our_pid = getpid();

    Logger::Info("Checking assigned audit pid");
    audit_status status;
    ret = netlink.AuditGet(status);
    if (ret != 0) {
        Logger::Error("Failed to get audit status: %s", std::strerror(-ret));
        return 1;
    }
    uint32_t pid = status.pid;
    uint32_t enabled = status.enabled;

    if (pid != 0 && PathExists("/proc/" + std::to_string(pid))) {
        Logger::Error("There is another process (pid = %d) already assigned as the audit collector", pid);
        return 1;
    }

    Logger::Info("Enabling AUDIT event collection");
    ret = netlink.AuditSetPid(our_pid);
    if (ret != 0) {
        Logger::Error("Failed to set audit pid: %s", std::strerror(-ret));
        return 1;
    }
    if (enabled == 0) {
        ret = netlink.AuditSetEnabled(1);
        if (ret != 0) {
            Logger::Error("Failed to enable auditing: %s", std::strerror(-ret));
            return 1;
        }
    }
    Defer _revert_enabled([&netlink,enabled]() {
        if (enabled == 0) {
            auto ret = netlink.AuditSetEnabled(0);
            if (ret != 0) {
                Logger::Error("Failed to disable auditing: %s", std::strerror(-ret));
                return 1;
            }
        }
    });

    Signals::SetExitHandler([&_stop_gate]() { _stop_gate.Open(); });

    while(!Signals::IsExit()) {
        if (_stop_gate.Wait(Gate::OPEN, 1000)) {
            return 0;
        }

        pid = 0;
        auto ret = netlink.AuditGetPid(pid);
        if (ret != 1) {
            if (ret < 0) {
                Logger::Error("Failed to get audit pid");
                return 1;
            }
        } else {
            if (pid != our_pid) {
                Logger::Warn("Another process (pid = %d) has taken over AUDIT NETLINK event collection.", pid);
                return 1;
            }
        }
    }
    return 0;
}

void handle_raw_connection(int fd) {
    std::array<uint8_t, 1024*256> data;

    for (;;) {
        auto nread = 0;
        auto nleft = 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    Logger::Error("Failed to read frame size: %s", std::strerror(errno));
                    return;
                } else {
                    return;
                }
            }
            nleft -= nr;
            nread += nr;
        }
        auto size = *reinterpret_cast<uint32_t *>(data.data()) & 0x00FFFFFF;
        if (size <= 4 || size > 1024 * 256) {
            Logger::Error("Invalid frame size");
        }
        nread = 4;
        nleft = size - 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    Logger::Error("Failed to read frame: %s", std::strerror(errno));
                    return;
                } else {
                    return;
                }
            }
            nleft -= nr;
            nread += nr;
        }

        Event event(data.data(), size);
        std::cout << EventToRawText(event, true);

        std::array<uint8_t, 8+8+4> ack_data;
        *reinterpret_cast<uint64_t*>(ack_data.data()) = event.Seconds();
        *reinterpret_cast<uint32_t*>(ack_data.data()+8) = event.Milliseconds();
        *reinterpret_cast<uint64_t*>(ack_data.data()+12) = event.Serial();
        auto nw = write(fd, ack_data.data(), ack_data.size());
        if (nw != ack_data.size()) {
            if (nw < 0) {
                Logger::Error("Failed to write ack: %s", std::strerror(errno));
            } else {
                Logger::Error("Failed to write ack: no enough bytes written");
            }
            return;
        }
    }
}

bool reload_auoms() {
    std::string path = "/usr/bin/pkill";
    std::vector<std::string> args;
    args.emplace_back("-HUP");
    args.emplace_back("-x");
    args.emplace_back("-f");
    args.emplace_back("-U");
    args.emplace_back("0");
    args.emplace_back(SERVICE_BIN);

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        return false;
    }
    return true;
}

int monitor_auoms_events() {
    if (geteuid() != 0) {
        std::cerr << "Must be root to collect audit events" << std::endl;
        return 1;
    }

    std::string sock_path = "/var/run/auoms/auomsctl.socket";
    std::string config_path = "/etc/opt/microsoft/auoms/outconf.d/auomsctl.conf";

    Signals::Init();
    Signals::Start();

    UnixDomainListener listener(sock_path, 0666);
    if (!listener.Open()) {
        return -1;
    }

    Signals::SetExitHandler([&listener]() { listener.Close(); });

    std::vector<std::string> lines({
        "output_format = raw",
        "output_socket = " + sock_path,
        "enable_ack_mode = true",
    });

    WriteFile(config_path, lines);
    reload_auoms();

    int retcode = 0;
    std::cerr << "Waiting for connection" << std::endl;
    int fd = listener.Accept();
    if (fd < 0) {
        retcode = 1;
    } else {
        std::cerr << "Connected" << std::endl;
        handle_raw_connection(fd);
        close(fd);
    }

    listener.Close();
    unlink(config_path.c_str());
    reload_auoms();

    return retcode;
}

int main(int argc, char**argv) {
    if (argc < 2 || strlen(argv[1]) < 2) {
        usage();
        exit(1);
    }

    if (strcmp(argv[1], "-v") == 0) {
        std::cout << std::string(AUOMS_VERSION) << std::endl;
        return 0;
    } else if (strcmp(argv[1], "-s") == 0) {
        return show_audit_status();
    } else if (strcmp(argv[1], "-l") == 0) {
        std::string key;
        if (argc > 2) {
            key = argv[2];
        }
        return list_rules(false, key);
    } else if (strcmp(argv[1], "-rl") == 0) {
        std::string key;
        if (argc > 2) {
            key = argv[2];
        }
        return list_rules(true, key);
    } else if (strcmp(argv[1], "-D") == 0) {
        std::string key;
        if (argc > 2) {
            key = argv[2];
        }
        return delete_rules(key);
    } else if (strcmp(argv[1], "-R") == 0) {
        if (argc < 3) {
            usage();
            exit(1);
        }
        return load_rules(argv[2]);
    } else if (strcmp(argv[1], "-p") == 0) {
        if (argc < 3) {
            usage();
            exit(1);
        }
        return print_rules(argv[2]);
    } else if (strcmp(argv[1], "-m") == 0) {
        if (argc < 4) {
            usage();
            exit(1);
        }
        return merge_rules(argv[2], argv[3]);
    } else if (strcmp(argv[1], "-d") == 0) {
        if (argc < 4) {
            usage();
            exit(1);
        }
        return diff_rules(argv[2], argv[3]);
    } else if (strcmp(argv[1], "status") == 0) {
        return show_auoms_status();
    } else if (strcmp(argv[1], "is-enabled") == 0) {
        try {
            if (is_service_enabled()) {
                std::cout << "enabled" << std::endl;
                return 0;
            } else {
                std::cout << "disabled" << std::endl;
                return 1;
            }
        } catch (std::exception& ex) {
            std::cerr << ex.what() << std::endl;
            return 2;
        }
    } else if (strcmp(argv[1], "enable") == 0) {
        return enable_auoms();
    } else if (strcmp(argv[1], "disable") == 0) {
        return disable_auoms();
    } else if (strcmp(argv[1], "tap") == 0) {
        return tap_audit();
    } else if (strcmp(argv[1], "monitor") == 0) {
        return monitor_auoms_events();
    } else if (strcmp(argv[1], "reload") == 0) {
        return reload_auoms();
    }

    usage();
    exit(1);
}
