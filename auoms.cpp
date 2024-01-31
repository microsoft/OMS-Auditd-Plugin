/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "RawEventProcessor.h"
#include "StdoutWriter.h"
#include "StdinReader.h"
#include "UnixDomainWriter.h"
#include "Signals.h"
#include "PriorityQueue.h"
#include "Config.h"
#include "Logger.h"
#include "EventQueue.h"
#include "EventPrioritizer.h"
#include "UserDB.h"
#include "Inputs.h"
#include "Outputs.h"
#include "CollectionMonitor.h"
#include "AuditRulesMonitor.h"
#include "OperationalStatus.h"
#include "FileUtils.h"
#include "FiltersEngine.h"
#include "ProcessTree.h"
#include "Metrics.h"
#include "SyscallMetrics.h"
#include "SystemMetrics.h"
#include "ProcMetrics.h"
#include "FileUtils.h"
#include "CPULimits.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <system_error>

#include <unistd.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "env_config.h"
#include "LockFile.h"
#include "StringUtils.h"

void usage()
{
    std::cerr <<
              "Usage:\n"
              "auoms [-c <config>]\n"
              "\n"
              "-c <config>   - The path to the config file.\n"
            ;
    exit(1);
}

bool parsePath(std::vector<std::string>& dirs, const std::string& path_str) {
    std::string str = path_str;
    while (!str.empty()) {
        auto idx = str.find_first_of(':', 0);
        std::string dir;
        if (idx == std::string::npos) {
            dir = str;
            str.clear();
        } else {
            dir = str.substr(0, idx);
            str = str.substr(idx+1);
        }
        if (dir.length() < 2 || dir[0] != '/') {
            Logger::Error("Config parameter 'allowed_socket_dirs' has invalid value");
            return false;
        }
        if (dir[dir.length()-1] != '/') {
            dir += '/';
        }
        dirs.push_back(dir);
    }
    return true;
}

int main(int argc, char**argv) {
    std::string config_file = AUOMS_CONF;
    bool netlink_only = false;
    bool debug_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "c:dn")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'n':
                netlink_only = true;
                break;
            default:
                usage();
        }
    }

    if (debug_mode) {
        // Enable core dumps
        struct rlimit limits;
        limits.rlim_cur = RLIM_INFINITY;
        limits.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_CORE, &limits);
    }

    Config config;

    if (!config_file.empty()) {
        try {
            config.Load(config_file);
        } catch (std::runtime_error& ex) {
            Logger::Error("%s", ex.what());
            exit(1);
        }
    }

    std::string auditd_path = AUDITD_BIN;
    std::string collector_path = AUOMSCOLLECT_EXE;
    std::string collector_config_path = "";

    std::string outconf_dir = AUOMS_OUTCONF_DIR;
    std::string rules_dir = AUOMS_RULES_DIR;
    std::string redact_dir = AUOMS_REDACT_DIR;
    std::string data_dir = AUOMS_DATA_DIR;
    std::string run_dir = AUOMS_RUN_DIR;

    uint32_t backlog_limit = 10240;
    uint32_t backlog_wait_time = 1;

    if (config.HasKey("outconf_dir")) {
        outconf_dir = config.GetString("outconf_dir");
    }

    if (config.HasKey("rules_dir")) {
        rules_dir = config.GetString("rules_dir");
    }

    if (config.HasKey("redact_dir")) {
        redact_dir = config.GetString("redact_dir");
    }

    if (config.HasKey("data_dir")) {
        data_dir = config.GetString("data_dir");
    }

    if (config.HasKey("run_dir")) {
        run_dir = config.GetString("run_dir");
    }

    if (config.HasKey("auditd_path")) {
        auditd_path = config.GetString("auditd_path");
    }

    if (netlink_only) {
        auditd_path = "/does/not/exist";
    }

    if (config.HasKey("collector_path")) {
        collector_path = config.GetString("collector_path");
    }

    if (config.HasKey("collector_config_path")) {
        collector_config_path = config.GetString("collector_config_path");
    }

    if (config.HasKey("backlog_limit")) {
        backlog_limit = static_cast<uint32_t>(config.GetUint64("backlog_limit"));
    }

    if (config.HasKey("backlog_wait_time")) {
        backlog_wait_time = static_cast<uint32_t>(config.GetUint64("backlog_wait_time"));
    }

    std::string input_socket_path = run_dir + "/input.socket";
    std::string status_socket_path = run_dir + "/status.socket";

    if (config.HasKey("input_socket_path")) {
        input_socket_path = config.GetString("input_socket_path");
    }

    if (config.HasKey("status_socket_path")) {
        status_socket_path = config.GetString("status_socket_path");
    }

    std::string save_dir = data_dir + "/save";

    if (config.HasKey("save_dir")) {
        save_dir = config.GetString("save_dir");
    }

    int num_priorities = 8;
    size_t max_file_data_size = 1024*1024;
    size_t max_unsaved_files = 128;
    size_t max_fs_bytes = 1024*1024*1024;
    double max_fs_pct = 10;
    double min_fs_free_pct = 5;
    long save_delay = 250;

    std::string queue_dir = data_dir + "/queue";

    if (config.HasKey("queue_dir")) {
        queue_dir = config.GetString("queue_dir");
    }

    if (queue_dir.empty()) {
        Logger::Error("Invalid 'queue_file' value");
        exit(1);
    }

    if (config.HasKey("queue_num_priorities")) {
        num_priorities = config.GetUint64("queue_num_priorities");
    }

    if (config.HasKey("queue_max_file_data_size")) {
        max_file_data_size = config.GetUint64("queue_max_file_data_size");
    }

    if (config.HasKey("queue_max_unsaved_files")) {
        max_unsaved_files = config.GetUint64("queue_max_unsaved_files");
    }

    if (config.HasKey("queue_max_fs_bytes")) {
        max_fs_bytes = config.GetUint64("queue_max_fs_bytes");
    }

    if (config.HasKey("queue_max_fs_pct")) {
        max_fs_pct = config.GetDouble("queue_max_fs_pct");
    }

    if (config.HasKey("queue_min_fs_free_pct")) {
        min_fs_free_pct = config.GetDouble("queue_min_fs_free_pct");
    }

    if (config.HasKey("queue_save_delay")) {
        save_delay = config.GetUint64("queue_save_delay");
    }

    std::string lock_file = data_dir + "/auoms.lock";

    if (config.HasKey("lock_file")) {
        lock_file = config.GetString("lock_file");
    }

    uint64_t rss_limit = 1024L*1024L*1024L;
    uint64_t virt_limit = 4096L*1024L*1024L;
    double rss_pct_limit = 5;

    if (config.HasKey("rss_limit")) {
        rss_limit = config.GetUint64("rss_limit");
    }

    if (config.HasKey("rss_pct_limit")) {
        rss_pct_limit = config.GetDouble("rss_pct_limit");
    }

    if (config.HasKey("virt_limit")) {
        virt_limit = config.GetUint64("virt_limit");
    }

    bool use_syslog = true;
    if (config.HasKey("use_syslog")) {
        use_syslog = config.GetBool("use_syslog");
    }

    if (use_syslog) {
        Logger::OpenSyslog("auoms", LOG_DAEMON);
    }

    bool disable_cgroups = false;
    if (config.HasKey("disable_cgroups")) {
        disable_cgroups = config.GetBool("disable_cgroups");
    }

    // Set cgroup defaults
    if (!config.HasKey(CPU_SOFT_LIMIT_NAME)) {
        config.SetString(CPU_SOFT_LIMIT_NAME, "5");
    }

    if (!config.HasKey(CPU_HARD_LIMIT_NAME)) {
        config.SetString(CPU_HARD_LIMIT_NAME, "25");
    }

    bool disable_event_filtering = false;
    if (config.HasKey("disable_event_filtering")) {
        disable_event_filtering = config.GetBool("disable_event_filtering");
    }

    // Set EventPrioritizer defaults
    if (!config.HasKey("event_priority_by_syscall")) {
        config.SetString("event_priority_by_syscall", R"json({"execve":2,"execveat":2,"*":3})json");
    }

    if (!config.HasKey("event_priority_by_record_type")) {
        config.SetString("event_priority_by_record_type", R"json({"AUOMS_EXECVE":2,"AUOMS_SYSCALL":3,"AUOMS_PROCESS_INVENTORY":1})json");
    }

    if (!config.HasKey("event_priority_by_record_type_category")) {
        config.SetString("event_priority_by_record_type_category", R"json({"AUOMS_MSG":0, "USER_MSG":1,"SELINUX":1,"APPARMOR":1})json");
    }

    int default_priority = 4;
    if (config.HasKey("default_event_priority")) {
        default_priority = static_cast<uint16_t>(config.GetUint64("default_event_priority"));
    }
    if (default_priority > num_priorities-1) {
        default_priority = num_priorities-1;
    }

    auto event_prioritizer = std::make_shared<EventPrioritizer>(default_priority);
    if (!event_prioritizer->LoadFromConfig(config)) {
        Logger::Error("Failed to load EventPrioritizer config, exiting");
        exit(1);
    }

    if (!PathExists(save_dir)) {
        if (mkdir(save_dir.c_str(), 0750) != 0) {
            Logger::Error("Failed to create dir '%s': %s", save_dir.c_str(), std::strerror(errno));
            exit(1);
        }
    }

    Logger::Info("Trying to acquire singleton lock");
    LockFile singleton_lock(lock_file);
    switch(singleton_lock.Lock()) {
        case LockFile::FAILED:
            Logger::Error("Failed to acquire singleton lock (%s): %s", lock_file.c_str(), std::strerror(errno));
            exit(1);
            break;
        case LockFile::PREVIOUSLY_ABANDONED:
            Logger::Warn("Previous instance did not exit cleanly");
            break;
        case LockFile::INTERRUPTED:
            Logger::Error("Failed to acquire singleton lock (%s): Interrupted", lock_file.c_str());
            exit(1);
            break;
    }
    Logger::Info("Acquire singleton lock");

    std::shared_ptr<CGroupCPU> cgcpu;
    if (!disable_cgroups) {
        try {
            cgcpu = CPULimits::CGFromConfig(config, "auoms");
            // systemd may not have put auoms into the default cgroup at this point
            // Wait a few seconds before moving into the right cgroup so we avoid getting moved back out by systemd
            std::thread cg_thread([&cgcpu]() {
                Signals::InitThread();
                int sleep_time = 5;
                // Loop forever to make sure we stay in our cgroup
                while (!Signals::IsExit()) {
                    sleep(sleep_time);
                    sleep_time = 60;
                    try {
                        cgcpu->AddSelf();
                    } catch (const std::exception &ex) {
                        Logger::Error("Failed to configure cpu cgroup: %s", ex.what());
                        Logger::Warn("CPU Limits cannot be enforced");
                        return;
                    }
                }
            });
            cg_thread.detach();
        } catch (std::runtime_error &ex) {
            Logger::Error("Failed to configure cpu cgroup: %s", ex.what());
            Logger::Warn("CPU Limits cannot be enforced");
        }
    }

    // This will block signals like SIGINT and SIGTERM
    // They will be handled once Signals::Start() is called.
    Signals::Init();

    Logger::Info("Opening queue: %s", queue_dir.c_str());
    auto queue = PriorityQueue::Open(queue_dir, num_priorities, max_file_data_size, max_unsaved_files, max_fs_bytes, max_fs_pct, min_fs_free_pct);
    if (!queue) {
        Logger::Error("Failed to open queue '%s'", queue_dir.c_str());
        exit(1);
    }

    auto operational_status = std::make_shared<OperationalStatus>(status_socket_path, queue);
    if (!operational_status->Initialize()) {
        Logger::Error("Failed to initialize OperationalStatus");
        exit(1);
    }
    operational_status->Start();

    auto cmdline_redactor = std::make_shared<CmdlineRedactor>();
    cmdline_redactor->LoadFromDir(redact_dir, true);

    std::thread rule_thread([&redact_dir, &cmdline_redactor, &operational_status]() {
        Signals::InitThread();
        int sleep_time = 1;
        // Loop forever until required rules are successfully loaded.
        while (!Signals::IsExit()) {
            if (cmdline_redactor->LoadFromDir(redact_dir, true)) {
                operational_status->ClearErrorCondition(ErrorCategory::MISSING_REDACTION_RULES);
                operational_status->SetRedactionRules(cmdline_redactor->GetRules());
                return;
            }

            auto missing_rules = join(cmdline_redactor->GetMissingRules(), ", ");
            operational_status->SetErrorCondition(ErrorCategory::MISSING_REDACTION_RULES, "Missing redaction rules: " + missing_rules);
            operational_status->SetRedactionRules(cmdline_redactor->GetRules());

            sleep(sleep_time);
            sleep_time *= 2;
            if (sleep_time > 60) {
                sleep_time = 60;
            }
        }
    });
    rule_thread.detach();

    auto metrics = std::make_shared<Metrics>("auoms", queue);
    metrics->Start();

    auto syscall_metrics = std::make_shared<SyscallMetrics>(metrics);
    syscall_metrics->Start();

    auto system_metrics = std::make_shared<SystemMetrics>(metrics);
    system_metrics->Start();

    auto proc_metrics = std::make_shared<ProcMetrics>("auoms", queue, metrics, rss_limit, virt_limit, rss_pct_limit, []() {
        Logger::Error("A memory limit was exceeded, exiting immediately");
        exit(1);
    });
    proc_metrics->Start();

    Inputs inputs(input_socket_path, operational_status);
    if (!inputs.Initialize()) {
        Logger::Error("Failed to initialize inputs");
        exit(1);
    }

    CollectionMonitor collection_monitor(queue, auditd_path, collector_path, collector_config_path);
    collection_monitor.Start();

    AuditRulesMonitor rules_monitor(rules_dir, backlog_limit, backlog_wait_time, operational_status);
    rules_monitor.Start();

    auto user_db = std::make_shared<UserDB>();
    try {
        user_db->Start();
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during user_db startup: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception during user_db startup");
        exit(1);
    }

    std::shared_ptr<FiltersEngine> filtersEngine;
    std::shared_ptr<ProcessTree> processTree;
    std::shared_ptr<IEventFilterFactory> outputsFilterFactory;

    if (!disable_event_filtering) {
        filtersEngine = std::make_shared<FiltersEngine>();

        processTree = std::make_shared<ProcessTree>(user_db, filtersEngine);
        processTree->PopulateTree(); // Pre-populate tree

        outputsFilterFactory = std::shared_ptr<IEventFilterFactory>(static_cast<IEventFilterFactory*>(new OutputsEventFilterFactory(user_db, filtersEngine, processTree)));
    }

    Outputs outputs(queue, outconf_dir, save_dir, outputsFilterFactory);

    std::thread autosave_thread([&]() {
        Signals::InitThread();
        try {
            queue->Saver(save_delay);
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in autosave thread: %s", ex.what());
            exit(1);
        }
    });

    try {
        outputs.Start();
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during outputs startup: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception during outputs startup");
        exit(1);
    }

    Signals::SetHupHandler([&outputs,&config_file](){
        Config config;

        if (config_file.size() > 0) {
            try {
                config.Load(config_file);
            } catch (std::runtime_error& ex) {
                Logger::Error("Config error during reload: %s", ex.what());
                return;
            }
        }
        outputs.Reload();
    });

    // Start signal handling thread
    Signals::Start();

    std::shared_ptr<ProcessNotify> processNotify;
    if (!disable_event_filtering) {
        processTree->Start();
        processNotify = std::make_shared<ProcessNotify>(processTree);
        processNotify->Start();
    }

    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue, event_prioritizer);

    RawEventProcessor rep(builder, user_db, cmdline_redactor, processTree, filtersEngine, metrics);
    inputs.Start();

    Signals::SetExitHandler([&inputs]() {
        Logger::Info("Stopping inputs");
        inputs.Stop();
    });

    bool remove_lock = true;
    try {
        Logger::Info("Starting input loop");
        while (!Signals::IsExit()) {
            if (!inputs.HandleData([&rep](void* ptr, size_t size) {
                rep.ProcessData(reinterpret_cast<char*>(ptr), size);
                rep.DoProcessInventory();
            })) {
                break;
            };
        }
        Logger::Info("Input loop stopped");
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception in input loop: %s", ex.what());
        remove_lock = false;
    } catch (...) {
        Logger::Error("Unexpected exception in input loop");
        remove_lock = false;
    }

    Logger::Info("Exiting");

    try {
        collection_monitor.Stop();
        if (!disable_event_filtering) {
            processNotify->Stop();
            processTree->Stop();
        }
        proc_metrics->Stop();
        system_metrics->Stop();
        syscall_metrics->Stop();
        metrics->Stop();
        rules_monitor.Stop();
        inputs.Stop();
        outputs.Stop(false); // Trigger outputs shutdown but don't block
        user_db->Stop(); // Stop user db monitoring
        metrics->FlushLogMetrics();
        queue->Close(); // Close queue, this will trigger exit of autosave thread
        outputs.Wait(); // Wait for outputs to finish shutdown
        autosave_thread.join(); // Wait for autosave thread to exit
        operational_status->Stop();
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during exit: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception during exit");
        exit(1);
    }

    if (remove_lock) {
        singleton_lock.Unlock();
    }

    exit(0);
}
