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
#include "AuomsConfig.h"
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

    AuomsConfig& config = AuomsConfig::GetInstance();

    if (!config_file.empty()) {
        try {
            config.Load(config_file);
        } catch (std::runtime_error& ex) {
            Logger::Error("%s", ex.what());
            exit(1);
        }
    }

    if (config.UseSyslog()) {
        Logger::OpenSyslog("auoms", LOG_DAEMON);
    }

    config.SetNetlinkOnly(netlink_only);

    if (config.GetQueueDir().empty()) {
        Logger::Error("Invalid 'queue_file' value");
        exit(1);
    }

    auto event_prioritizer = std::make_shared<EventPrioritizer>(
                                config.GetDefaultEventPriority()
                                );
    if (!event_prioritizer->LoadFromConfig(config)) {
        Logger::Error("Failed to load EventPrioritizer config, exiting");
        exit(1);
    }
    const std::string& save_dir = config.GetSaveDirectory();
    if (!PathExists(save_dir)) {
        if (mkdir(save_dir.c_str(), 0750) != 0) {
            Logger::Error("Failed to create dir '%s': %s", save_dir.c_str(), std::strerror(errno));
            exit(1);
        }
    }

    Logger::Info("Trying to acquire singleton lock");
    const std::string& lock_file = config.GetLockFile();
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
    if (!config.DisableCGroups()) {
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
    std::string queue_dir = config.GetQueueDir();
    Logger::Info("Opening queue: %s", queue_dir.c_str());
    auto queue = PriorityQueue::Open(
                    queue_dir,
                    config.GetNumberOfEventPriorities(),
                    config.GetMaxFileDataSize(),
                    config.GetMaxUnsavedFiles(),
                    config.GetMaxFsBytes(),
                    config.GetMaxFsPercentage(),
                    config.GetMinFsFreePercentage()
                    );
    if (!queue) {
        Logger::Error("Failed to open queue '%s'", queue_dir.c_str());
        exit(1);
    }

    auto operational_status = std::make_shared<OperationalStatus>(
                                    config.GetStatusSocketPath(),
                                    queue
                                    );
    if (!operational_status->Initialize()) {
        Logger::Error("Failed to initialize OperationalStatus");
        exit(1);
    }
    operational_status->Start();

    auto cmdline_redactor = std::make_shared<CmdlineRedactor>();
    const std::string& redact_dir = config.GetRedactDir();
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

    auto proc_metrics = std::make_shared<ProcMetrics>(
                            "auoms",
                            queue,
                            metrics,
                            config.GetRSSLimit(),
                            config.GetVirtLimit(),
                            config.GetRSSPercentageLimit(),
                            []() {
        Logger::Error("A memory limit was exceeded, exiting immediately");
        exit(1);
    });
    proc_metrics->Start();

    Inputs inputs(config.GetInputSocketPath(), operational_status);
    if (!inputs.Initialize()) {
        Logger::Error("Failed to initialize inputs");
        exit(1);
    }

    CollectionMonitor collection_monitor(
                            queue,
                            config.GetAuditdPath(),
                            config.GetCollectorPath(),
                            config.GetCollectorConfigPath()
                            );
    collection_monitor.Start();

    AuditRulesMonitor rules_monitor(
                            config.GetRulesDir(),
                            config.GetBacklogLimit(),
                            config.GetBacklogWaitTime(),
                            operational_status
                            );
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

    if (!config.DisableEventFiltering()) {
        filtersEngine = std::make_shared<FiltersEngine>();

        processTree = std::make_shared<ProcessTree>(user_db, filtersEngine);
        processTree->PopulateTree(); // Pre-populate tree

        outputsFilterFactory = std::shared_ptr<IEventFilterFactory>(
                                    static_cast<IEventFilterFactory*>(
                                        new OutputsEventFilterFactory(
                                            user_db, 
                                            filtersEngine, 
                                            processTree
                                            )
                                    )
                                );
    }

    Outputs outputs(
                queue,
                config.GetOutconfDir(),
                save_dir,
                outputsFilterFactory);

    std::thread autosave_thread([&]() {
        Signals::InitThread();
        try {
            queue->Saver(config.GetSaveDelay());
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
        AuomsConfig& config = AuomsConfig::GetInstance();

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
    if (!config.DisableEventFiltering()) {
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
        if (!config.DisableEventFiltering()) {
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
