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
#include "Queue.h"
#include "Config.h"
#include "Logger.h"
#include "EventQueue.h"
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

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <system_error>

#include <unistd.h>
#include <syslog.h>
#include <sys/resource.h>

#include "env_config.h"
#include "LockFile.h"

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
    // Enable core dumps
    struct rlimit limits;
    limits.rlim_cur = RLIM_INFINITY;
    limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limits);


    std::string config_file = AUOMS_CONF;
    bool netlink_only = false;

    int opt;
    while ((opt = getopt(argc, argv, "nc:")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'n':
                netlink_only = true;
                break;
            default:
                usage();
        }
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
    std::string data_dir = AUOMS_DATA_DIR;
    std::string run_dir = AUOMS_RUN_DIR;

    if (config.HasKey("outconf_dir")) {
        outconf_dir = config.GetString("outconf_dir");
    }

    if (config.HasKey("rules_dir")) {
        rules_dir = config.GetString("rules_dir");
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

    std::vector<std::string> allowed_socket_dirs;
    if (!config.HasKey("allowed_output_socket_dirs")) {
        Logger::Error("Required config parameter missing: allowed_output_socket_dirs");
        exit(1);
    } else {
        if (!parsePath(allowed_socket_dirs, config.GetString("allowed_output_socket_dirs"))) {
            exit(1);
        }
    }

    std::string input_socket_path = run_dir + "/input.socket";
    std::string status_socket_path = run_dir + "/status.socket";
    std::string queue_file = data_dir + "/queue.dat";
    std::string cursor_dir = data_dir + "/outputs";
    size_t queue_size = 10*1024*1024;

    if (config.HasKey("input_socket_path")) {
        input_socket_path = config.GetString("input_socket_path");
    }

    if (config.HasKey("status_socket_path")) {
        status_socket_path = config.GetString("status_socket_path");
    }

    if (config.HasKey("queue_file")) {
        queue_file = config.GetString("queue_file");
    }

    if (queue_file.empty()) {
        Logger::Error("Invalid 'queue_file' value");
        exit(1);
    }

    if (config.HasKey("queue_size")) {
        try {
            queue_size = config.GetUint64("queue_size");
        } catch(std::exception& ex) {
            Logger::Error("Invalid 'queue_size' value: %s", config.GetString("queue_size").c_str());
            exit(1);
        }
    }

    std::string lock_file = data_dir + "/auoms.lock";

    if (config.HasKey("lock_file")) {
        lock_file = config.GetString("lock_file");
    }

    if (queue_size < Queue::MIN_QUEUE_SIZE) {
        Logger::Warn("Value for 'queue_size' (%ld) is smaller than minimum allowed. Using minimum (%ld).", queue_size, Queue::MIN_QUEUE_SIZE);
        exit(1);
    }

    bool use_syslog = true;
    if (config.HasKey("use_syslog")) {
        use_syslog = config.GetBool("use_syslog");
    }

    if (use_syslog) {
        Logger::OpenSyslog("auoms", LOG_DAEMON);
    }

    bool reset_queue = false;
    bool reset_flagged = false;

    Logger::Info("Trying to acquire singleton lock");
    LockFile singleton_lock(lock_file);
    switch(singleton_lock.Lock()) {
        case LockFile::FAILED:
            Logger::Error("Failed to acquire singleton lock (%s): %s", lock_file.c_str(), std::strerror(errno));
            exit(1);
            break;
        case LockFile::FLAGGED:
            reset_flagged = true;
        case LockFile::PREVIOUSLY_ABANDONED:
            reset_queue = true;
            break;
        case LockFile::INTERRUPTED:
            Logger::Error("Failed to acquire singleton lock (%s): Interrupted", lock_file.c_str());
            exit(1);
            break;
    }
    Logger::Info("Acquire singleton lock");

    // This will block signals like SIGINT and SIGTERM
    // They will be handled once Signals::Start() is called.
    Signals::Init();

    if (reset_queue) {
        if (reset_flagged) {
            Logger::Info("Resetting queue due to upgrade.");
        } else {
            Logger::Warn("Previous instance may have crashed, resetting queue as a precaution.");
        }
        if (PathExists(queue_file)) {
            try {
                RemoveFile(queue_file, true);
            } catch (std::system_error& ex) {
                Logger::Error("Failed to remove queue file: %s", ex.what());
            }
        }

        try {
            auto list = GetDirList(cursor_dir);
            for (auto& name: list) {
                RemoveFile(cursor_dir + "/" + name, true);
            }
        } catch (std::exception& ex) {
            Logger::Error("Failed to remove cursors: %s", ex.what());
        }
    }

    auto queue = std::make_shared<Queue>(queue_file, queue_size);
    try {
        Logger::Info("Opening queue: %s", queue_file.c_str());
        queue->Open();
    } catch (std::runtime_error& ex) {
        Logger::Error("Failed to open queue file '%s': %s", queue_file.c_str(), ex.what());
        exit(1);
    }

    auto operational_status = std::make_shared<OperationalStatus>(status_socket_path, queue);
    if (!operational_status->Initialize()) {
        Logger::Error("Failed to initialize OperationalStatus");
        exit(1);
    }
    operational_status->Start();

    auto metrics = std::make_shared<Metrics>(queue);
    metrics->Start();

    auto syscall_metrics = std::make_shared<SyscallMetrics>(metrics);
    syscall_metrics->Start();

    auto system_metrics = std::make_shared<SystemMetrics>(metrics);
    system_metrics->Start();

    auto proc_metrics = std::make_shared<ProcMetrics>("auoms", metrics);
    proc_metrics->Start();

    Inputs inputs(input_socket_path, operational_status);
    if (!inputs.Initialize()) {
        Logger::Error("Failed to initialize inputs");
        exit(1);
    }

    CollectionMonitor collection_monitor(queue, auditd_path, collector_path, collector_config_path);
    collection_monitor.Start();

    AuditRulesMonitor rules_monitor(rules_dir, operational_status);
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

    auto filtersEngine = std::make_shared<FiltersEngine>();

    auto processTree = std::make_shared<ProcessTree>(user_db, filtersEngine);
    processTree->PopulateTree(); // Pre-populate tree

    Outputs outputs(queue, outconf_dir, cursor_dir, allowed_socket_dirs, user_db, filtersEngine, processTree);

    std::thread autosave_thread([&]() {
        Signals::InitThread();
        try {
            queue->Autosave(128*1024, 250);
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
        std::vector<std::string> allowed_socket_dirs;
        if (!config.HasKey("allowed_output_socket_dirs")) {
            Logger::Error("Config error during reload: Required config parameter missing: allowed_output_socket_dirs");
            return;
        } else {
            if (!parsePath(allowed_socket_dirs, config.GetString("allowed_output_socket_dirs"))) {
                Logger::Error("Config error during reload: Invalid config parameter: allowed_output_socket_dirs");
                return;
            }
        }
        outputs.Reload(allowed_socket_dirs);
    });

    // Start signal handling thread
    Signals::Start();

    processTree->Start();
    auto processNotify = std::make_shared<ProcessNotify>(processTree);
    processNotify->Start();

    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue);

    RawEventProcessor rep(builder, user_db, processTree, filtersEngine, metrics);
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
        processNotify->Stop();
        processTree->Stop();
        proc_metrics->Stop();
        system_metrics->Stop();
        syscall_metrics->Stop();
        metrics->Stop();
        rules_monitor.Stop();
        inputs.Stop();
        outputs.Stop(false); // Trigger outputs shutdown but don't block
        user_db->Stop(); // Stop user db monitoring
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
