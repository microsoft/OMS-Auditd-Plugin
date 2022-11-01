/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "StdoutWriter.h"
#include "StdinReader.h"
#include "UnixDomainWriter.h"
#include "Signals.h"
#include "SPSCDataQueue.h"
#include "PriorityQueue.h"
#include "Config.h"
#include "Logger.h"
#include "EventQueue.h"
#include "Output.h"
#include "RawEventRecord.h"
#include "RawEventAccumulator.h"
#include "Netlink.h"
#include "FileWatcher.h"
#include "Defer.h"
#include "Gate.h"
#include "FileUtils.h"
#include "Metrics.h"
#include "ProcMetrics.h"
#include "CPULimits.h"
#include "SchedPriority.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <thread>
#include <system_error>
#include <csignal>

#include <unistd.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "env_config.h"
#include "LockFile.h"
#include "EventPrioritizer.h"
#include "CPULimits.h"

void usage()
{
    std::cerr <<
              "Usage:\n"
              "auomscollect [-c <config>]\n"
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


void DoStdinCollection(SPSCDataQueue& raw_queue, std::shared_ptr<Metric>& bytes_metric, std::shared_ptr<Metric>& records_metric, std::shared_ptr<Metric>& lost_bytes_metric, std::shared_ptr<Metric>& lost_segments_metric) {
    StdinReader reader;

    try {
        for (;;) {
            size_t loss_bytes = 0;
            auto ptr = raw_queue.Allocate(RawEventRecord::MAX_RECORD_SIZE, &loss_bytes);
            if (ptr == nullptr) {
                return;
            }
            if (loss_bytes > 0) {
                lost_bytes_metric->Update(loss_bytes);
                lost_segments_metric->Update(1);
                loss_bytes = 0;
            }
            *reinterpret_cast<RecordType*>(ptr) = RecordType::UNKNOWN;
            ssize_t nr = reader.ReadLine(reinterpret_cast<char*>(ptr+sizeof(RecordType)), RawEventRecord::MAX_RECORD_SIZE-sizeof(RecordType), 100, [] {
                return Signals::IsExit();
            });
            if (nr > 0) {
                // Some versions of auditd will append interpreted data to the record line
                // The interpreted data is separated from the record data by a \x1d char.
                auto str_size = nr;
                auto str = std::string_view(reinterpret_cast<char*>(ptr+sizeof(RecordType)), nr);
                // Look for the \x1d char and exclude it and any data that follows
                auto idx = str.find_first_of('\x1d');
                if (idx != std::string_view::npos) {
                    str_size = idx;
                }
                raw_queue.Commit(str_size+sizeof(RecordType));
                bytes_metric->Update(nr);
                records_metric->Update(1.0);
            } else if (nr == StdinReader::TIMEOUT) {
                if (Signals::IsExit()) {
                    Logger::Info("Exiting input loop");
                    break;
                }
            } else { // nr == StdinReader::CLOSED, StdinReader::FAILED or StdinReader::INTERRUPTED
                if (nr == StdinReader::CLOSED) {
                    Logger::Info("STDIN closed, exiting input loop");
                } else if (nr == StdinReader::FAILED) {
                    Logger::Error("Encountered an error while reading STDIN, exiting input loop");
                }
                break;
            }
        }
    } catch (const std::exception &ex) {
        Logger::Error("Unexpected exception in input loop: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception in input loop");
        exit(1);
    }
}

bool DoNetlinkCollection(SPSCDataQueue& raw_queue, std::shared_ptr<Metric>& bytes_metric, std::shared_ptr<Metric>& records_metric, std::shared_ptr<Metric>& lost_bytes_metric, std::shared_ptr<Metric>& lost_segments_metric) {
    // Request that that this process receive a SIGTERM if the parent process (thread in parent) dies/exits.
    auto ret = prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (ret != 0) {
        Logger::Warn("prctl(PR_SET_PDEATHSIG, SIGTERM) failed: %s", std::strerror(errno));
    }

    Netlink data_netlink;
    Netlink netlink;
    Gate _stop_gate;

    FileWatcher::notify_fn_t fn = [&_stop_gate](const std::string& dir, const std::string& name, uint32_t mask) {
        if (name == "auditd" && (mask & (IN_CREATE|IN_MOVED_TO)) != 0) {
            Logger::Info("/sbin/auditd found on the system, exiting.");
            _stop_gate.Open();
        }
    };

    FileWatcher watcher(std::move(fn), {
            {"/sbin", IN_CREATE|IN_MOVED_TO},
    });

    std::function handler = [&](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        // Ignore AUDIT_REPLACE for now since replying to it doesn't actually do anything.
        if (type >= AUDIT_FIRST_USER_MSG && type != static_cast<uint16_t>(RecordType::REPLACE)) {
            size_t loss_bytes = 0;
            auto ptr = raw_queue.Allocate(len+sizeof(RecordType), &loss_bytes);
            if (ptr == nullptr) {
                _stop_gate.Open();
                return false;
            }
            if (loss_bytes > 0) {
                lost_bytes_metric->Update(loss_bytes);
                lost_segments_metric->Update(1);
                loss_bytes = 0;
            }
            *reinterpret_cast<RecordType*>(ptr) = static_cast<RecordType>(type);
            std::memcpy(ptr+sizeof(RecordType), data, len);
            raw_queue.Commit(len+sizeof(RecordType));
            bytes_metric->Update(len);
            records_metric->Update(1.0);
        }
        return false;
    };

    Logger::Info("Connecting to AUDIT NETLINK socket");
    ret = data_netlink.Open(std::move(handler));
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return false;
    }
    Defer _close_data_netlink([&data_netlink]() { data_netlink.Close(); });

    ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return false;
    }
    Defer _close_netlink([&netlink]() { netlink.Close(); });

    watcher.Start();
    Defer _stop_watcher([&watcher]() { watcher.Stop(); });

    uint32_t our_pid = getpid();

    Logger::Info("Checking assigned audit pid");
    audit_status status;
    ret = NetlinkRetry([&netlink,&status]() { return netlink.AuditGet(status); } );
    if (ret != 0) {
        Logger::Error("Failed to get audit status: %s", std::strerror(-ret));
        return false;
    }
    uint32_t pid = status.pid;
    uint32_t enabled = status.enabled;

    if (pid != 0 && PathExists("/proc/" + std::to_string(pid))) {
        Logger::Error("There is another process (pid = %d) already assigned as the audit collector", pid);
        return false;
    }

    Logger::Info("Enabling AUDIT event collection");
    int retry_count = 0;
    do {
        if (retry_count > 5) {
            Logger::Error("Failed to set audit pid: Max retried exceeded");
        }
        ret = data_netlink.AuditSetPid(our_pid);
        if (ret == -ETIMEDOUT) {
            // If setpid timedout, it may have still succeeded, so re-fetch pid
            ret = NetlinkRetry([&]() { return netlink.AuditGetPid(pid); });
            if (ret != 0) {
                Logger::Error("Failed to get audit pid: %s", std::strerror(-ret));
                return false;
            }
        } else if (ret != 0) {
            Logger::Error("Failed to set audit pid: %s", std::strerror(-ret));
            return false;
        } else {
            break;
        }
        retry_count += 1;
    } while (pid != our_pid);
    if (enabled == 0) {
        ret = NetlinkRetry([&netlink,&status]() { return netlink.AuditSetEnabled(1); });
        if (ret != 0) {
            Logger::Error("Failed to enable auditing: %s", std::strerror(-ret));
            return false;
        }
    }

    Defer _revert_enabled([&netlink,enabled]() {
        if (enabled == 0) {
            int ret;
            ret = NetlinkRetry([&netlink]() { return netlink.AuditSetEnabled(1); });
            if (ret != 0) {
                Logger::Error("Failed to enable auditing: %s", std::strerror(-ret));
            }
        }
    });

    Signals::SetExitHandler([&_stop_gate]() { _stop_gate.Open(); });

    auto _last_pid_check = std::chrono::steady_clock::now();
    while(!Signals::IsExit()) {
        if (_stop_gate.Wait(Gate::OPEN, 1000)) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        if (_last_pid_check < now - std::chrono::seconds(10)) {
            _last_pid_check = now;
            pid = 0;
            int ret;
            ret = NetlinkRetry([&netlink,&pid]() { return netlink.AuditGetPid(pid); });
            if (ret != 0) {
                if (ret == -ECANCELED || ret == -ENOTCONN) {
                    if (!Signals::IsExit()) {
                        Logger::Error("AUDIT NETLINK connection has closed unexpectedly");
                    }
                } else {
                    Logger::Error("Failed to get audit pid: %s", std::strerror(-ret));
                }
                return false;
            } else {
                if (pid != our_pid) {
                    if (pid != 0) {
                        Logger::Warn("Another process (pid = %d) has taken over AUDIT NETLINK event collection.", pid);
                        return false;
                    } else {
                        Logger::Warn("Audit pid was unexpectedly set to 0, restarting...");
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

int main(int argc, char**argv) {
    std::string config_file = AUOMSCOLLECT_CONF;
    int stop_delay = 0; // seconds
    bool netlink_mode = false;
    bool debug_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "c:dns:")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 's':
                stop_delay = atoi(optarg);
                break;
            case 'n':
                netlink_mode = true;
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

    Config config;

    if (!config_file.empty()) {
        try {
            Logger::Info("Opening config file %s", config_file.c_str());
            config.Load(config_file);
        } catch (std::runtime_error& ex) {
            Logger::Error("%s", ex.what());
            exit(1);
        }
    }

    std::string data_dir = AUOMS_DATA_DIR;
    std::string run_dir = AUOMS_RUN_DIR;

    if (config.HasKey("data_dir")) {
        data_dir = config.GetString("data_dir");
    }

    if (config.HasKey("run_dir")) {
        run_dir = config.GetString("run_dir");
    }

    std::string socket_path = run_dir + "/input.socket";

    std::string queue_dir = data_dir + "/collect_queue";

    if (config.HasKey("socket_path")) {
        socket_path = config.GetString("socket_path");
    }

    if (config.HasKey("queue_dir")) {
        queue_dir = config.GetString("queue_dir");
    }

    if (queue_dir.empty()) {
        Logger::Error("Invalid 'queue_file' value");
        exit(1);
    }

    size_t raw_queue_segment_size = 1024*1024;
    size_t num_raw_queue_segments = 10;

    int num_priorities = 8;
    size_t max_file_data_size = 1024*1024;
    size_t max_unsaved_files = 64;
    size_t max_fs_bytes = 128*1024*1024;
    double max_fs_pct = 10;
    double min_fs_free_pct = 5;
    long save_delay = 250;

    if (config.HasKey("raw_queue_segment_size")) {
        raw_queue_segment_size = config.GetUint64("raw_queue_segment_size");
    }

    if (config.HasKey("num_raw_queue_segments")) {
        num_raw_queue_segments = config.GetUint64("num_raw_queue_segments");
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

    std::string lock_file = data_dir + "/auomscollect.lock";

    if (config.HasKey("lock_file")) {
        lock_file = config.GetString("lock_file");
    }

    uint64_t rss_limit = 256L*1024L*1024L;
    uint64_t virt_limit = 1024L*1024L*1024L;
    double rss_pct_limit = 2;

    if (config.HasKey("rss_limit")) {
        rss_limit = config.GetUint64("rss_limit");
    }

    if (config.HasKey("rss_pct_limit")) {
        rss_pct_limit = config.GetDouble("rss_pct_limit");
    }

    if (config.HasKey("virt_limit")) {
        virt_limit = config.GetUint64("virt_limit");
    }

    int cpu_nice = -20;
    if (config.HasKey("cpu_nice")) {
        cpu_nice = config.GetInt64("cpu_nice");
    }

    bool use_syslog = true;
    if (config.HasKey("use_syslog")) {
        use_syslog = config.GetBool("use_syslog");
    }

    if (use_syslog) {
        Logger::OpenSyslog("auomscollect", LOG_DAEMON);
    }

    bool disable_cgroups = false;
    if (config.HasKey("disable_cgroups")) {
        disable_cgroups = config.GetBool("disable_cgroups");
    }

    // Set cgroup defaults
    if (!config.HasKey(CPU_SOFT_LIMIT_NAME)) {
        config.SetString(CPU_SOFT_LIMIT_NAME, "3");
    }

    if (!config.HasKey(CPU_HARD_LIMIT_NAME)) {
        config.SetString(CPU_HARD_LIMIT_NAME, "20");
    }

    // Set EventPrioritizer defaults
    if (!config.HasKey("event_priority_by_syscall")) {
        config.SetString("event_priority_by_syscall", R"json({"execve":2,"execveat":2,"*":3})json");
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

    std::atomic_long ingest_thread_id(0);
    std::shared_ptr<CGroupCPU> cgcpu_root;
    std::shared_ptr<CGroupCPU> cgcpu;
    if (!disable_cgroups) {
        try {
            cgcpu_root = CGroups::OpenCPU("");
            cgcpu = CPULimits::CGFromConfig(config, "auomscollect");
            // systemd may not have put auomscollect into the default cgroup at this point
            // Wait a few seconds before moving into the right cgroup so we avoid getting moved back out by systemd
            std::thread cg_thread([&cgcpu_root,&cgcpu,&ingest_thread_id]() {
                Signals::InitThread();
                int sleep_time = 10;
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
                    long tid = ingest_thread_id.load();
                    if (tid != 0) {
                        try {
                            cgcpu_root->AddThread(tid);
                        } catch (std::runtime_error &ex) {
                            Logger::Error("Failed to move ingest thread to root cgroup: %s", ex.what());
                            // Set the id back to 0 so we don't keep trying.
                            ingest_thread_id.store(0);
                        }
                    }
                }
            });
            cg_thread.detach();
        } catch (std::runtime_error &ex) {
            Logger::Error("Failed to configure cpu cgroup: %s", ex.what());
            Logger::Warn("CPU Limits cannot be enforced");
        }
    }

    if (!SetProcNice(cpu_nice)) {
        Logger::Warn("Failed to set CPU nice value to %d: %s", cpu_nice, std::strerror(errno));
    }

    // This will block signals like SIGINT and SIGTERM
    // They will be handled once Signals::Start() is called.
    Signals::Init();

    SPSCDataQueue raw_queue(raw_queue_segment_size, num_raw_queue_segments);

    Logger::Info("Opening queue: %s", queue_dir.c_str());
    auto queue = PriorityQueue::Open(queue_dir, num_priorities, max_file_data_size, max_unsaved_files, max_fs_bytes, max_fs_pct, min_fs_free_pct);
    if (!queue) {
        Logger::Error("Failed to open queue '%s'", queue_dir.c_str());
        exit(1);
    }

    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue, event_prioritizer);

    auto metrics = std::make_shared<Metrics>("auomscollect", queue);
    metrics->Start();

    auto proc_metrics = std::make_shared<ProcMetrics>("auomscollect", queue, metrics, rss_limit, virt_limit, rss_pct_limit, []() {
        Logger::Error("A memory limit was exceeded, exiting immediately");
        exit(1);
    });
    proc_metrics->Start();

    RawEventAccumulator accumulator (builder, metrics);

    auto output_config = std::make_unique<Config>(std::unordered_map<std::string, std::string>({
        {"output_format","raw"},
        {"output_socket", socket_path},
        {"enable_ack_mode", "true"},
        {"ack_queue_size", "100"}
    }));
    auto writer_factory = std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new RawOnlyEventWriterFactory()));
    Output output("output", "", queue, writer_factory, nullptr);
    output.Load(output_config);

    std::thread autosave_thread([&]() {
        Signals::InitThread();
        try {
            queue->Saver(save_delay);
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in autosave thread: %s", ex.what());
            exit(1);
        }
    });

    auto ingest_bytes_metric = metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "ingest", "bytes", MetricPeriod::SECOND, MetricPeriod::HOUR);
    auto ingest_records_metric = metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "ingest", "records", MetricPeriod::SECOND, MetricPeriod::HOUR);
    auto lost_bytes_metric = metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "ingest", "lost_bytes", MetricPeriod::SECOND, MetricPeriod::HOUR);
    auto lost_segments_metric = metrics->AddMetric(MetricType::METRIC_BY_ACCUMULATION, "ingest", "lost_segments", MetricPeriod::SECOND, MetricPeriod::HOUR);

    std::thread proc_thread([&]() {
        std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();
        uint8_t* ptr;
        ssize_t size;

        while((size = raw_queue.Get(&ptr)) > 0) {
            auto data_ptr = reinterpret_cast<char*>(ptr)+sizeof(RecordType);
            auto data_size = size-sizeof(RecordType);
            if (data_size <= RawEventRecord::MAX_RECORD_SIZE) {
                memcpy(record->Data(), data_ptr, data_size);
                if (record->Parse(*reinterpret_cast<RecordType*>(ptr), data_size)) {
                    accumulator.AddRecord(std::move(record));
                    record = std::make_unique<RawEventRecord>();
                } else {
                    Logger::Warn("Received unparsable event data: '%s'", std::string(record->Data(), size).c_str());
                }
            } else {
                Logger::Warn("Received event data size (%ld) exceeded size limit (%ld)", data_size, RawEventRecord::MAX_RECORD_SIZE);
            }
            raw_queue.Release();
        }
    });

    // Start signal handling thread
    Signals::Start();
    output.Start();

    // The ingest tasks needs to run outside cgroup limits
    std::thread ingest_thread([&]() {
        Signals::InitThread();
        auto thread_id = CGroups::GetSelfThreadId();
        Logger::Info("Starting ingest thead (%ld)", thread_id);
        ingest_thread_id.store(thread_id);
        if (netlink_mode) {
            bool restart;
            do {
                restart = DoNetlinkCollection(raw_queue, ingest_bytes_metric, ingest_records_metric, lost_bytes_metric,
                                              lost_segments_metric);
            } while (restart);
        } else {
            DoStdinCollection(raw_queue, ingest_bytes_metric, ingest_records_metric, lost_bytes_metric,
                              lost_segments_metric);
        }
    });
    ingest_thread.join();

    Logger::Info("Exiting");

    try {
        raw_queue.Close();
        proc_thread.join();
        proc_metrics->Stop();
        metrics->Stop();
        accumulator.Flush(0);
        if (stop_delay > 0) {
            Logger::Info("Waiting %d seconds for output to flush", stop_delay);
            sleep(stop_delay);
        }
        output.Stop();
        metrics->FlushLogMetrics();
        queue->Close(); // Close queue, this will trigger exit of autosave thread
        autosave_thread.join(); // Wait for autosave thread to exit
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during exit: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception during exit");
        exit(1);
    }

    singleton_lock.Unlock();

    exit(0);
}
