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
#include "Queue.h"
#include "Config.h"
#include "Logger.h"
#include "EventQueue.h"
#include "Output.h"
#include "RawEventRecord.h"
#include "RawEventAccumulator.h"
#include "Netlink.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <thread>
#include <system_error>

extern "C" {
#include <unistd.h>
#include <syslog.h>
}

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


void DoStdinCollection(RawEventAccumulator& accumulator) {
    StdinReader reader;

    try {
        int timeout = -1;
        std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();

        for (;;) {
            if (!Signals::IsExit()) {
                // Only use infinite timeout if Signals::IsExit() is false
                timeout = -1;
            } else {
                // We want to keep this number small to reduce shutdown delay.
                // However, audispd waits 50 msec after sending SIGTERM before closing pipe
                // So this needs to be larger than 50.
                timeout = 100;
            }
            ssize_t nr = reader.ReadLine(record->Data(), RawEventRecord::MAX_RECORD_SIZE, timeout, [] {
                return Signals::IsExit();
            });
            if (nr > 0) {
                if (record->Parse(RecordType::UNKNOWN, nr)) {
                    accumulator.AddRecord(std::move(record));
                    record = std::make_unique<RawEventRecord>();
                } else {
                    Logger::Warn("Received unparsable event data");
                }
            } else if (nr == StdinReader::TIMEOUT && Signals::IsExit()) {
                break;
            } else { // nr == StdinReader::CLOSED, StdinReader::FAILED or StdinReader::INTERRUPTED
                break;
            }
        }
    } catch (const std::exception &ex) {
        Logger::Error("Unexpected exception in input loop: %s", ex.what());
    } catch (...) {
        Logger::Error("Unexpected exception in input loop");
    }
}

void DoNetlinkCollection(RawEventAccumulator& accumulator) {
    Netlink netlink;
    std::function handler = [&accumulator](uint16_t type, uint16_t flags, void* data, size_t len) -> bool {
        if (type >= AUDIT_FIRST_USER_MSG) {
            std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();
            std::memcpy(record->Data(), data, len);
            if (record->Parse(static_cast<RecordType>(type), len)) {
                accumulator.AddRecord(std::move(record));
            } else {
                Logger::Warn("Received unparsable event data");
            }
        }
        return false;
    };

    Logger::Info("Connecting to AUDIT NETLINK socket");
    if (!netlink.Open(handler)) {
        Logger::Error("Failed to open AUDIT NETLINK connection");
        return;
    }

    uint32_t our_pid = getpid();

    Logger::Info("Checking assigned audit pid");
    uint32_t pid = 0;
    auto ret = netlink.AuditGetPid(pid);
    if (ret != Netlink::SUCCESS) {
        Logger::Error("Failed to get audit pid");
        return;
    }

    if (pid != 0) {
        Logger::Error("There is another process (pid = %d) already assigned as the audit collector", pid);
        return;
    }

    Logger::Info("Connecting to AUDIT NETLINK socket");
    ret = netlink.AuditSetPid(our_pid);
    if (ret != Netlink::SUCCESS) {
        Logger::Error("Failed to set audit pid");
        netlink.Close();
        return;
    }

    while(!Signals::IsExit()) {
        sleep(1);

        pid = 0;
        auto ret = netlink.AuditGetPid(pid);
        if (ret != 1) {
            if (ret < 0) {
                Logger::Error("Failed to get audit pid");
                break;
            } else {
                continue;
            }
        } else {
            if (pid != our_pid) {
                Logger::Warn("Another process (pid = %d) has taken over AUDIT NETLINK event collection.", pid);
                break;
            }
        }
    }

    netlink.Close();
}

int main(int argc, char**argv) {
    std::string config_file = "/etc/opt/microsoft/auoms/auomscollect.conf";
    int stop_delay = 0; // seconds
    bool netlink_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "c:ns:")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
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

    Config config;

    if (!config_file.empty()) {
        try {
            config.Load(config_file);
        } catch (std::runtime_error& ex) {
            Logger::Error("%s", ex.what());
            exit(1);
        }
    }

    std::string data_dir = "/var/opt/microsoft/auoms/data";
    std::string run_dir = "/var/run/auoms";

    if (config.HasKey("data_dir")) {
        data_dir = config.GetString("data_dir");
    }

    if (config.HasKey("run_dir")) {
        run_dir = config.GetString("run_dir");
    }

    std::string output_socket_path = run_dir + "/input.socket";

    std::string output_cursor_path = data_dir + "/input.cursor";
    std::string queue_file = data_dir + "/input_queue.dat";

    size_t queue_size = 10*1024*1024;

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

    if (queue_size < Queue::MIN_QUEUE_SIZE) {
        Logger::Warn("Value for 'queue_size' (%d) is smaller than minimum allowed. Using minimum (%d).", queue_size, Queue::MIN_QUEUE_SIZE);
        exit(1);
    }

    bool use_syslog = true;
    if (config.HasKey("use_syslog")) {
        use_syslog = config.GetBool("use_syslog");
    }

    if (use_syslog) {
        Logger::OpenSyslog("auomscollect", LOG_DAEMON);
    }

    // This will block signals like SIGINT and SIGTERM
    // They will be handled once Signals::Start() is called.
    Signals::Init();

    auto queue = std::make_shared<Queue>(queue_file, queue_size);
    try {
        Logger::Info("Opening queue: %s", queue_file.c_str());
        queue->Open();
    } catch (std::runtime_error& ex) {
        Logger::Error("Failed to open queue file '%s': %s", queue_file.c_str(), ex.what());
        exit(1);
    }

    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue);

    RawEventAccumulator accumulator (builder);

    auto output_config = std::make_unique<Config>(std::unordered_map<std::string, std::string>({
        {"output_format","raw"},
        {"output_socket", output_socket_path},
        {"enable_ack_mode", "true"},
        {"ack_queue_size", "10"}
    }));
    Output output("output", output_cursor_path, queue);
    output.Load(output_config);

    std::thread autosave_thread([&]() {
        try {
            queue->Autosave(128*1024, 250);
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in autosave thread: %s", ex.what());
            throw;
        }
    });

    // Start signal handling thread
    Signals::Start();

    output.Start();

    if (netlink_mode) {
        DoNetlinkCollection(accumulator);
    } else {
        DoStdinCollection(accumulator);
    }

    Logger::Info("Exiting");

    try {
        accumulator.Flush();
        if (stop_delay > 0) {
            Logger::Info("Waiting %d seconds for output to flush", stop_delay);
            sleep(stop_delay);
        }
        output.Stop();
        queue->Close(); // Close queue, this will trigger exit of autosave thread
        autosave_thread.join(); // Wait for autosave thread to exit
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during exit: %s", ex.what());
        throw;
    } catch (...) {
        Logger::Error("Unexpected exception during exit");
        throw;
    }

    exit(0);
}
