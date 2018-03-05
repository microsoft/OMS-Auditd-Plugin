/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "AuditEventProcessor.h"
#include "StdoutWriter.h"
#include "StdinReader.h"
#include "UnixDomainWriter.h"
#include "Signals.h"
#include "Queue.h"
#include "Config.h"
#include "Logger.h"
#include "EventQueue.h"
#include "UserDB.h"
#include "Outputs.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <system_error>

extern "C" {
#include <unistd.h>
#include <syslog.h>
}

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
    // AuditEventProcessor needs audit_msg_type_to_name(). load_libaudit_symbols() loads that symbol.
    // See comments next to load_libaudit_symbols for the reason why it is done this way.
    // This function will call exit(1) if it fails to load the symbol.
    load_libaudit_symbols();

    std::string config_file = "/etc/opt/microsoft/auoms/auoms.conf";

    int opt;
    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
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
    std::string outconf_dir = "/etc/opt/microsoft/auoms/outconf.d";
    std::string data_dir = "/var/opt/microsoft/auoms/data";

    if (config.HasKey("outconf_dir")) {
        outconf_dir = config.GetString("outconf_dir");
    }

    if (config.HasKey("data_dir")) {
        data_dir = config.GetString("data_dir");
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

    std::string queue_file = data_dir + "/queue.dat";
    std::string cursor_dir = data_dir + "/outputs";
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
        Logger::OpenSyslog("auoms", LOG_DAEMON);
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

    Outputs outputs(queue, outconf_dir, cursor_dir, allowed_socket_dirs);

    auto user_db = std::make_shared<UserDB>();

    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue);

    try {
        user_db->Start();
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during startup: %s", ex.what());
        throw;
    } catch (...) {
        Logger::Error("Unexpected exception during startup");
        throw;
    }    

    auto proc_filter = std::make_shared<ProcFilter>(user_db);
    if (proc_filter->ParseConfig(config)) {
        proc_filter->Load();
    } else {
        Logger::Error("Invalid 'process_filters' value");
        exit(1);
    }

    AuditEventProcessor aep(builder, user_db, proc_filter);
    aep.Initialize();
    StdinReader reader;

    std::thread autosave_thread([&]() {
        try {
            queue->Autosave(128*1024, 250);
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in autosave thread: %s", ex.what());
            throw;
        }
    });
try {
        outputs.Start();
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during outputs startup: %s", ex.what());
        throw;
    } catch (...) {
        Logger::Error("Unexpected exception during outputs startup");
        throw;
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

    try {
        char buffer[64*1024];
        int timeout = -1;
        bool flushed = true;
        for (;;) {
            if (flushed && !Signals::IsExit()) {
                // Only use infinite timeout if AuditEventProcessor hasn't been flushed
                // and Signals::IsExit() is false
                timeout = -1;
            } else {
                // We want to keep this number small to reduce shutdown delay.
                // However, audispd waits 50 msec after sending SIGTERM before closing pipe
                // So this needs to be larger than 50.
                timeout = 100;
            }
            int nr = reader.Read(buffer, sizeof(buffer), timeout);
            if (nr > 0) {
                aep.ProcessData(buffer, nr);
                flushed = false;
            } else if (nr == StdinReader::TIMEOUT || nr == StdinReader::INTERRUPTED) {
                if (nr != StdinReader::INTERRUPTED) {
                    aep.Flush();
                    flushed = true;
                }
                if (nr == StdinReader::TIMEOUT && Signals::IsExit()) {
                    break;
                }
            } else { // nr == StdinReader::CLOSED
                break;
            }
        }
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception in input loop: %s", ex.what());
        throw;
    } catch (...) {
        Logger::Error("Unexpected exception in input loop");
        throw;
    }

    Logger::Info("Exiting");

    try {
        aep.Flush(); // Force processing of any remaining data
        outputs.Stop(false); // Trigger outputs shutdown but don't block
        user_db->Stop(); // Stop user db monitoring
        queue->Close(); // Close queue, this will trigger exit of autosave thread
        outputs.Wait(); // Wait for outputs to finish shutdown
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
