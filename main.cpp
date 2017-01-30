/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "OMSEventTransformerConfig.h"
#include "EventTransformerConfig.h"
#include "AuditEventProcessor.h"
#include "MsgPackMessageSink.h"
#include "OMSEventTransformer.h"
#include "EventTransformer.h"
#include "JSONMessageSink.h"
#include "StdoutWriter.h"
#include "StdinReader.h"
#include "UnixDomainWriter.h"
#include "Signals.h"
#include "Queue.h"
#include "Config.h"
#include "Logger.h"
#include "EventQueue.h"
#include "UserDB.h"

#include <iostream>
#include <fstream>
#include <memory>
#include <system_error>
#include <thread>

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

int main(int argc, char**argv) {
    // AuditEventProcessor needs audit_msg_type_to_name(). load_libaudit_symbols() loads that symbol.
    // See comments next to load_libaudit_symbols for the reason why it is done this way.
    // This function will call exit(1) if it fails to load the symbol.
    load_libaudit_symbols();

    std::string output_file = "";
    std::string output_format = "json";
    std::string mode = "event";
    std::string config_file = "/etc/opt/microsoft/auoms/auoms.conf";
    std::string in_queue_file = "/var/opt/microsoft/auoms/data/in_queue.dat";
    std::string out_queue_file = "/var/opt/microsoft/auoms/data/out_queue.dat";
    std::string message_label = "audit";
    size_t in_queue_size = 10*1024*1024;
    size_t out_queue_size = 128*1024;
    bool use_ext_time = false;

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

    if (config_file.size() > 0) {
        try {
            config.Load(config_file);
        } catch (std::runtime_error& ex) {
            Logger::Error("%s", ex.what());
            exit(1);
        }
    }

    if (config.HasKey("output_path")) {
        output_file = config.GetString("output_path");
    } else {
        Logger::Error("No output parameter found!");
        exit(1);
    }

    if (config.HasKey("mode")) {
        mode = config.GetString("mode");
    }

    if (mode != "record" && mode != "event" && mode != "oms") {
        Logger::Error("Invalid 'mode' value: %s", mode.c_str());
        exit(1);
    }

    if (config.HasKey("output_format")) {
        output_format = config.GetString("output_format");
    }

    if (output_format != "json" && output_format != "msgpack") {
        Logger::Error("Invalid 'output_format' value: %s", output_format.c_str());
        exit(1);
    }

    if (config.HasKey("in_queue_file")) {
        in_queue_file = config.GetString("in_queue_file");
    }

    if (config.HasKey("out_queue_file")) {
        out_queue_file = config.GetString("out_queue_file");
    }

    if (in_queue_file.size() == 0) {
        Logger::Error("Invalid 'in_queue_file' value");
        exit(1);
    }

    if (out_queue_file.size() == 0) {
        Logger::Error("Invalid 'out_queue_file' value");
        exit(1);
    }

    if (config.HasKey("in_queue_size")) {
        try {
            in_queue_size = config.GetUint64("in_queue_size");
        } catch(std::exception& ex) {
            Logger::Error("Invalid 'in_queue_size' value: %s", config.GetString("in_queue_size").c_str());
            exit(1);
        }
    }

    if (config.HasKey("out_queue_size")) {
        try {
            out_queue_size = config.GetUint64("out_queue_size");
        } catch(std::exception& ex) {
            Logger::Error("Invalid 'out_queue_size' value: %s", config.GetString("out_queue_size").c_str());
            exit(1);
        }
    }

    if (in_queue_size < Queue::MIN_QUEUE_SIZE) {
        Logger::Warn("Value for 'in_queue_size' (%d) is smaller than minimum allowed. Using mimumum (%d).", in_queue_size, Queue::MIN_QUEUE_SIZE);
        exit(1);
    }

    if (out_queue_size < Queue::MIN_QUEUE_SIZE) {
        Logger::Warn("Value for 'out_queue_size' (%d) is smaller than minimum allowed. Using mimumum (%d).", out_queue_size, Queue::MIN_QUEUE_SIZE);
        exit(1);
    }

    if (config.HasKey("msgpack_ext_time")) {
        use_ext_time = config.GetBool("msgpack_ext_time");
    }

    if (config.HasKey("message_label")) {
        message_label = config.GetString("message_label");
    }

    Logger::OpenSyslog("auoms", LOG_DAEMON);

    void * et_config_p;

    if (mode == "oms") {
        OMSEventTransformerConfig* et_config = new OMSEventTransformerConfig();
        if (!et_config->LoadFromConfig(config)) {
            Logger::Error("Invalid config. Exiting.");
            exit(1);
        }
        et_config_p = et_config;
    } else {
        EventTransformerConfig* et_config = new EventTransformerConfig(mode == "record");
        if (!et_config->LoadFromConfig(config)) {
            Logger::Error("Invalid config. Exiting.");
            exit(1);
        }
        et_config_p = et_config;
    }

    auto in_queue = std::make_shared<Queue>(in_queue_file, in_queue_size);
    try {
        Logger::Info("Opening input queue: %s", out_queue_file.c_str());
        in_queue->Open();
    } catch (std::runtime_error& ex) {
        Logger::Error("Failed to open input queue file '%s': %s", in_queue_file.c_str(), ex.what());
        exit(1);
    }

    auto out_queue = std::make_shared<Queue>(out_queue_file, out_queue_size);
    try {
        Logger::Info("Opening output queue: %s", out_queue_file.c_str());
        out_queue->Open();
    } catch (std::runtime_error& ex) {
        Logger::Error("Failed to open output queue file '%s': %s", out_queue_file.c_str(), ex.what());
        exit(1);
    }

    std::unique_ptr<OutputBase> output;

    if (output_file == "-") {
        output = std::move(std::unique_ptr<OutputBase>(static_cast<OutputBase*>(new StdoutWriter())));
    } else {
        output = std::move(std::unique_ptr<OutputBase>(static_cast<OutputBase*>(new UnixDomainWriter(output_file))));
    }

    MessageSinkBase::RegisterSinkFactory("json", JSONMessageSink::Create);
    MessageSinkBase::RegisterSinkFactory("msgpack", MsgPackMessageSink::Create);

    std::shared_ptr<MessageSinkBase> sink = MessageSinkBase::CreateSink(output_format, std::move(output), config);

    if (!sink) {
        throw std::runtime_error("Invalid output format");
    }

    auto user_db = std::make_shared<UserDB>();

    auto event_queue = std::make_shared<EventQueue>(in_queue);

    std::shared_ptr<EventBuilder> builder = std::make_shared<EventBuilder>(event_queue);
    EventTransformerBase* transformer;
    if (mode == "oms") {
        transformer = new OMSEventTransformer(*(static_cast<OMSEventTransformerConfig*>(et_config_p)), message_label, sink);
    } else {
        transformer = new EventTransformer(*(static_cast<EventTransformerConfig*>(et_config_p)), message_label, sink);
    }
    AuditEventProcessor aep(builder, user_db);
    aep.Initialize();
    StdinReader reader;

    Signals::Init();

    std::thread in_autosave_thread([&]() {
        try {
            in_queue->Autosave(128*1024, 250);
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in autosave thread: %s", ex.what());
            throw;
        }
    });

    std::thread out_autosave_thread([&]() {
        try {
            out_queue->Autosave(32*1024, 250);
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in autosave thread: %s", ex.what());
            throw;
        }
    });

    std::thread forward_thread([&]() {
        try {
            void* ptr;
            size_t size;
            queue_msg_type_t msg_type;
            while(true) {
                int64_t id = in_queue->Peek(&size, &msg_type, 250);
                if (id > 0) {
                    // Wait until these is enough space in the output queue
                    auto ret = out_queue->Allocate(&ptr, size, false, -1);
                    if (ret == Queue::CLOSED) {
                        Logger::Info("Output Queue closed");
                        return;
                    } else if (ret > 0) {
                        auto tret = in_queue->TryGet(id, ptr, size, true);
                        if (tret == 1) {
                            out_queue->Commit(msg_type);
                        } else {
                            out_queue->Rollback();
                        }
                    }
                } else if (id == Queue::CLOSED) {
                    Logger::Info("Input Queue closed");
                    return;
                }
            }
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in forward thread: %s", ex.what());
            throw;
        } catch (...) {
            Logger::Error("Unexpected exception in forward thread");
            throw;
        }
    });

    std::thread output_thread([&]() {
        try {
            char data[128*1024];
            size_t size;
            queue_msg_type_t msg_type;
            while(true) {
                size = sizeof(data);
                auto ret = out_queue->Get(data, &size, &msg_type, false, 250);
                if (ret > 0) {
                    switch (msg_type) {
                        case queue_msg_type_t::EVENT: {
                            Event event(data, size);
                            transformer->ProcessEvent(event);
                            break;
                        }
                        case queue_msg_type_t::EVENTS_GAP: {
                            transformer->ProcessEventsGap(*reinterpret_cast<EventGapReport *>(data));
                            break;
                        }
                        default: {
                            Logger::Warn("Unexpected message type found in queue");
                            break;
                        }
                    }
                    out_queue->Checkpoint(ret); // TODO: Need to refactor this logic.
                } else if (ret == Queue::CLOSED) {
                    Logger::Info("Output: Queue closed");
                    return;
                }
            }
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in output thread: %s", ex.what());
            throw;
        } catch (...) {
            Logger::Error("Unexpected exception in output thread");
            throw;
        }
    });

    user_db->Start();

    int exit_code = 0;
    try {
        char buffer[64*1024];
        while(true) {
            ssize_t nr = reader.Read(buffer, sizeof(buffer));
            if (nr > 0) {
                aep.ProcessData(buffer, nr);
            } else if (nr == 0) {
                aep.Flush();
            } else {
                break;
            }
            if (Signals::IsExit()) {
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
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    try {
        aep.Close();
        user_db->Stop();
        in_queue->Close();
        out_queue->Close();
        sink->Close();
        forward_thread.join();
        output_thread.join();
        in_autosave_thread.join();
        out_autosave_thread.join();
        in_queue->Save();
        out_queue->Save();
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during exit: %s", ex.what());
        throw;
    } catch (...) {
        Logger::Error("Unexpected exception during exit");
        throw;
    }
    exit(exit_code);
}
