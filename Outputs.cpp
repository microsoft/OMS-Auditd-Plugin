/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Outputs.h"

#include "Logger.h"
#include "OMSEventWriter.h"
#include "FluentEventWriter.h"
#include "RawEventWriter.h"
#include "SyslogEventWriter.h"
#include "EventFilter.h"

#include <cstring>

extern "C" {
#include <dirent.h>
#include <unistd.h>
}

std::shared_ptr<IEventWriter> OutputsEventWriterFactory::CreateEventWriter(const std::string& name, const Config& config) {
    EventWriterConfig writer_config;
    writer_config.LoadFromConfig(name, config);

    std::string format = "oms";

    if (config.HasKey("output_format")) {
        format = config.GetString("output_format");
    }

    if (format == "oms") {
        return std::shared_ptr<IEventWriter>(static_cast<IEventWriter*>(new OMSEventWriter(writer_config)));
    } else if (format == "fluent") {
        std::string fluentTag = "LINUX_AUDITD_BLOB";
        if (config.HasKey("fluent_message_tag")) {
            fluentTag = config.GetString("fluent_message_tag");
        }
        return std::shared_ptr<IEventWriter>(static_cast<IEventWriter*>(new FluentEventWriter(writer_config, fluentTag)));
    } else if (format == "raw") {
        return std::shared_ptr<IEventWriter>(static_cast<IEventWriter*>(new RawEventWriter()));
    } else if (format == "syslog") {
        return std::shared_ptr<IEventWriter>(static_cast<IEventWriter*>(new SyslogEventWriter(writer_config)));
    } else {
        Logger::Error("Output(%s): Invalid output_format parameter value: '%s'", name.c_str(), format.c_str());
        return nullptr;
    }
}

std::shared_ptr<IEventFilter> OutputsEventFilterFactory::CreateEventFilter(const std::string& name, const Config& config) {
    return EventFilter::NewEventFilter(name, config, _user_db, _filtersEngine, _processTree);
}

void Outputs::Reload() {
    Logger::Info("Reload requested");
    std::unique_lock<std::mutex> lock(_run_mutex);
    _do_reload = true;
    _run_cond.notify_all();
}

void Outputs::on_stop() {
    for( auto ent: _outputs) {
        ent.second->Stop();
    }
    _outputs.clear();
}

void Outputs::run() {
    do_conf_sync();

    std::unique_lock<std::mutex> lock(_run_mutex);
    while (!_stop) {
        _run_cond.wait(lock, [this]() { return _stop || _do_reload; });
        if (_do_reload) {
            _do_reload = false;
            lock.unlock();
            do_conf_sync();
            lock.lock();
        }
    }
}

/*
 *  Get List of outputs
 *  Delete existing output not in new list
 *  If new output is in existing outputs
 *      If config is not valid or config is different
 *          stop output
 *      if config is valid
 *          start new output
 *  Else
 *      If config is valid
 *          Start new output
 */

std::unique_ptr<Config> Outputs::read_and_validate_config(const std::string& name, const std::string& path) {
    Logger::Info("Output(%s): Reading config from %s", name.c_str(), path.c_str());

    std::unique_ptr<Config> config(new Config());
    try {
        config->Load(path);
    } catch (std::runtime_error& ex) {
        Logger::Error("Output(%s): Failed to read configuration: %s", name.c_str(), ex.what());
        return nullptr;
    }

    std::string format = "oms";
    if (config->HasKey("output_format")) {
        format = config->GetString("output_format");
    }

    // Skip the socket check for the syslog event writer. This writes directly to Syslog so no output socket is required
    if (format.compare("syslog")) {
        if (!config->HasKey("output_socket")) {
            Logger::Error("Output(%s): Missing required parameter: output_socket", name.c_str());
            return nullptr;
        }

        auto socket_path = config->GetString("output_socket");
    }
    
    if (format != "oms" && format != "json" && format != "msgpack" && format != "raw" && format != "syslog" && format != "fluent") {
        Logger::Error("Output(%s): Invalid output_format parameter value: '%s'", name.c_str(), format.c_str());
        return nullptr;
    }

    bool ack_mode = false;
    if (config->HasKey("enable_ack_mode")) {
        try {
            ack_mode = config->GetBool("enable_ack_mode");
        } catch (std::exception) {
            Logger::Error("Output(%s): Invalid enable_ack_mode parameter value", name.c_str());
            return nullptr;
        }
    }

    if (ack_mode) {
        uint64_t ack_queue_size = Output::DEFAULT_ACK_QUEUE_SIZE;
        if (config->HasKey("ack_queue_size")) {
            try {
                ack_queue_size = config->GetUint64("ack_queue_size");
            } catch (std::exception) {
                Logger::Error("Output(%s): Invalid ack_queue_size parameter value", name.c_str());
                return nullptr;
            }
        }
        if (ack_queue_size < 1) {
            Logger::Error("Output(%s): Invalid ack_queue_size parameter value", name.c_str());
            return nullptr;
        }
    }

    return config;
}

void Outputs::do_conf_sync() {
    std::unique_lock<std::mutex> lock(_mutex);

    std::unordered_map<std::string, std::string> new_outputs;

    std::array<char, 4096> buffer;

    auto dir = opendir(_conf_dir.c_str());
    if (dir == nullptr) {
        Logger::Error("Outputs: Failed to open outconf dir (%s): %s", _conf_dir.c_str(), std::strerror(errno));
        return;
    }

    struct dirent* dent;
    while((dent = readdir(dir)) != nullptr) {

        std::string name(&dent->d_name[0]);
        if (name.length() > 5) {
            auto prefix_len = name.length() - 5;
            if (name.substr(prefix_len, 5) == ".conf") {
                new_outputs[name.substr(0, prefix_len)] = _conf_dir + "/" + name;
            }
        }
    }
    closedir(dir);

    std::unordered_map<std::string, std::shared_ptr<Output>> to_delete;
    for(auto ent: _outputs) {
        if (new_outputs.find(ent.first) == new_outputs.end()) {
            to_delete.insert(ent);
        }
    }

    for(auto ent: to_delete) {
        _outputs.erase(ent.first);
        ent.second->Stop();
        ent.second->Delete();
    }

    for(auto ent: new_outputs) {
        auto config = read_and_validate_config(ent.first, ent.second);

        if (!config) {
            Logger::Error("Output(%s): Config is invalid: It will be ignored", ent.first.c_str());
            continue;
        }

        auto it = _outputs.find(ent.first);

        bool load = false;
        if (it != _outputs.end()) {
            if (it->second->IsConfigDifferent(*config)) {
                Logger::Info("Output(%s): Config has changed", ent.first.c_str());
                it->second->Stop();
                load = true;
            }
        } else {
            auto o = std::make_shared<Output>(ent.first, _save_dir, _queue, _writer_factory, _filter_factory);
            it = _outputs.insert(std::make_pair(ent.first, o)).first;
            load = true;
        }

        if (load) {
            if (!it->second->Load(config)) {
                Logger::Error("Output(%s): Failed to load config: Not started", ent.first.c_str());
            } else {
                it->second->Start();
            }
        }
    }
}
