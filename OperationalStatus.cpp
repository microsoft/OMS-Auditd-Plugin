/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "OperationalStatus.h"
#include "Logger.h"
#include "RecordType.h"
#include "Translate.h"

#include "auoms_version.h"
#include "StringUtils.h"

#include <sstream>

#include <sys/time.h>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>


bool OperationalStatusListener::Initialize() {
    return _listener.Open();
}

void OperationalStatusListener::on_stopping() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _listener.Close();
}

void OperationalStatusListener::run() {
    Logger::Info("OperationalStatusListener starting");

    while(!IsStopping()) {
        int newfd = _listener.Accept();
        if (newfd > 0) {
            Logger::Info("OperationalStatusListener: new connection: fd == %d", newfd);
            if (!IsStopping()) {
                handle_connection(newfd);
            } else {
                close(newfd);
            }
        } else {
            return;
        }
    }
}

void OperationalStatusListener::handle_connection(int fd) {
    IOBase io(fd);

    auto rep = _status_fn();

    io.SetNonBlock(true);
    // Only give status requester 100 milliseconds to read the status.
    // We don't care if the write fails
    io.WriteAll(rep.data(), rep.size(), 100, [this]() { return !IsStopping(); });
    io.Close();
}


bool OperationalStatus::Initialize() {
    Logger::Info("OperationalStatus initializing");

    return _listener.Initialize();
}

std::vector<std::pair<ErrorCategory, std::string>> OperationalStatus::GetErrors() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    std::vector<std::pair<ErrorCategory, std::string>> errors;

    for (auto& e : _error_conditions) {
        errors.emplace_back(e);
    }

    std::sort(errors.begin(), errors.end(), [](std::pair<ErrorCategory, std::string>& a, std::pair<ErrorCategory, std::string>& b) -> bool { return a.first < b.first; });

    return errors;
}

void OperationalStatus::SetErrorCondition(ErrorCategory category, const std::string& error_msg) {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _error_conditions[category] = error_msg;
}

void OperationalStatus::ClearErrorCondition(ErrorCategory category) {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _error_conditions.erase(category);
}

void OperationalStatus::SetDesiredAuditRules(const std::vector<AuditRule>& rules) {
    std::unique_lock<std::mutex> lock(_run_mutex);

    std::vector<std::string> lines;
    for (auto& rule :rules ) {
        lines.emplace_back(rule.CanonicalText());
    }

    _desired_audit_rules = join(lines, "\n");
}

void OperationalStatus::SetLoadedAuditRules(const std::vector<AuditRule>& rules) {
    std::unique_lock<std::mutex> lock(_run_mutex);

    std::vector<std::string> lines;
    for (auto& rule :rules ) {
        lines.emplace_back(rule.CanonicalText());
    }

    _loaded_audit_rules = join(lines, "\n");
}

void OperationalStatus::SetRedactionRules(const std::vector<std::shared_ptr<const CmdlineRedactionRule>>& rules) {
    if (rules.empty()) {
        _redaction_rules = "";
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer;

    buffer.Clear();
    writer.Reset(buffer);

    writer.StartArray();

    for (auto& rule : rules) {
        writer.StartObject();
        writer.Key("file_name");
        writer.String(rule->FileName().data(), rule->FileName().size(), true);
        writer.Key("name");
        writer.String(rule->Name().data(), rule->Name().size(), true);
        writer.Key("regex");
        writer.String(rule->Regex().data(), rule->Regex().size(), true);
        std::string rchar;
        rchar.push_back(rule->ReplacementChar());
        writer.Key("replacement_char");
        writer.String(rchar.data(), rchar.size(), true);
        writer.EndObject();
    }

    writer.EndArray();

    _redaction_rules = std::string(buffer.GetString(), buffer.GetSize());
}

void OperationalStatus::on_stopping() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _listener.Stop();
}

void OperationalStatus::run() {
    Logger::Info("OperationalStatus starting");

    _listener.Start();

    // Send first status 15 seconds after startup
    if(!_sleep(15000)) {
        if (!send_status()) {
            return;
        }
    }

    // Generate a status message once an hour
    while(!_sleep(3600000)) {
        if (!send_status()) {
            return;
        }
    }
}

std::string OperationalStatus::get_status_str() {
    std::stringstream str;

    str << "Version: " << AUOMS_VERSION << std::endl;

    auto errors = GetErrors();
    if (errors.empty()) {
        str << "Status: Healthy" << std::endl;
    } else {
        str << "Status: " << errors.size() << " errors" << std::endl;
        str << "Errors:" << std::endl;
        for (auto& error: errors) {
            str << "    " << error.second << std::endl;
        }
    }

    return str.str();
}

std::string OperationalStatus::get_json_status() {
    auto errors = GetErrors();
    if (errors.empty()) {
        return std::string();
    }


    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer;

    buffer.Clear();
    writer.Reset(buffer);
    writer.StartObject();

    for (auto& error: errors) {
        std::string key;
        switch (error.first) {
            case ErrorCategory::DATA_COLLECTION:
                key = "DATA_COLLECTION";
                break;
            case ErrorCategory::DESIRED_RULES:
                key = "DESIRED_RULES";
                break;
            case ErrorCategory::AUDIT_RULES_KERNEL:
                key = "AUDIT_RULES_KERNEL";
                break;
            case ErrorCategory::AUDIT_RULES_FILE:
                key = "AUDIT_RULES_FILE";
                break;
            case ErrorCategory ::MISSING_REDACTION_RULES:
                key = "MISSING_REDACTION_RULES";
                break;
            default:
                key = "UNKNOWN[" + std::to_string(static_cast<int>(error.first)) + "]";
                break;
        }
        writer.Key(key.data(), key.length(), true);
        writer.String(error.second.data(), error.second.size(), true);
    }


    writer.EndObject();

    return std::string(buffer.GetString(), buffer.GetSize());
}

bool OperationalStatus::send_status() {
    static std::string_view SV_EMPTY;

    struct timeval tv;
    gettimeofday(&tv, nullptr);

    uint64_t sec = static_cast<uint64_t>(tv.tv_sec);
    uint32_t msec = static_cast<uint32_t>(tv.tv_usec)/1000;

    int num_fields = 4;
    auto errors = get_json_status();
    if (!errors.empty()) {
        num_fields += 1;
    }

    if (!_builder.BeginEvent(sec, msec, 0, 1)) {
        return false;
    }

    if (!_builder.BeginRecord(static_cast<uint32_t>(RecordType::AUOMS_STATUS), RecordTypeToName(RecordType::AUOMS_STATUS), "", num_fields)) {
        return false;
    }

    if (!_builder.AddField("version", AUOMS_VERSION, nullptr, field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!_builder.AddField("desired_audit_rules", _desired_audit_rules, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!_builder.AddField("loaded_audit_rules", _loaded_audit_rules, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!_builder.AddField("redaction_rules", _redaction_rules, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
        return false;
    }

    if (!errors.empty()) {
        if (!_builder.AddField("errors", errors, SV_EMPTY, field_type_t::UNCLASSIFIED)) {
            return false;
        }
    }
    if(!_builder.EndRecord()) {
        return false;
    }
    return _builder.EndEvent() != 0;
}