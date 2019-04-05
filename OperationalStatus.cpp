//
// Created by tad on 3/18/19.
//

#include <sstream>
#include "OperationalStatus.h"

#include "Logger.h"

bool OperationalStatus::Initialize() {
    Logger::Info("OperationalStatus initializing");

    return _listener.Open();
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

void OperationalStatus::ClearErrorCondition(ErrorCategory category, const std::string& error_msg) {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _error_conditions.erase(category);
}

void OperationalStatus::on_stopping() {
    std::unique_lock<std::mutex> lock(_run_mutex);

    _listener.Close();
}

void OperationalStatus::run() {
    Logger::Info("OperationalStatus starting");

    while(!IsStopping()) {
        int newfd = _listener.Accept();
        if (newfd > 0) {
            Logger::Info("OperationalStatus: new connection: fd == %d", newfd);
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

void OperationalStatus::handle_connection(int fd) {
    IOBase io(fd);

    std::stringstream str;

    auto errors = GetErrors();
    if (errors.empty()) {
        str << "No errors" << std::endl;
    } else {
        for (auto& error: errors) {
            str << error.second << std::endl;
        }
    }

    auto rep = str.str();

    io.SetNonBlock(true);
    // Only give status requester 100 milliseconds to read the status.
    // We don't care if the write fails
    io.WriteAll(rep.data(), rep.size(), 100, [this]() { return !IsStopping(); });
    io.Close();
}
