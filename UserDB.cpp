/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "UserDB.h"

#include "Logger.h"
#include "Signals.h"

#include <cstring>
#include <fstream>
#include <cstdio>
#include <sstream>
#include <array>
#include <pwd.h>

extern "C" {
#include <unistd.h>
#include <sys/inotify.h>
#include <poll.h>
}

std::string UserDB::GetUserName(int uid)
{
    std::lock_guard<std::mutex> lock(_lock);

    auto it = user_map.find(uid);
    if (it != user_map.end()) {
        Logger::Info("Matching username found: %s", it->second.c_str());
        return it->second;
    }

    auto it_u = _users.find(uid);
    if (it_u != _users.end()) {
        Logger::Info("Matching username found in /etc/passwd file: %s", it_u->second.c_str());
        return it_u->second;
    }

    return std::string();
}

std::string UserDB::GetGroupName(int gid)
{
    std::lock_guard<std::mutex> lock(_lock);

    auto it = _groups.find(gid);
    if (it != _groups.end()) {
        return it->second;
    }

    return std::string();
}

void UserDB::Start()
{
    std::unique_lock<std::mutex> lock(_lock);
    if (_stop) {
        _stop = false;
        lock.unlock();
        update();
        lock.lock();
        _last_update = std::chrono::steady_clock::now();
        _need_update = false;
        std::thread inotify_thread([this](){ this->inotify_task(); });
        std::thread update_thread([this](){ this->update_task(); });
        _inotify_thread = std::move(inotify_thread);
        _update_thread = std::move(update_thread);

        int ret = sd_bus_open_system(&bus);
        if (ret < 0) {
            Logger::Error("Failed to connect to system bus: %s", strerror(-ret));
        }

        // Initialize the user list
        update_user_list();

        // Start the listener thread for user change signals
        listener_thread = std::thread(&UserDB::ListenForUserChanges, this);

        // Wait for a short period to allow the listener to initialize and capture signals
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void UserDB::Stop()
{
    std::unique_lock<std::mutex> lock(_lock);
    if (!_stop) {
        _stop = true;
        _cond.notify_all();

        close(_inotify_fd);
        _inotify_fd = -1;
        lock.unlock();
        _inotify_thread.join();
        _update_thread.join();

        if (listener_thread.joinable()) {
            listener_thread.join();
        }
        sd_bus_unref(bus);
        bus = nullptr;
    }
}

void UserDB::ListenForUserChanges() {
    // Add match rules for user added and removed signals
    Logger::Info("Listen for user changes: Entered");

    sd_bus_match_signal(bus, nullptr, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "UserNew", user_added_handler, this);
    sd_bus_match_signal(bus, nullptr, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "UserRemoved", user_removed_handler, this);

    Logger::Info("Listen for user changes: Registered signals");

    while (!_stop) {
        Logger::Info("Listen for user changes: In stop loop");
        int ret = sd_bus_process(bus, nullptr);
        Logger::Info("Listen for user changes: In bus process success");
        if (ret < 0) {
            Logger::Error("Failed to process bus: %s", strerror(-ret));
            break;
        }
        if (ret > 0) {
            continue; // Continue to process any further pending events
        }

        // Wait for the next event
        Logger::Info("Listen for user changes: In bus wait");
        ret = sd_bus_wait(bus, UINT64_MAX);
        Logger::Info("Listen for user changes: In bus wait success");
        if (ret < 0) {
            Logger::Error("Failed to wait on bus: %s", strerror(-ret));
            break;
        }
    }
    Logger::Info("Listen for user changes: Successfully out of while");
}

int UserDB::user_added_handler(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
    UserDB* db = static_cast<UserDB*>(userdata);
    uint32_t uid;
    const char* username;

    Logger::Info("Added user handler: before read");
    int ret = sd_bus_message_read(m, "us", &uid, &username);
    Logger::Info("Added user handler: before read success");
    if (ret < 0) {
        Logger::Error("Failed to parse UserNew signal: %s", strerror(-ret));
        return ret;
    }

    Logger::Info("User added: UID=%d, Username=%s", uid, username);
    db->user_map[uid] = username;
    return 0;
}

int UserDB::user_removed_handler(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
    UserDB* db = static_cast<UserDB*>(userdata);
    uint32_t uid;

    Logger::Info("Remove user handler: before read");
    int ret = sd_bus_message_read(m, "u", &uid);
    Logger::Info("Remove user handler: before read success");
    if (ret < 0) {
        Logger::Error("Failed to parse UserRemoved signal: %s", strerror(-ret));
        return ret;
    }

    Logger::Info("User removed: UID=%d", uid);
    db->user_map.erase(uid);
    return 0;
}

void UserDB::update_user_list() {
    std::vector<std::pair<int, std::string>> users;

    Logger::Info("In Update: Update_user_list call");
    int ret = get_user_list(users);

    Logger::Info("In Update: Update_user_list call success");

    if (ret < 0) {
        Logger::Error("In Update: Failed to get user list");
        return;
    }

    Logger::Info("In Update: Creating new user_map");
    user_map.clear();
    for (const auto& user : users) {
        user_map[user.first] = user.second;
    }
    Logger::Info("In Update: Creating new user_map success");
}

int UserDB::get_user_list(std::vector<std::pair<int, std::string>>& users) {
    sd_bus_message* msg = nullptr;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret;

    Logger::Info("In calling get_user_list");
    // Call ListUsers method on login1.Manager interface
    ret = sd_bus_call_method(bus,
                             "org.freedesktop.login1",          // service name
                             "/org/freedesktop/login1",         // object path
                             "org.freedesktop.login1.Manager",  // interface name
                             "ListUsers",                       // method name
                             &error,
                             &msg,
                             nullptr);                          // no input arguments

    Logger::Info("sd_bus call method complete");

    if (ret < 0) {
        Logger::Error("Failed to call ListUsers: %s", error.message);
        sd_bus_error_free(&error);
        Logger::Info("ret not expected. Returning");
        return ret;
    }

    Logger::Info("ret success");

    // Read the array of (uint32, string) structures
    ret = sd_bus_message_enter_container(msg, SD_BUS_TYPE_ARRAY, "(uso)");
    Logger::Info("Container call complete");
    if (ret < 0) {
        Logger::Error("Failed to enter array container: %s", strerror(-ret));
        sd_bus_message_unref(msg);
        return ret;
    }
    Logger::Info("Container call success");

    while ((ret = sd_bus_message_enter_container(msg, SD_BUS_TYPE_STRUCT, "uso")) > 0) {
        uint32_t user_id;
        const char* user_name;

        Logger::Info("Container while loop");
        ret = sd_bus_message_read(msg, "us", &user_id, &user_name);
        Logger::Info("Container while read");
        if (ret < 0) {
            Logger::Error("Failed to read user entry: %s", strerror(-ret));
            break;
        }

        Logger::Info("Container while read success");
        users.emplace_back(static_cast<int>(user_id), user_name);
        sd_bus_message_exit_container(msg);  // Exit the struct container
    }

    Logger::Info("Container while read out");
    sd_bus_message_exit_container(msg);  // Exit the array container

    Logger::Info("Container while read out success");

    // Clean up
    sd_bus_message_unref(msg);

    Logger::Info("Container clean up success");

    return ret < 0 ? ret : 0;
}

int _read(int fd, void *buf, size_t buf_size)
{
    struct pollfd fds;
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents = 0;

    for (;;) {
        auto ret = poll(&fds, 1, 250);
        if (ret < 0) {
            return ret;
        }

        if ((fds.revents & POLLIN) != 0) {
            return read(fd, buf, buf_size);
        }

        if (fds.revents & (POLLERR|POLLHUP|POLLNVAL)) {
            return 0;
        }
    }
}


void UserDB::inotify_task()
{
    Signals::InitThread();

    /* Create the file descriptor for accessing the inotify API */
    int fd = inotify_init();
    if (fd == -1) {
        Logger::Error("UserDB: Failed to init inotify socket: %s", std::strerror(errno));
        return;
    }

    int wd;
    wd = inotify_add_watch(fd, _dir.c_str(), IN_MODIFY|IN_MOVED_TO);
    if (wd == -1) {
        close(fd);
        Logger::Error("UserDB: Failed add watch for '%s': %s", _dir.c_str(), std::strerror(errno));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(_lock);
        _inotify_fd = fd;
    }

    char buf[4096]
            __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t nr;
    char *ptr;

    for (;;) {
        nr = _read(fd, buf, sizeof buf);
        if (nr == -1) {
            close(fd);
            Logger::Warn("UserDB: failed to read from inotify socket: %s", std::strerror(errno));
            return;
        } else if (nr == 0) {
            return;
        }

        /* Loop over all events in the buffer */
        for (ptr = buf; ptr < buf + nr; ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;

            if (event->mask & (IN_MODIFY|IN_MOVED_TO) && (strcmp(event->name, "passwd") == 0 || strcmp(event->name, "group") == 0)) {
                std::lock_guard<std::mutex> lock(_lock);
                _need_update = true;
                _need_update_ts = std::chrono::steady_clock::now();
                _cond.notify_all();
            }
        }
    }

}

constexpr int POST_MOD_DELAY = 100;
constexpr int REPEAT_UPDATE_DELAY = 500;

void UserDB::update_task()
{
    Signals::InitThread();

    std::unique_lock<std::mutex> lock(_lock);

    while (!_stop) {
        _cond.wait(lock, [this]() { return _stop || _need_update; });

        if (!_stop) {
            // Make sure it has been at lease 100 milliseconds since the last IN_MODIFY event
            // This will help avoid the race between the program making the modifications
            // and us reading the files.
            auto now = std::chrono::steady_clock::now();
            while ((now - _need_update_ts) < std::chrono::milliseconds(POST_MOD_DELAY)) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(POST_MOD_DELAY)-(now - _need_update_ts));
                lock.lock();
                now = std::chrono::steady_clock::now();
            }

            // Limit how often we do updates
            auto delta = std::chrono::steady_clock::now() - _last_update;
            if (delta < std::chrono::milliseconds(REPEAT_UPDATE_DELAY)) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(REPEAT_UPDATE_DELAY)-delta);
                lock.lock();
            }

            _last_update = std::chrono::steady_clock::now();
            _need_update = false;
            lock.unlock();
            update();
            lock.lock();
        }
    }
}

std::vector<std::pair<int, std::string>> parse_file(const std::string& path)
{
    std::vector<std::pair<int, std::string>> entries;
    std::ifstream fs(path);

    int line_num = 1;
    for (std::string line; std::getline(fs, line); line_num++) {
        size_t idx = line.find(':');
        if (idx == std::string::npos) {
            continue;
        }
        std::string name = line.substr(0, idx);
        line = line.substr(idx+1);
        idx = line.find(':');
        if (idx == std::string::npos) {
            continue;
        }
        line = line.substr(idx+1);
        idx = line.find(':');
        if (idx == std::string::npos) {
            continue;
        }
        std::string id_str = line.substr(0, idx);
        int id = 0;
        try {
            id = stoi(id_str);
        } catch (...) {
            continue;
        }
        entries.emplace_back(id, name);
    }
    return entries;
}

void UserDB::update()
{
    std::unordered_map<int, std::string> users;
    std::unordered_map<int, std::string> groups;

    try {
        for (auto& e : parse_file(_dir + "/passwd")) {
            // Just in case there are multiple entries, only the first id->name is used
            if (users.count(e.first) == 0) {
                users.emplace(e);
            }
        }
        for (auto& e : parse_file(_dir + "/group")) {
            // Just in case there are multiple entries, only the first id->name is used
            if (groups.count(e.first) == 0) {
                groups.emplace(e);
            }
        }
    } catch (const std::exception& ex) {
        Logger::Warn("UserDB: Update failed: %s", ex.what());
        return;
    }

    std::lock_guard<std::mutex> lock(_lock);
    _users = users;
    _groups = groups;
}

int UserDB::UserNameToUid(const std::string& name) {
    try {
        for (auto& e : parse_file("/etc/passwd")) {
            if (e.second == name) {
                return e.first;
            }
        }
    } catch (const std::exception& ex) {
        return -1;
    }
    return -1;
}

int UserDB::GroupNameToGid(const std::string& name) {
    try {
        for (auto& e : parse_file("/etc/group")) {
            if (e.second == name) {
                return e.first;
            }
        }
    } catch (const std::exception& ex) {
        return -1;
    }
    return -1;
}