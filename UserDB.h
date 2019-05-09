/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef AUOMS_USERDB_H
#define AUOMS_USERDB_H

#include <string>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <thread>

class UserDB {
public:
    UserDB(): _dir("/etc"), _stop(true), _inotify_fd(-1), _need_update(true) {}

    // This constructor exists solely to enable testing.
    UserDB(const std::string& dir): _dir(dir), _stop(true), _inotify_fd(-1), _need_update(true) {}

    std::string GetUserName(int uid);
    std::string GetGroupName(int gid);

    void Start();
    void Stop();

    void update(); // Exposed only to simplify tests

    static int UserNameToUid(const std::string& name);
    static int GroupNameToGid(const std::string& name);

private:
    void inotify_task();

    void update_task();

    std::mutex _lock;
    std::condition_variable _cond;

    std::string _dir;
    bool _stop;

    std::unordered_map<int, std::string> _users;
    std::unordered_map<int, std::string> _groups;

    std::chrono::time_point<std::chrono::steady_clock> _last_update;
    std::chrono::time_point<std::chrono::steady_clock> _need_update_ts;
    bool _need_update;

    int _inotify_fd;

    std::thread _inotify_thread;
    std::thread _update_thread;
};


#endif //AUOMS_USERDB_H
