/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_OUTPUTS_H
#define AUOMS_OUTPUTS_H

#include "RunBase.h"
#include "Output.h"
#include "Queue.h"

#include <string>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <vector>

class Outputs: public RunBase {
public:
    Outputs(std::shared_ptr<Queue>& queue, const std::string& conf_dir, const std::string& cursor_dir, const std::vector<std::string>& allowed_socket_dirs, std::shared_ptr<UserDB>& user_db, std::shared_ptr<FiltersEngine> filtersEngine, std::shared_ptr<ProcessTree> processTree):
            _queue(queue), _conf_dir(conf_dir), _cursor_dir(cursor_dir), _allowed_socket_dirs(allowed_socket_dirs),
            _user_db(user_db), _filtersEngine(filtersEngine), _processTree(processTree), _do_reload(false) {}

    void Reload(const std::vector<std::string>& allowed_socket_dirs);

protected:
    virtual void on_stop();
    virtual void run();

private:
    void do_conf_sync();

    std::unique_ptr<Config> read_and_validate_config(const std::string& name, const std::string& path);

    std::shared_ptr<Queue> _queue;
    std::string _conf_dir;
    std::string _cursor_dir;
    std::vector<std::string> _allowed_socket_dirs;
    std::shared_ptr<UserDB> _user_db;
    std::shared_ptr<FiltersEngine> _filtersEngine;
    std::shared_ptr<ProcessTree> _processTree;
    bool _do_reload;
    std::mutex _mutex;
    std::condition_variable _cond;
    std::unordered_map<std::string, std::shared_ptr<Output>> _outputs;
};


#endif //AUOMS_OUTPUTS_H
