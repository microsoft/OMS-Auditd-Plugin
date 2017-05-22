/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_OUTPUT_H
#define AUOMS_OUTPUT_H

#include "RunBase.h"
#include "Queue.h"
#include "Config.h"
#include "OMSEventWriter.h"
#include "WriterBase.h"

#include <string>
#include <mutex>
#include <memory>
#include <vector>

class Output: public RunBase {
public:
    static constexpr int START_SLEEP_PERIOD = 1;
    static constexpr int MAX_SLEEP_PERIOD = 60;

    Output(const std::string& name, const std::string& conf_path, const std::string& cursor_path, const std::vector<std::string>& allowed_socket_dirs, std::shared_ptr<Queue>& queue):
            _name(name), _conf_path(conf_path), _cursor_path(cursor_path), _allowed_socket_dirs(allowed_socket_dirs), _queue(queue), _config_valid(false), _reload_pending(false)
    {}

    // Return false if the output isn't valid
    bool IsValid();

    // Trigger config reload
    void Reload();

    // Delete any resources associated with the output
    void Delete();

protected:
    virtual void on_stop();
    virtual void run();

    // Return true on success, false on failure
    bool read_cursor_file();
    bool write_cursor_file();
    bool delete_cursor_file();

    // Return true on success, false if Output should stop.
    bool configure();

    // Return true on success, false if Output should stop.
    bool check_open();

    // Return true if writer closed and Output should reconnect, false if Output should stop.
    bool handle_events();

    bool is_reload_pending();
    void clear_reload_pending();

    std::mutex _mutex;
    std::string _name;
    std::string _conf_path;
    std::string _cursor_path;
    std::vector<std::string> _allowed_socket_dirs;
    std::string _socket_path;
    std::shared_ptr<Queue> _queue;
    bool _config_valid;
    bool _reload_pending;
    std::unique_ptr<Config> _config;
    QueueCursor _cursor;
    std::unique_ptr<IEventWriter> _event_writer;
    std::unique_ptr<WriterBase> _writer;
};


#endif //AUOMS_OUTPUT_H
