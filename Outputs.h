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
#include "PriorityQueue.h"

#include <string>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <vector>

class OutputsEventWriterFactory: public IEventWriterFactory {
public:
    OutputsEventWriterFactory() {}

    virtual std::shared_ptr<IEventWriter> CreateEventWriter(const std::string& name, const Config& config) override;
};

class OutputsEventFilterFactory: public IEventFilterFactory {
public:
    OutputsEventFilterFactory(std::shared_ptr<UserDB> user_db, std::shared_ptr<FiltersEngine> filtersEngine, std::shared_ptr<ProcessTree> processTree):
            _user_db(user_db), _filtersEngine(filtersEngine), _processTree(processTree)
    {}

    virtual std::shared_ptr<IEventFilter> CreateEventFilter(const std::string& name, const Config& config) override;
private:
    std::shared_ptr<UserDB> _user_db;
    std::shared_ptr<FiltersEngine> _filtersEngine;
    std::shared_ptr<ProcessTree> _processTree;
};

class Outputs: public RunBase {
public:
    Outputs(std::shared_ptr<PriorityQueue>& queue, const std::string& conf_dir, const std::string& save_dir, std::shared_ptr<UserDB>& user_db, std::shared_ptr<FiltersEngine> filtersEngine, std::shared_ptr<ProcessTree> processTree):
            _queue(queue), _conf_dir(conf_dir), _save_dir(save_dir), _do_reload(false) {
        _writer_factory = std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new OutputsEventWriterFactory()));
        _filter_factory = std::shared_ptr<IEventFilterFactory>(static_cast<IEventFilterFactory*>(new OutputsEventFilterFactory(user_db, filtersEngine, processTree)));
    }

    Outputs(std::shared_ptr<PriorityQueue>& queue, const std::string& conf_dir, const std::string& save_dir, const std::shared_ptr<IEventFilterFactory>& filter_factory):
            _queue(queue), _conf_dir(conf_dir), _save_dir(save_dir),
            _writer_factory(std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new OutputsEventWriterFactory()))),
            _filter_factory(filter_factory),
            _do_reload(false) {
    }

    void Reload();

protected:
    virtual void on_stop();
    virtual void run();

private:
    void do_conf_sync();

    std::unique_ptr<Config> read_and_validate_config(const std::string& name, const std::string& path);

    std::shared_ptr<PriorityQueue> _queue;
    std::string _conf_dir;
    std::string _save_dir;
    std::shared_ptr<IEventWriterFactory> _writer_factory;
    std::shared_ptr<IEventFilterFactory> _filter_factory;
    bool _do_reload;
    std::mutex _mutex;
    std::condition_variable _cond;
    std::unordered_map<std::string, std::shared_ptr<Output>> _outputs;
};


#endif //AUOMS_OUTPUTS_H
