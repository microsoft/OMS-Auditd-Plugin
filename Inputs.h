/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_INPUTS_H
#define AUOMS_INPUTS_H

#include "IO.h"
#include "UnixDomainListener.h"
#include "RunBase.h"
#include "InputBuffer.h"
#include "Input.h"
#include "OperationalStatus.h"

#include <string>
#include <unordered_map>

class Inputs: public RunBase {
public:
    explicit Inputs(const std::string& addr, const std::shared_ptr<OperationalStatus>& op_status): _listener(addr), _buffer(std::make_shared<InputBuffer>()), _op_status(op_status) {}

    bool Initialize();

    bool HandleData(const std::function<void(void*,size_t)>& fn) {
        return _buffer->HandleData(fn);
    }

protected:
    void on_stopping() override;
    void on_stop() override;
    void run() override;

private:
    UnixDomainListener _listener;
    std::unordered_map<int, std::shared_ptr<Input>> _inputs;
    std::shared_ptr<InputBuffer> _buffer;
    std::shared_ptr<OperationalStatus> _op_status;
    std::vector<std::shared_ptr<Input>> _inputs_to_clean;

    void add_connection(int fd);
    void remove_connection(int fd);
    void cleanup();
};

#endif //AUOMS_INPUTS_H
