/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_INPUT_H
#define AUOMS_INPUT_H

#include "RunBase.h"
#include "IO.h"
#include "InputBuffer.h"
#include "RawEventReader.h"

class Input: public RunBase {
public:
    Input(std::unique_ptr<IOBase> conn, std::shared_ptr<InputBuffer> buffer, std::function<void()>&& stop_fn)
    : _conn(std::move(conn)), _fd(_conn->GetFd()), _buffer(std::move(buffer)), _stop_fn(std::move(stop_fn)) {}

protected:
    void on_stopping() override;
    void on_stop() override;
    void run() override;

private:
    std::unique_ptr<IOBase> _conn;
    int _fd;
    RawEventReader _reader;
    std::shared_ptr<InputBuffer> _buffer;
    std::function<void()> _stop_fn;
};


#endif //AUOMS_INPUT_H
