/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_UNIXDOMAINLISTENER_H
#define AUOMS_UNIXDOMAINLISTENER_H

#include "IO.h"

#include <string>
#include <functional>
#include <atomic>

class UnixDomainListener {
public:
    explicit UnixDomainListener(const std::string& path): _socket_path(path), _socket_file_mode(0600), _listen_fd(-1) {}
    UnixDomainListener(const std::string& path, int mode): _socket_path(path), _socket_file_mode(mode), _listen_fd(-1) {}

    bool Open();
    int Accept();
    void Close();

private:
    std::string _socket_path;
    int _socket_file_mode;
    std::atomic<int> _listen_fd;
};


#endif //AUOMS_UNIXDOMAINLISTENER_H
