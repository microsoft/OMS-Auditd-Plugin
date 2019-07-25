/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "TempDir.h"

#include <iostream>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <system_error>

extern "C" {
#include <unistd.h>
#include <stdlib.h>
};

TempDir::TempDir(const std::string& prefix)
{
    char tpath[1024];
    assert(prefix.size()+6 < sizeof(tpath));
    strcpy(tpath, prefix.c_str());
    strcat(tpath, "XXXXXX");
    char* ptr = mkdtemp(tpath);
    if (ptr == nullptr) {
        throw std::system_error(errno, std::system_category(), "Failed to create temporary directory");
    }
    _path = tpath;
}

TempDir::~TempDir()
{
    std::string cmd = "rm -rf " +_path;
    if (system(cmd.c_str()) != 0) {
        std::cerr << "Failed to remove temp dir (" << _path << "): " << std::strerror(errno) << std::endl;
    }
}
