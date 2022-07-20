/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "LockFile.h"

#include "Logger.h"
#include "StringUtils.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <array>

int LockFile::Lock() {
    // Open (and possibly create the file)
    auto fd = open(_path.c_str(), O_CLOEXEC|O_CREAT|O_RDWR, 0700);
    if (fd < 0) {
        return FAILED;
    }

    if (flock(fd, LOCK_EX) != 0) {
        auto saved_errno = errno;
        close(fd);
        errno = saved_errno;
        if (errno == EINTR) {
            return INTERRUPTED;
        }
        return FAILED;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        auto saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return FAILED;
    }

    int ret = SUCCESS;
    if (st.st_size != 0) {
        std::string flag;
        flag.resize(st.st_size, 0);
        int nr = read(fd, flag.data(), flag.size());
        if (nr != st.st_size) {
            auto saved_errno = errno;
            close(fd);
            if (nr < 0) {
                errno = saved_errno;
            } else {
                errno = EIO;
            }
            return FAILED;
        }
        flag = trim_whitespace(flag);
        if (starts_with(flag, "flag")) {
            ret = FLAGGED;
        } else {
            ret = PREVIOUSLY_ABANDONED;
        }
        auto ignored = ftruncate(fd, 0);
    }

    std::string pid = std::to_string(getpid());
    int nw = pwrite(fd, pid.data(), pid.size(), 0);
    if (nw != pid.size()) {
        auto saved_errno = errno;
        close(fd);
        if (nw < 0) {
            errno = saved_errno;
        } else {
            errno = EIO;
        }
        return FAILED;
    }

    _fd = fd;

    return ret;
}

void LockFile::Unlock() {
    auto ignored = ftruncate(_fd, 0);
    close(_fd);
}
