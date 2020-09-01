/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "KernelInfo.h"
#include "Version.h"
#include "Logger.h"
#include "Translate.h"
#include "FileUtils.h"

#include <cstring>
#include <mutex>
#include <algorithm>

#include <sys/utsname.h>

#define MINIMUM_INTERFIELD_COMPARE_VERSION "3.10"
#define MINIMUM_EXE_FIELD_VERSION "4.4"
#define MINIMUM_SESSIONID_FIELD_VERSION "4.10"
#define MINIMUM_AUDIT_MULTICAST_VERSION "3.16"

static std::once_flag s_init_flag;

KernelInfo* KernelInfo::_info;

KernelInfo* KernelInfo::ptr() {
    std::call_once(s_init_flag, KernelInfo::init);
    return _info;
}

void KernelInfo::init() {
    _info = new KernelInfo();
    _info->load();
}

void KernelInfo::load() noexcept {
    try {
        struct utsname uts;
        if (uname(&uts) < 0) {
            Logger::Error("uname() failed: %s", std::strerror(errno));
            return;
        }

        _kver = uts.release;
        _is_64bit = Is64BitMachineType(ArchNameToMachine(uts.machine));

        Version kver(_kver);
        _compare = kver >= Version(MINIMUM_INTERFIELD_COMPARE_VERSION);
        _exe_field = kver >= Version(MINIMUM_EXE_FIELD_VERSION);
        _session_id_field = kver >= Version(MINIMUM_SESSIONID_FIELD_VERSION);
        _audit_multicast = kver >= Version(MINIMUM_AUDIT_MULTICAST_VERSION);

        std::string config_path = "/boot/config-" + _kver;
        try {
            auto lines = ReadFile(config_path);
            _syscall = std::any_of(lines.begin(), lines.end(), [](const std::string& str) ->bool { return str == "CONFIG_AUDITSYSCALL=y"; });
        } catch (std::exception& ex) {
            // If the /boot/config file is absent, or cannot be read, assume that CONFIG_AUDITSYSCALL=y.
            // This is fairly safe since all the major distro kernels have this set to true by default.
            _syscall = true;
        }
    } catch (std::exception& ex) {
        Logger::Error("Unexpected exception while trying to obtain Kernel info: %s", ex.what());
    }
}
