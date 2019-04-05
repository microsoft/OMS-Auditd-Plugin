//
// Created by tad on 3/19/19.
//

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

        std::string config_path = "/boot/config-" + _kver;
        try {
            auto lines = ReadFile(config_path);
            _syscall = std::any_of(lines.begin(), lines.end(), [](const std::string& str) ->bool { return str == "CONFIG_AUDITSYSCALL=y"; });
        } catch (std::exception& ex) {
            Logger::Error("Unable to read kernel config (%s): %s", config_path.c_str(), ex.what());
        }
    } catch (std::exception& ex) {
        Logger::Error("Unexpected exception while trying to obtain Kernel info: %s", ex.what());
    }
}
