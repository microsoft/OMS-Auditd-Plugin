/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Translate.h"
#include "StringTable.h"

#include <linux/audit.h>
#include <sys/utsname.h>
#include <mutex>

// These EM_ defines are found in newer versions of /usr/include/linux/elf-em.h
#ifndef EM_ARM
#define EM_ARM 40
#endif

#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

// These AUDIT_ARCH_ defines are found in newer versions of /usr/include/linux/audit.h
#ifndef AUDIT_ARCH_ARM
#define AUDIT_ARCH_ARM (EM_ARM|__AUDIT_ARCH_LE)
#endif

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 (EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif

std::string s_uname_machine;
MachineType s_machine_type;
std::once_flag s_machine_type_flag;

MachineType DetectMachine() {
    std::call_once(s_machine_type_flag, [](){
        struct utsname uts;
        if (uname(&uts) == 0) {
            s_uname_machine = uts.machine;
            s_machine_type = ArchNameToMachine(uts.machine);
        } else {
            s_machine_type = MachineType::UNKNOWN;
        }
    });
    return s_machine_type;
}

static std::unordered_map<std::string, MachineType> s_name2mach({
     {"i386", MachineType::X86},
     {"i486", MachineType::X86},
     {"i586", MachineType::X86},
     {"i686", MachineType::X86},
     {"x86_64", MachineType::X86_64},
     {"arm", MachineType::ARM},
     {"aarch64", MachineType::ARM64},
});

MachineType ArchNameToMachine(const std::string_view& arch) {
    if (arch == "b64") {
        auto mach = DetectMachine();
        switch (mach) {
            case MachineType::X86:
                return MachineType::UNKNOWN; // b64 not allowed for 32bit machines.
            case MachineType::X86_64:
                return MachineType::X86_64;
            case MachineType::ARM:
                return MachineType::UNKNOWN; // b64 not allowed for 32bit machines.
            case MachineType::ARM64:
                return MachineType::ARM64;
        }
        return mach;
    } else if (arch == "b32") {
        auto mach = DetectMachine();
        switch (mach) {
            case MachineType::X86:
            case MachineType::X86_64:
                return MachineType::X86;
            case MachineType::ARM:
            case MachineType::ARM64:
                return MachineType::ARM;
        }
        return mach;
    } else if (arch == "x86_64") {
        return MachineType ::X86_64;
    } else if (arch == "i686" || arch == "i386" || arch == "i486" || arch == "i586") {
        return MachineType::X86;
    } else if (arch == "arm" || arch == "armeb" || arch == "armv5tejl" || arch == "armv5tel" || arch == "armv6l" || arch == "armv7l") {
        return MachineType::ARM;
    } else if (arch == "aarch64") {
        return MachineType::ARM64;
    } else {
        auto itr = s_name2mach.find(std::string(arch));
        if (itr != s_name2mach.end()) {
            return itr->second;
        }
    }
    return MachineType::UNKNOWN;
}

bool MachineToName(MachineType mach, std::string& str) {
    switch (mach) {
        case MachineType::X86:
            str = "i386";
            return true;
        case MachineType::X86_64:
            str = "x86_64";
            return true;
        case MachineType::ARM:
            str = "arm";
            return true;
        case MachineType::ARM64:
            str = "aarch64";
            return true;
        default:
            str = "unknown-machine("+std::to_string(static_cast<int>(mach))+")";
            return false;
    }
}

static std::unordered_map<std::string, uint32_t> s_name2arch({
        {"i386", AUDIT_ARCH_I386},
        {"i486", AUDIT_ARCH_I386},
        {"i586", AUDIT_ARCH_I386},
        {"i686", AUDIT_ARCH_I386},
        {"x86_64", AUDIT_ARCH_X86_64},
        {"arm", AUDIT_ARCH_ARM},
        {"armeb", AUDIT_ARCH_ARM},
        {"armv5tejl", AUDIT_ARCH_ARM},
        {"armv5tel", AUDIT_ARCH_ARM},
        {"armv6l", AUDIT_ARCH_ARM},
        {"armv7l", AUDIT_ARCH_ARM},
        {"aarch64", AUDIT_ARCH_AARCH64},
});

uint32_t ArchNameToArch(const std::string_view& arch) {
    if (arch == "b64") {
        auto mach = DetectMachine();
        if (Is64BitMachineType(mach)) {
            return MachineToArch(mach);
        }
        return 0;
    } else if (arch == "b32") {
        auto mach = DetectMachine();
        switch (mach) {
            case MachineType::X86:
            case MachineType::X86_64:
                return AUDIT_ARCH_I386;
            case MachineType::ARM:
            case MachineType::ARM64:
                return AUDIT_ARCH_ARM;
            default:
                return 0;
        }
    } else {
        auto itr = s_name2arch.find(std::string(arch));
        if (itr != s_name2arch.end()) {
            return itr->second;
        }
    }
    return 0;
}

MachineType ArchToMachine(uint32_t arch) {
    switch (arch) {
        case AUDIT_ARCH_I386:
            return MachineType::X86;
        case AUDIT_ARCH_X86_64:
            return MachineType::X86_64;
        case AUDIT_ARCH_ARM:
            return MachineType::ARM;
        case AUDIT_ARCH_ARMEB:
            return MachineType::ARM;
        case AUDIT_ARCH_AARCH64:
            return MachineType::ARM64;
        default:
            return MachineType::UNKNOWN;
    }
}

uint32_t MachineToArch(MachineType arch) {
    switch (arch) {
        case MachineType::X86:
            return AUDIT_ARCH_I386;
        case MachineType::X86_64:
            return AUDIT_ARCH_X86_64;
        case MachineType::ARM:
            return AUDIT_ARCH_ARM;
        case MachineType::ARM64:
            return AUDIT_ARCH_AARCH64;
        default:
            return 0;
    }
}

std::string ArchToName(uint32_t arch) {
    switch (arch) {
        case AUDIT_ARCH_I386:
            return "i386";
        case AUDIT_ARCH_X86_64:
            return "x86_64";
        case AUDIT_ARCH_ARM:
            return "arm";
        case AUDIT_ARCH_ARMEB:
            return "arm";
        case AUDIT_ARCH_AARCH64:
            return "aarch64";
        default:
            return "unknown-arch("+std::to_string(arch)+")";
    }
}
