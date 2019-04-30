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

#include <linux/audit.h>
#include <sys/utsname.h>

MachineType DetectMachine() {
    struct utsname uts;
    if (uname(&uts) == 0)
        return ArchNameToMachine(uts.machine);
    return MachineType::UNKNOWN;
}

MachineType ArchNameToMachine(const std::string_view& arch) {
    if (arch == "b64") {
        return MachineType::X86_64;
    } else if (arch == "b32") {
        return MachineType::X86;
    } else if (arch == "x86_64") {
        return MachineType ::X86_64;
    } else if (arch == "i686" || arch == "i386" || arch == "i486" || arch == "i586") {
        return MachineType::X86;
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
        default:
            str = "unknown-machine("+std::to_string(static_cast<int>(mach))+")";
            return false;
    }
}

uint32_t ArchNameToArch(const std::string_view& arch) {
    if (arch == "b64") {
        return AUDIT_ARCH_X86_64;
    } else if (arch == "b32") {
        return AUDIT_ARCH_I386;
    } else if (arch == "x86_64") {
        return AUDIT_ARCH_X86_64;
    } else if (arch == "i686" || arch == "i386" || arch == "i486" || arch == "i586") {
        return AUDIT_ARCH_I386;
    }
    return 0;
}

MachineType ArchToMachine(uint32_t arch) {
    switch (arch) {
        case AUDIT_ARCH_I386:
            return MachineType::X86;
        case AUDIT_ARCH_X86_64:
            return MachineType::X86_64;
        default:
            return MachineType::UNKNOWN;
    }
}

std::string ArchToName(uint32_t arch) {
    switch (arch) {
        case AUDIT_ARCH_I386:
            return "i386";
        case AUDIT_ARCH_X86_64:
            return "x86_64";
        default:
            return "unknown-arch("+std::to_string(arch)+")";
    }
}
