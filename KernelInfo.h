/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_KERNELINFO_H
#define AUOMS_KERNELINFO_H

#include <string>

class KernelInfo {
public:
    static KernelInfo GetKernelInfo() {
        KernelInfo info;
        info.load();
        return info;
    };

    static std::string KernelVersion() { return ptr()->_kver; }
    static bool Is64bit() { return ptr()->_is_64bit; };
    static bool HasAuditSyscall() { return ptr()->_syscall; };
    static bool HasAuditInterfieldCompare() { return ptr()->_compare; };
    static bool HasAuditExeField() { return ptr()->_exe_field; };
    static bool HasAuditSessionIdField() { return ptr()->_session_id_field; };
    static bool HasAuditMulticast() { return ptr()->_audit_multicast; };

private:
    KernelInfo(): _kver(), _is_64bit(false), _syscall(false), _compare(false), _exe_field(false), _session_id_field(false), _audit_multicast(false) {};

    static void init();
    static KernelInfo* ptr();

    void load() noexcept;

    static KernelInfo* _info;
    std::string _kver;
    bool _is_64bit;
    bool _syscall;
    bool _compare;
    bool _exe_field;
    bool _session_id_field;
    bool _audit_multicast;
};


#endif //AUOMS_KERNELINFO_H
