//
// Created by tad on 3/19/19.
//

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

private:
    KernelInfo(): _kver(), _is_64bit(false), _syscall(false), _compare(false), _exe_field(false), _session_id_field(false) {};

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
};


#endif //AUOMS_KERNELINFO_H
