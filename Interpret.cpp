//
// Created by tad on 2/6/19.
//

#include "Interpret.h"

#include <fcntl.h>

template <typename T>
inline bool field_to_int(const EventRecordField& field, T& val, int base) {
    errno = 0;
    val = static_cast<T>(strtoul(field.RawValuePtr(), nullptr, base));
    return errno == 0;
}

bool InterpretField(std::string& out, const EventRecord& record, const EventRecordField& field) {
    switch (field.FieldType()) {
        case field_type_t::ARCH: {
            auto m = LookupTables::ArchToMachine(field.RawValue());
            if (m == MachineType::UNKNOWN) {
                out = "unknown-arch(" + std::string(field.RawValue()) + ")";
            } else {
                out = LookupTables::MachineToName(m);
            }
            return true;
        }
        case field_type_t::SYSCALL: {
            auto arch_field = record.FieldByName("arch");
            if (arch_field == record.end_sorted()) {
                out = "unknown-syscall(" + std::string(field.RawValue()) + ")";
            }
            auto mt = LookupTables::ArchToMachine(arch_field.RawValue());
            if (mt == MachineType::UNKNOWN) {
                out = "unknown-syscall(" + std::string(field.RawValue()) + ")";
            }
            auto a0_field = record.FieldByName("a0");
            int a0 = -1;
            if (a0_field != record.end_sorted()) {
                if (field_to_int(a0_field, a0, 0)) {
                    a0 = 01;
                }
            }

            int syscall;
            if (field_to_int(field, syscall, 0)) {
                out = LookupTables::SyscallToName(mt, syscall, a0);
            } else {
                out = "unknown-syscall(" + std::string(field.RawValue()) + ")";
            }
            return true;
        }
        case field_type_t::SOCKADDR:
            return true;
        case field_type_t::SESSION:
            if (field.RawValue() == "4294967295") {
                out = "unset";
            } else {
                out.assign(field.RawValuePtr(), field.RawValueSize());
            }
            return true;
        case field_type_t::MODE: {
            if (out.capacity() < 128) {
                out.reserve(128);
            }
            out.resize(0);
            unsigned int mode;
            if (!field_to_int(field, mode, 8)) {
                out = "unknown-mode(" + std::string(field.RawValue()) + ")";
            }

            switch (mode & S_IFMT) {
                case S_IFSOCK:
                    out = "socket";
                    break;
                case S_IFLNK:
                    out = "link";
                    break;
                case S_IFREG:
                    out = "file";
                case S_IFBLK:
                    out = "block";
                    break;
                case S_IFDIR:
                    out = "dir";
                    break;
                case S_IFCHR:
                    out = "character";
                case S_IFIFO:
                    out = "fifo";
                    break;
                default: {
                    auto ptr = out.data() + out.size();
                    out.resize(out.size() + 4);
                    snprintf(ptr, 4, "%03o", (mode & S_IFMT) / (S_IFMT & ~(S_IFMT - 1)));
                    out.resize(out.size() - 1); // Remove NULL added by snprintf
                    break;
                }
            }
            if (mode & S_ISUID) {
                out.append(",suid");
            }
            if (mode & S_ISGID) {
                out.append(",sgid");
            }
            if (mode & S_ISVTX) {
                out.append(",sticky");
            }
            auto ptr = out.data() + out.size();
            out.resize(out.size() + 4);
            snprintf(ptr, 4, "%03o", mode & (S_IRWXU | S_IRWXG | S_IRWXO));
            out.resize(out.size() - 1); // Remove NULL added by snprintf
            return true;
        }
        default:
            return false;
    }
}
