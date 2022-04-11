/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Interpret.h"
#include "Translate.h"
#include "StringUtils.h"
#include "StringTable.h"
#include "Logger.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#ifndef NO_INTERP_EXTRA_PROTO
#include <linux/ax25.h>
#include <linux/atm.h>
#include <linux/x25.h>
#include <linux/ipx.h>
#endif

template <typename T>
inline bool field_to_int(const EventRecordField& field, T& val, int base) {
    errno = 0;
    val = static_cast<T>(strtol(field.RawValuePtr(), nullptr, base));
    return errno == 0;
}

template <typename T>
inline bool field_to_uint(const EventRecordField& field, T& val, int base) {
    errno = 0;
    val = static_cast<T>(strtoul(field.RawValuePtr(), nullptr, base));
    return errno == 0;
}

static StringTable<int> s_fam_table(-1, {
        {"local",      AF_LOCAL},
        {"inet",       AF_INET},
        {"ax25",       AF_AX25},
        {"ipx",        AF_IPX},
        {"appletalk",  AF_APPLETALK},
        {"netrom",     AF_NETROM},
        {"bridge",     AF_BRIDGE},
        {"atmpvc",     AF_ATMPVC},
        {"x25",        AF_X25},
        {"inet6",      AF_INET6},
        {"rose",       AF_ROSE},
        {"decnet",     AF_DECnet},
        {"netbeui",    AF_NETBEUI},
        {"security",   AF_SECURITY},
        {"key",        AF_KEY},
        {"netlink",    AF_NETLINK},
        {"packet",     AF_PACKET},
        {"ash",        AF_ASH},
        {"econet",     AF_ECONET},
        {"atmsvc",     AF_ATMSVC},
        {"rds",        AF_RDS},
        {"sna",        AF_SNA},
        {"irda",       AF_IRDA},
        {"pppox",      AF_PPPOX},
        {"wanpipe",    AF_WANPIPE},
        {"llc",        AF_LLC},
        {"can",        AF_CAN},
        {"tipc",       AF_TIPC},
        {"bluetooth",  AF_BLUETOOTH},
        {"iucv",       AF_IUCV},
        {"rxrpc",      AF_RXRPC},
        {"isdn",       AF_ISDN},
        {"phonet",     AF_PHONET},
        {"ieee802154", AF_IEEE802154},
        {"caif",       37},
        {"alg",        38},
        {"nfc",        39},
        {"vsock",      40},
});

bool InterpretSockaddrField(std::string& out, const EventRecord& record, const EventRecordField& field) {
    // It is assumed that a sockaddr will never exceed 1024 bytes
    std::array<uint8_t, 1024> _buf;
    if (!decode_hex(_buf.data(), _buf.size(), field.RawValuePtr(), field.RawValueSize())) {
        out = "malformed-host(";
        out.append(field.RawValue());
        out.append(")");
        return false;
    }
    size_t bsize = field.RawValueSize()/2;

    const struct sockaddr *saddr = reinterpret_cast<struct sockaddr *>(_buf.data());
    out.append("{ fam=");
    auto fam = s_fam_table.ToString(saddr->sa_family);
    if (!fam.empty()) {
        out.append(fam);
    } else {
        out.append("unknown-family(");
        out.append(std::to_string(saddr->sa_family));
        out.append(")");
    }
    out.append(" ");

    switch (saddr->sa_family) {
        case AF_LOCAL: {
            auto addr = reinterpret_cast<struct sockaddr_un *>(_buf.data());
            // Calculate the sun_path size based on what was actually provided by the kernel
            // What the kernel emits may be smaller than sizeof(addr->sun_path) and may not be null terminated.
            size_t path_size = bsize-offsetof(struct sockaddr_un, sun_path);
            out.append("path=");
            if (addr->sun_path[0] != 0) {
                // The sun_path might not be NUL terminated, so limit strlen to the minimum of path_size or sizeof(addr->sun_path)
                out.append(addr->sun_path, strnlen(addr->sun_path, std::min(path_size, sizeof(addr->sun_path))));
            } else {
                out.push_back('@');
                if (path_size > 1) {
                    out.append(&addr->sun_path[1], path_size - 1);
                }
            }
            out.append(" }");
            break;
        }
        case AF_INET: {
            std::array<char, INET_ADDRSTRLEN+1> _abuf;
            auto addr = reinterpret_cast<struct sockaddr_in *>(_buf.data());
            if (bsize < sizeof(struct sockaddr_in)) {
                out.append("sockaddr len too short }");
                break;
            }
            if (inet_ntop(AF_INET, &addr->sin_addr, _abuf.data(), _abuf.size()) != nullptr) {
                out.append("laddr=");
                out.append(_abuf.data());
            } else {
                out.append("(error resolving addr) }");
                break;
            }
            out.append(" lport=");
            append_int(out, addr->sin_port);
            out.append(" }");
            break;
        }
#ifndef NO_INTERP_EXTRA_PROTO
        case AF_AX25: {
            auto addr = reinterpret_cast<struct sockaddr_ax25 *>(_buf.data());
            if (bsize < sizeof(struct sockaddr_ax25)) {
                out.append("ax25 len too short }");
                break;
            }
            out.append("call=");
            tty_escape_string_append(out, addr->sax25_call.ax25_call, sizeof(addr->sax25_call.ax25_call));
            out.append(" }");
            break;
        }
        case AF_IPX: {
            auto addr = reinterpret_cast<struct sockaddr_ipx *>(_buf.data());
            if (bsize < sizeof(struct sockaddr_ipx)) {
                out.append("ipx len too short }");
                break;
            }
            out.append("lport=");
            append_int(out, addr->sipx_port);
            out.append("ipx-net=");
            append_uint(out, addr->sipx_network);
            out.append(" }");
            break;
        }
        case AF_ATMPVC: {
            auto addr = reinterpret_cast<struct sockaddr_atmpvc *>(_buf.data());
            if (bsize < sizeof(struct sockaddr_atmpvc)) {
                out.append("atmpvc len too short }");
                break;
            }
            out.append("int=");
            append_uint(out, addr->sap_addr.itf);
            out.append(" }");
            break;
        }
        case AF_X25: {
            auto addr = reinterpret_cast<struct sockaddr_x25 *>(_buf.data());
            if (bsize < sizeof(struct sockaddr_x25)) {
                out.append("x25 len too short }");
                break;
            }
            out.append("laddr=");
            // Valid X25 address is null terminated and only decimal digits (0-9).
            addr->sx25_addr.x25_addr[15] = 0;
            out.append(addr->sx25_addr.x25_addr);
            break;
        }
#endif
        case AF_INET6: {
            std::array<char, INET6_ADDRSTRLEN+1> _abuf;
            auto addr = reinterpret_cast<struct sockaddr_in6 *>(_buf.data());
            if (bsize < sizeof(struct sockaddr_in6)) {
                out.append("sockaddr6 len too short }");
                break;
            }
            if (inet_ntop(AF_INET6, &addr->sin6_addr, _abuf.data(), _abuf.size()) != nullptr) {
                out.append("laddr=");
                out.append(_abuf.data());
            } else {
                out.append("(error resolving addr) }");
                break;
            }
            out.append(" lport=");
            append_int(out, addr->sin6_port);
            out.append(" }");
            break;
        }
        case AF_NETLINK: {
            auto addr = reinterpret_cast<struct sockaddr_nl *>(_buf.data());
            if (bsize < sizeof(struct sockaddr_nl)) {
                out.append("netlink len too short }");
                break;
            }
            out.append("nlnk-fam=");
            append_uint(out, addr->nl_family);
            out.append("nlnk-pid=");
            append_uint(out, addr->nl_pid);
            out.append(" }");
            break;
        }
        default:
            out.append("(unsupported) }");
            break;
    }
    return true;
}

bool InterpretField(std::string& out, const EventRecord& record, const EventRecordField& field, field_type_t field_type) {
    static std::string_view SV_ARCH = "arch";

    switch (field_type) {
        case field_type_t::ARCH: {
            uint32_t arch;
            if (!field_to_uint(field, arch, 16)) {
                arch = 0;
            }
            auto m = ArchToMachine(arch);
            if (m == MachineType::UNKNOWN) {
                Logger::Warn("InterpretField: Invalid arch=%s", field.RawValuePtr());
                out = "unknown-arch(" + std::string(field.RawValue()) + ")";
            } else {
                MachineToName(m, out);
            }
            return true;
        }
        case field_type_t::SYSCALL: {
            auto arch_field = record.FieldByName(SV_ARCH);
            if (!arch_field) {
                out = "unknown-syscall(" + std::string(field.RawValue()) + ")";
                return true;
            }
            uint32_t arch;
            if (!field_to_uint(arch_field, arch, 16)) {
                arch = 0;
            }
            auto mt = ArchToMachine(arch);
            if (mt == MachineType::UNKNOWN) {
                Logger::Warn("InterpretField: Invalid arch=%s", arch_field.RawValuePtr());
                out = "unknown-syscall(" + std::string(field.RawValue()) + ")";
                return true;
            }

            int syscall;
            if (field_to_int(field, syscall, 10)) {
                SyscallToName(mt, syscall, out);
            } else {
                out = "unknown-syscall(" + std::string(field.RawValue()) + ")";
            }
            return true;
        }
        case field_type_t::SOCKADDR:
            return InterpretSockaddrField(out, record, field);
        case field_type_t::SESSION:
            if (field.RawValue() == "4294967295") {
                out = "unset";
                return true;
            }
            return false;
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
                    break;
                case S_IFBLK:
                    out = "block";
                    break;
                case S_IFDIR:
                    out = "dir";
                    break;
                case S_IFCHR:
                    out = "character";
                    break;
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
            out.push_back(',');
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
