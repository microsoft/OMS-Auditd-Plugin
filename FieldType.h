//
// Created by tad on 3/8/19.
//

#ifndef AUOMS_FIELDTYPE_H
#define AUOMS_FIELDTYPE_H

// This enum mirrors the auparse_type_t found in auparse-defs.h
// The values here must appear in the same order as their counterpart in the definition of auparse_type_t
enum class field_type_t: int {
    UNKNOWN = -1,
    UNCLASSIFIED = 0,
    UID,
    GID,
    SYSCALL,
    ARCH,
    EXIT,
    ESCAPED,
    PERM,
    MODE,
    SOCKADDR,
    FLAGS,
    PROMISC,
    CAPABILITY,
    SUCCESS,
    A0,
    A1,
    A2,
    A3,
    SIGNAL,
    LIST,
    TTY_DATA,
    SESSION,
    CAP_BITMAP,
    NFPROTO,
    ICMPTYPE,
    PROTOCOL,
    ADDR,
    PERSONALITY,
    SECCOMP,
    OFLAG,
    MMAP,
    MODE_SHORT,
    MAC_LABEL,
    PROCTITLE,
    HOOK,
    NETACTION,
    MACPROTO,
    IOCTL_REQ,
    ESCAPED_KEY
};

#endif //AUOMS_FIELDTYPE_H
