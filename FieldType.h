/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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
    ESCAPED_KEY,
    UNESCAPED
};

#endif //AUOMS_FIELDTYPE_H
