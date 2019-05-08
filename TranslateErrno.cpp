/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <linux/audit.h>

#include "Translate.h"
#include "StringTable.h"

#include <errno.h>

static StringTable<int> s_errno_table(0, {
        {"EPERM", EPERM},
        {"ENOENT", ENOENT},
        {"ESRCH", ESRCH},
        {"EINTR", EINTR},
        {"EIO", EIO},
        {"ENXIO", ENXIO},
        {"E2BIG", E2BIG},
        {"ENOEXEC", ENOEXEC},
        {"EBADF", EBADF},
        {"ECHILD", ECHILD},
        {"EAGAIN", EAGAIN},
        {"ENOMEM", ENOMEM},
        {"EACCES", EACCES},
        {"EFAULT", EFAULT},
        {"ENOTBLK", ENOTBLK},
        {"EBUSY", EBUSY},
        {"EEXIST", EEXIST},
        {"EXDEV", EXDEV},
        {"ENODEV", ENODEV},
        {"ENOTDIR", ENOTDIR},
        {"EISDIR", EISDIR},
        {"EINVAL", EINVAL},
        {"ENFILE", ENFILE},
        {"EMFILE", EMFILE},
        {"ENOTTY", ENOTTY},
        {"ETXTBSY", ETXTBSY},
        {"EFBIG", EFBIG},
        {"ENOSPC", ENOSPC},
        {"ESPIPE", ESPIPE},
        {"EROFS", EROFS},
        {"EMLINK", EMLINK},
        {"EPIPE", EPIPE},
        {"EDOM", EDOM},
        {"ERANGE", ERANGE},
        {"EDEADLK", EDEADLK},
        {"ENAMETOOLONG", ENAMETOOLONG},
        {"ENOLCK", ENOLCK},
        {"ENOSYS", ENOSYS},
        {"ENOTEMPTY", ENOTEMPTY},
        {"ELOOP", ELOOP},
        {"EWOULDBLOCK", EWOULDBLOCK},
        {"ENOMSG", ENOMSG},
        {"EIDRM", EIDRM},
        {"ECHRNG", ECHRNG},
        {"EL2NSYNC", EL2NSYNC},
        {"EL3HLT", EL3HLT},
        {"EL3RST", EL3RST},
        {"ELNRNG", ELNRNG},
        {"EUNATCH", EUNATCH},
        {"ENOCSI", ENOCSI},
        {"EL2HLT", EL2HLT},
        {"EBADE", EBADE},
        {"EBADR", EBADR},
        {"EXFULL", EXFULL},
        {"ENOANO", ENOANO},
        {"EBADRQC", EBADRQC},
        {"EBADSLT", EBADSLT},
        {"EDEADLOCK", EDEADLOCK},
        {"EBFONT", EBFONT},
        {"ENOSTR", ENOSTR},
        {"ENODATA", ENODATA},
        {"ETIME", ETIME},
        {"ENOSR", ENOSR},
        {"ENONET", ENONET},
        {"ENOPKG", ENOPKG},
        {"EREMOTE", EREMOTE},
        {"ENOLINK", ENOLINK},
        {"EADV", EADV},
        {"ESRMNT", ESRMNT},
        {"ECOMM", ECOMM},
        {"EPROTO", EPROTO},
        {"EMULTIHOP", EMULTIHOP},
        {"EDOTDOT", EDOTDOT},
        {"EBADMSG", EBADMSG},
        {"EOVERFLOW", EOVERFLOW},
        {"ENOTUNIQ", ENOTUNIQ},
        {"EBADFD", EBADFD},
        {"EREMCHG", EREMCHG},
        {"ELIBACC", ELIBACC},
        {"ELIBBAD", ELIBBAD},
        {"ELIBSCN", ELIBSCN},
        {"ELIBMAX", ELIBMAX},
        {"ELIBEXEC", ELIBEXEC},
        {"EILSEQ", EILSEQ},
        {"ERESTART", ERESTART},
        {"ESTRPIPE", ESTRPIPE},
        {"EUSERS", EUSERS},
        {"ENOTSOCK", ENOTSOCK},
        {"EDESTADDRREQ", EDESTADDRREQ},
        {"EMSGSIZE", EMSGSIZE},
        {"EPROTOTYPE", EPROTOTYPE},
        {"ENOPROTOOPT", ENOPROTOOPT},
        {"EPROTONOSUPPORT", EPROTONOSUPPORT},
        {"ESOCKTNOSUPPORT", ESOCKTNOSUPPORT},
        {"EOPNOTSUPP", EOPNOTSUPP},
        {"EPFNOSUPPORT", EPFNOSUPPORT},
        {"EAFNOSUPPORT", EAFNOSUPPORT},
        {"EADDRINUSE", EADDRINUSE},
        {"EADDRNOTAVAIL", EADDRNOTAVAIL},
        {"ENETDOWN", ENETDOWN},
        {"ENETUNREACH", ENETUNREACH},
        {"ENETRESET", ENETRESET},
        {"ECONNABORTED", ECONNABORTED},
        {"ECONNRESET", ECONNRESET},
        {"ENOBUFS", ENOBUFS},
        {"EISCONN", EISCONN},
        {"ENOTCONN", ENOTCONN},
        {"ESHUTDOWN", ESHUTDOWN},
        {"ETOOMANYREFS", ETOOMANYREFS},
        {"ETIMEDOUT", ETIMEDOUT},
        {"ECONNREFUSED", ECONNREFUSED},
        {"EHOSTDOWN", EHOSTDOWN},
        {"EHOSTUNREACH", EHOSTUNREACH},
        {"EALREADY", EALREADY},
        {"EINPROGRESS", EINPROGRESS},
        {"ESTALE", ESTALE},
        {"EUCLEAN", EUCLEAN},
        {"ENOTNAM", ENOTNAM},
        {"ENAVAIL", ENAVAIL},
        {"EISNAM", EISNAM},
        {"EREMOTEIO", EREMOTEIO},
        {"EDQUOT", EDQUOT},
        {"ENOMEDIUM", ENOMEDIUM},
        {"EMEDIUMTYPE", EMEDIUMTYPE},
        {"ECANCELED", ECANCELED},
        {"ENOKEY", ENOKEY},
        {"EKEYEXPIRED", EKEYEXPIRED},
        {"EKEYREVOKED", EKEYREVOKED},
        {"EKEYREJECTED", EKEYREJECTED},
        {"EOWNERDEAD", EOWNERDEAD},
        {"ENOTRECOVERABLE", ENOTRECOVERABLE},
        {"ERFKILL", ERFKILL},
        {"EHWPOISON", EHWPOISON},
});

std::string ErrnoToName(int n) {
    int err = n;
    if (err < 0) {
        err = -err;
    }
    auto str = std::string(s_errno_table.ToString(n));
    if (str.empty()) {
        str = std::to_string(n);
    }
    if (n < 0) {
        return "-" + str;
    } else {
        return str;
    }
}

int NameToErrno(const std::string_view& name) {
    if (!name.empty() && name[0] == '-') {
        return -(s_errno_table.ToInt(name.substr(1)));
    } else {
        return s_errno_table.ToInt(name);
    }
}
