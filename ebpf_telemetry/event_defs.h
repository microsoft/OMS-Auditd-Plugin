/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#ifndef EVENT_DEFS_H
#define EVENT_DEFS_H

#include <linux/limits.h>

#define VERSION 1
#define CODE_BYTES 0xdeadbeef

#define TOTAL_MAX_ARGS 128
#define ARGSIZE  128
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

// __NR_openat
typedef struct e_openat {
    char    filename[PATH_MAX];
} event_openat_s;

// __NR_execve
typedef struct e_execve {
    unsigned int  args_count;
    unsigned int  args_size;
    char          exe[PATH_MAX];
    char          cmdline[LAST_ARG];
} event_execve_s;

// __NR_connect: 
typedef struct e_socket {
    struct sockaddr_in *addrp;
    struct sockaddr_in addr;
} event_socket_s;

// Event structure
typedef struct e_rec {
    unsigned long int  code_bytes; //Always 0xdeadbeef = 3735928559
    unsigned int       version;
    unsigned long      syscall_id;
    unsigned int       pid;
    long int           return_code;
    unsigned int       ppid;
    unsigned int       ses;
    char               tty[64];
    char               comm[16];
    char               exe[PATH_MAX]; 
    unsigned int       auid;
    unsigned int       uid;
    unsigned int       gid;
    unsigned int       euid;
    unsigned int       suid;
    unsigned int       fsuid;
    unsigned int       egid;
    unsigned int       sgid;
    unsigned int       fsgid;
    union e_data {
        event_openat_s openat;
        event_execve_s execve;
        event_socket_s socket;
    } data;
} event_s;

// configuration
typedef struct conf {
    unsigned int userland_pid;
    unsigned int timesec[8];
    unsigned int timensec[8];
    unsigned int serial[8];
    unsigned int arch[8];
    unsigned int arg0[8];
    unsigned int arg1[8];
    unsigned int arg2[8];
    unsigned int arg3[8];
    unsigned int ppid[8];
    unsigned int auid[8];
    unsigned int cred[8];
    unsigned int cred_uid[8];
    unsigned int cred_gid[8];
    unsigned int cred_euid[8];
    unsigned int cred_suid[8];
    unsigned int cred_fsuid[8];
    unsigned int cred_egid[8];
    unsigned int cred_sgid[8];
    unsigned int cred_fsgid[8];
    unsigned int ses[8];
    unsigned int tty[8];
    unsigned int comm[8];
    unsigned int exe_dentry[8];
    unsigned int dentry_parent;
    unsigned int dentry_name;
    unsigned int cwd[8];
    unsigned int proctitle[8];
    unsigned int name_count[8];
    unsigned int names_head[8];
    unsigned int names_name[8];
    unsigned int names_namelen[8];
    unsigned int names_ino[8];
    unsigned int names_dev[8];
    unsigned int names_mode[8];
    unsigned int names_ouid[8];
    unsigned int names_ogid[8];
    unsigned int names_rdev[8];
    unsigned int names_type[8];
    unsigned int names_cap_fp[8];
    unsigned int names_cap_fi[8];
    unsigned int names_cap_fe[8];
    unsigned int names_cap_fver[8];
    unsigned int names_cap_frootid[8];
} config_s;

#endif
