/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#ifndef KERN_COMMON_H
#define KERN_COMMON_H

#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/string.h>
#include <bpf_tracing.h>
#include "../../event_defs.h"

// debug tracing cant be found using:
// #cat /sys/kernel/debug/tracing/trace_pipe

#ifdef DEBUG_K
#define BPF_PRINTK( format, ... ) \
    char fmt[] = format; \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__ ); 
#else
#define BPF_PRINTK ((void)0);
#endif

// x64 syscall macros
#define SYSCALL_PT_REGS_PARM1(x) ((x)->di)
#define SYSCALL_PT_REGS_PARM2(x) ((x)->si)
#define SYSCALL_PT_REGS_PARM3(x) ((x)->dx)
#define SYSCALL_PT_REGS_PARM4(x) ((x)->r10)
#define SYSCALL_PT_REGS_PARM5(x) ((x)->r8)
#define SYSCALL_PT_REGS_PARM6(x) ((x)->r9)
#define SYSCALL_PT_REGS_RC(x)    ((x)->ax)


// creat a map to transport events to userland via perf ring buffer
struct bpf_map_def SEC("maps") event_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, //BPF_MAP_TYPE_HASH doesnt stack....
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 512, // 512 CPUs - this needs to accommodate most systems as this is CO:RE-alike
                        // Also, as this map is quite small (8 bytes per entry), we could potentially
                        // make this event bigger and it woulnd't cost much
};
/* note: the alternative would be to transmit the number of CPUs from userland in a shared map and then
   dynamically build/size this map accordingly.  The trade off of potentially wasing <=4K on this map
   and limiting ourselves to systems with <= 512 CPUs seems fair.
*/

// create a map to hold the event as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") event_storage_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(event_s),
    .max_entries = 512,
};

// create a map to hold the args as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") args_storage_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(args_s),
    .max_entries = 512,
};

// create a map to hold a temporary cmdline as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") tempcmdline_array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = CMDLINE_MAX_LEN * 2,
    .max_entries = 512,
};

// create a map to hold a temporary filepath as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") temppath_array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = PATH_MAX * 2,
    .max_entries = 512,
};

// create a hash to hold event arguments between sys_enter and sys_exit
// shared by all cpus because sys_enter and sys_exit could be on different cpus
struct bpf_map_def SEC("maps") args_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(args_s),
    .max_entries = 10240,
};

// create a map to hold the configuration
// only one entry, which is the config struct
struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(config_s),
    .max_entries = 1,
};

// create a map to hold the syscall configuration
// key is syscall << 16 | index
// syscall indicies are per syscall, and each increments from 0
struct bpf_map_def SEC("maps") sysconf_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(sysconf_s),
    .max_entries = 10240,
};


// Our own inline helper functions

// return pointer to struct member
__attribute__((always_inline))
static inline void *deref_member(void *base, unsigned int *refs)
{
    unsigned int i;
    void *ref = base;
    void *result = ref;

    if (refs[0] == -1)
        return NULL;

    #pragma unroll
    for (i=0; i<NUM_REDIRECTS - 1 && ref && refs[i] != -1 && refs[i+1] != -1; i++) {
        if (bpf_probe_read(&result, sizeof(result), ref + refs[i]) != 0)
            return 0;
        ref = result;
    }

    return result + refs[i];
}

// return value pointed to by struct member
__attribute__((always_inline))
static inline u64 deref_ptr(void *base, unsigned int *refs)
{
    u64 result = 0;
    void *ref;

    ref = deref_member(base, refs);

    if (bpf_probe_read(&result, sizeof(result), ref) != 0)
        return 0;

    return result;
}

// extract string from struct
__attribute__((always_inline))
static inline bool deref_string_into(char *dest, unsigned int size, void *base, unsigned int *refs)
{
    unsigned int i;
    void *ref = base;
    u64 result = 0;

    ref = deref_member(base, refs);

    if (ref && bpf_probe_read_str(dest, size, ref) > 0)
        return true;
    else {
        *dest = 0x00;
        return false;
    }
}

// extract filepath from dentry
__attribute__((always_inline))
static inline bool deref_filepath_into(char *dest, void *base, unsigned int *refs, config_s *config)
{
    int dlen;
    char *dname = NULL;
    char *temp = NULL;
    unsigned int i;
    unsigned int size=0;
    u32 map_id = bpf_get_smp_processor_id();
    void *path = NULL;
    void *dentry = NULL;
    void *newdentry = NULL;
    void *vfsmount = NULL;
    void *mnt = NULL;

    // nullify string in case of error
    dest[0] = 0x00;

    path = deref_member(base, refs);
    if (!path)
        return false;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->path_dentry[0]) != 0)
        return false;

    if (!dentry)
        return false;

    // get a pointer to the vfsmount
    if (bpf_probe_read(&vfsmount, sizeof(vfsmount), path + config->path_vfsmount[0]) != 0)
        return false;

    // retrieve temporary filepath storage
    temp = bpf_map_lookup_elem(&temppath_array, &map_id);
    if (!temp)
        return false;

    #pragma unroll
    for (i=0; i<FILEPATH_NUMDIRS && size<PATH_MAX; i++) {
        if (bpf_probe_read(&dname, sizeof(dname), dentry + config->dentry_name[0]) != 0)
            return false;
        if (!dname)
            return false;
        // store this dentry name in start of second half of our temporary storage
        dlen = bpf_probe_read_str(&temp[PATH_MAX], PATH_MAX, dname);
        if (dlen <= 0 || dlen >= PATH_MAX || size + dlen > PATH_MAX)
            return false;
        // get parent dentry
        bpf_probe_read(&newdentry, sizeof(newdentry), dentry + config->dentry_parent[0]);
        // check if current dentry name is valid
        if (dlen > 0) {
            // copy the temporary copy to the first half of our temporary storage, building it backwards from the middle of it
            dlen = bpf_probe_read_str(&temp[(PATH_MAX - size - dlen) & (PATH_MAX - 1)], dlen & (PATH_MAX - 1), &temp[PATH_MAX]);
            if (dlen <= 0)
                return false;
            if (size > 0)
                // overwrite the null char with a slash
                temp[(PATH_MAX - size - 1) & (PATH_MAX - 1)] = '/';
            size = size + dlen;
        }
        // check if this is the root of the filesystem
        if (!newdentry || dentry == newdentry) {
            // check if we're on a mounted partition
            // find mount struct from vfsmount
            mnt = vfsmount - config->mount_mnt[0];
            void *parent = (void *)deref_ptr(mnt, config->mount_parent);
            // check if we're at the real root
            if (parent == mnt)
                break;
            // move to mount point
            vfsmount = parent + config->mount_mnt[0];
            newdentry = (void *)deref_ptr(mnt, config->mount_mountpoint);
            // another check for real root
            if (dentry == newdentry)
                break;
            size = size - dlen;
        }

        // go up one directory
        dentry = newdentry;
    }

    // copy the path from the temporary location to the destination
    if (size == 2)
        // path is simply "/"
        dlen = bpf_probe_read_str(dest, PATH_MAX, &temp[PATH_MAX - size]);
    else if (size > 2)
        // otherwise don't copy the extra slash
        dlen = bpf_probe_read_str(dest, PATH_MAX, &temp[PATH_MAX - (size - 1)]);
    if (dlen <= 0)
        return false;

    return true;
}

// extract command line from argv[]
__attribute__((always_inline))
static inline bool extract_commandline(event_execve_s *e, const char **argv, u32 map_id)
{
    volatile const char *argp;
    int dlen;
    unsigned int i;
    char *temp = NULL;

    // nullify string in case of error
    e->cmdline[0] = 0x00;
    e->args_count = 0;
    e->cmdline_size  = 0;

    // retrieve temporary filepath storage
    temp = bpf_map_lookup_elem(&tempcmdline_array, &map_id);
    if (!temp) {
        BPF_PRINTK("extract_commandline bpf_map_lookup_elem()\n");
        return false;
    }

    // check if &argv == NULL; this linux-specific behaviour is permitted
    if (!argv) {
        return true;
    }
   
    #pragma unroll // no loops in eBPF, but need to get all args....
    for (int i = 0; i < CMDLINE_MAX_ARGS && e->cmdline_size < CMDLINE_MAX_LEN; i++) {
        if (bpf_probe_read(&argp, sizeof(argp), (void*) &argv[i]) != 0) {
            // don't report page fault as an error at this point
            // pick this up on exit
            return false;
        }
        if (!argp)
            break;

        dlen = bpf_probe_read_str(&temp[e->cmdline_size & (CMDLINE_MAX_LEN - 1)], CMDLINE_MAX_LEN, (void*) argp);
        if (dlen < 0) {
            // don't report page fault as an error at this point
            // pick this up on exit
            return false;
        }

        e->args_count++;
        e->cmdline_size += dlen;
    }

    // copy from temporary cmdline to actual cmdline
    if (e->cmdline_size > 0)
        if (bpf_probe_read(e->cmdline, e->cmdline_size & (CMDLINE_MAX_LEN - 1), temp) != 0) {
            BPF_PRINTK("extract_commandline: copy from temp\n");
            return false;
        }

    return true;
}

// extract pathname from a file descriptor
__attribute__((always_inline))
static inline bool fd_to_path(char *fd_path, int fd, void *task, config_s *config)
{
    int byte_count;

    // check if fd is valid
    int max_fds = deref_ptr(task, config->max_fds);
    if (fd < 0 || fd > MAX_FDS || max_fds <= 0 || fd > max_fds) {
        return false;
    }

    // resolve the fd to the fd_path
    void **fd_table = (void **)deref_ptr(task, config->fd_table);
    if (!fd_table) {
        return false;
    }

    void *file = NULL;
    if (bpf_probe_read(&file, sizeof(file), &fd_table[fd & MAX_FDS]) != 0 || !file) {
        return false;
    } else {
        return deref_filepath_into(fd_path, file, config->fd_path, config);
    }
}

// wrapper for fd_to_path()
__attribute__((always_inline))
static inline bool resolve_fd_path(event_path_s *fd_path, int fd, void *task, config_s *config)
{
    fd_path->pathname[0] = 0x00;
    fd_path->dfd_path[0] = 'A';
    fd_path->dfd_path[1] = 0x00;

    if (fd > 0)
        return fd_to_path(fd_path->pathname, fd, task, config);

    return false;
}

// extract pathname and dfd pathname
__attribute__((always_inline))
static inline bool resolve_dfd_path(event_path_s *dfd_path, int dfd, char *pathname, void *task, config_s *config)
{
    int byte_count;

    if (pathname) {
        if ((byte_count = bpf_probe_read_str(dfd_path->pathname,
                sizeof(dfd_path->pathname), (void *)pathname)) < 0) {
            BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byte_count);
            return false;
        } 
    }

    dfd_path->dfd_path[1] = 0x00;
    // find the dfd path and store in event
    if (dfd_path->pathname[0] == '/') {
        // absolute path
        dfd_path->dfd_path[0] = 'A';
        return true;
    }
    if (dfd == AT_FDCWD) {
        // relative to current working directory
        dfd_path->dfd_path[0] = 'C';
        return true;
    }

    if (!fd_to_path(dfd_path->dfd_path, dfd, task, config)) {
        dfd_path->dfd_path[0] = 'U';
        BPF_PRINTK("resolve_dfd_path: fd_to_path() failed\n");
        return false;
    }

    return true;
}

// set the initial values for the event arguments
__attribute__((always_inline))
static inline void init_args(args_s *event_args, unsigned long syscall_id)
{
    memset(event_args, 0, sizeof(args_s));
    event_args->syscall_id = syscall_id;
    for (unsigned int i=0; i<8; i++) {
        event_args->a[i] = 0;
    }
}

// check if this is an event to process
__attribute__((always_inline))
static inline bool sys_enter_check_and_init(args_s *event_args, u32 syscall, u64 pid_tid, u32 cpu_id)
{
    u32 config_id = 0;
    config_s *config;
    u32 userland_pid = 0;
    char syscall_flags = 0;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return false;

    userland_pid = config->userland_pid;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == userland_pid)
        return false;

    // initialise the args
    init_args(event_args, syscall);

    return true;
}

// retrieve and process per-syscall filters
__attribute__((always_inline))
static inline bool check_event_filters(unsigned long *a, u32 syscall)
{
    sysconf_s *sysconf = NULL;
    u32 sysconf_index = 0;
    u32 index = 0;

    // check if there are any filters first
    sysconf_index = syscall << 16;
    sysconf = bpf_map_lookup_elem(&sysconf_map, &sysconf_index);
    if (!sysconf)
        return true;
    #pragma unroll
    for (index = 0; index < 8; index++) {
        sysconf_index = (syscall << 16) | index;
        sysconf = bpf_map_lookup_elem(&sysconf_map, &sysconf_index);
        if (!sysconf)
            return false;
        switch(sysconf->op) {
            case COMP_EQ:
                if (a[sysconf->arg & ARG_MASK] == sysconf->value)
                    return true;
                break;
            case COMP_LT:
                if (sysconf->is_signed) {
                    if ((long)a[sysconf->arg & ARG_MASK] < (long)sysconf->value)
                        return true;
                } else {
                    if (a[sysconf->arg & ARG_MASK] < sysconf->value)
                        return true;
                }
                break;
            case COMP_GT:
                if (sysconf->is_signed) {
                    if ((long)a[sysconf->arg & ARG_MASK] > (long)sysconf->value)
                        return true;
                } else {
                    if (a[sysconf->arg & ARG_MASK] > sysconf->value)
                        return true;
                }
                break;
            case COMP_AND:
                if ((a[sysconf->arg & ARG_MASK] & sysconf->value) == sysconf->value)
                    return true;
                break;
            case COMP_OR:
                if (a[sysconf->arg & ARG_MASK] & sysconf->value)
                    return true;
                break;
        }
    }
    return false;
}

// complete and store event
__attribute__((always_inline))
static inline void sys_enter_complete_and_store(args_s *event_args, u32 syscall, u64 pid_tid)
{
    args_s args;
    memset(&args, 0, sizeof(args_s));
    // check syscall conditions
    if (check_event_filters(event_args->a, syscall)) {
        // store args in the hash
        args.a[0] = event_args->a[0];
        args.a[1] = event_args->a[1];
        args.a[2] = event_args->a[2];
        args.a[3] = event_args->a[3];
        args.a[4] = event_args->a[4];
        args.a[5] = event_args->a[5];
        args.syscall_id = event_args->syscall_id;
        long ret = 0;
        if ((ret = bpf_map_update_elem(&args_hash, &pid_tid, &args, BPF_ANY)) != 0){
            BPF_PRINTK("ERROR, HASHMAP: failed to update args map, %ld\n", ret);
        }
    }
}

// set the initial values for an event
__attribute__((always_inline))
static inline void init_event(event_s *event, args_s *event_args, unsigned int pid)
{
    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end   = CODE_BYTES;
    event->version          = VERSION;
    event->syscall_id       = event_args->syscall_id;
    event->status           = 0;
    event->pid              = pid;
    for (int i=0; i<6; i++) {
        event->a[i] = event_args->a[i];
    }
}

// extract details of the process' executable
__attribute__((always_inline))
static inline bool set_event_exe_info(event_s *event, void *task, config_s *config)
{
    void *path = NULL;
    void *dentry = NULL;
    void *inode = NULL;

    path = deref_member(task, config->exe_path);
    if (!path)
        return false;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->path_dentry[0]) != 0)
        return false;
    inode = (void *)deref_ptr(dentry, config->dentry_inode);
    if (!inode)
        return false;
    event->exe_mode = (u16)deref_ptr(inode, config->inode_mode);
    event->exe_ouid = (u32)deref_ptr(inode, config->inode_ouid);
    event->exe_ogid = (u32)deref_ptr(inode, config->inode_ogid);
    return true;
}

// fill in details on syscall exit
__attribute__((always_inline))
static inline bool set_event_exit_info(event_s *event, void *task, config_s *config)
{
    void *cred = NULL;
    char notty[] = "(none)";

    // timestamp
    event->bootns = bpf_ktime_get_ns();

    // get the ppid
    event->ppid = (u32)deref_ptr(task, config->ppid);

    // get the session
    event->auid = (u32)deref_ptr(task, config->auid);
    event->ses = (u32)deref_ptr(task, config->ses);

    if (!deref_string_into(event->tty, sizeof(event->tty), task, config->tty)){
        bpf_probe_read_str(event->tty, sizeof(event->tty), notty);
    }

    // get the creds
    cred = (void *)deref_ptr(task, config->cred);
    if (cred) {
        event->uid = (u32)deref_ptr(cred, config->cred_uid);
        event->gid = (u32)deref_ptr(cred, config->cred_gid);
        event->euid = (u32)deref_ptr(cred, config->cred_euid);
        event->suid = (u32)deref_ptr(cred, config->cred_suid);
        event->fsuid = (u32)deref_ptr(cred, config->cred_fsuid);
        event->egid = (u32)deref_ptr(cred, config->cred_egid);
        event->sgid = (u32)deref_ptr(cred, config->cred_sgid);
        event->fsgid = (u32)deref_ptr(cred, config->cred_fsgid);
    } else {
        BPF_PRINTK("ERROR, failed to deref creds\n");
        event->status |= STATUS_CRED;

        event->uid = -1;
        event->gid = -1;
        event->euid = -1;
        event->suid = -1;
        event->fsuid = -1;
        event->egid = -1;
        event->sgid = -1;
        event->fsgid = -1;
    }

    // get the comm, etc
    if (!deref_string_into(event->comm, sizeof(event->comm), task, config->comm))
        event->status |= STATUS_COMM;
    if (!deref_filepath_into(event->exe, task, config->exe_path, config))
        event->status |= STATUS_EXE;
    if (!deref_filepath_into(event->pwd, task, config->pwd_path, config))
        event->status |= STATUS_PWD;
    if (!set_event_exe_info(event, task, config))
        event->status |= STATUS_EXEINFO;

    if (!event->status)
        return false;
    else
        return true;
}

// extract details from the arguments
__attribute__((always_inline))
static inline void set_event_arg_info(event_s *event, void *task, config_s *config, u32 cpu_id)
{
    switch(event->syscall_id)
    {
        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        case __NR_connect: 
        {
            if (bpf_probe_read(&event->socket.addr, sizeof(event->socket.addr), (void *)event->a[1]) != 0) {
                BPF_PRINTK("ERROR, CONNECT(%lu): failed to get socket info from a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int accept(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen);
        // int accept4(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags);
        case __NR_accept:
        case __NR_accept4:
        {
            event->socket.addr.sin_family = AF_UNSPEC;
            if (event->a[1] != 0) {
                if (bpf_probe_read(&event->socket.addr, 
                                         sizeof(event->socket.addr), 
                                         (void *)event->a[1]) != 0) {
                    BPF_PRINTK("ERROR, ACCEPT(%lu) failed to retrieve addr info from a1 0x%lx\n", event->syscall_id, event->a[1]);
                    event->status |= STATUS_VALUE;
                }
            }
            break;
        }

        // int open(const char *pathname, int flags, mode_t mode);
        case __NR_open:
        // int truncate(const char *pathname, long length);
        case __NR_truncate:
        // int rmdir(const char *pathname);
        case __NR_rmdir:
        // int creat(const char *pathname, int mode);
        case __NR_creat:
        // int unlink(const char *pathname);
        case __NR_unlink:
        // int chmod(const char *pathname, mode_t mode);
        case __NR_chmod:
        // int chown(const char *pathname, uid_t user, gid_t group);
        case __NR_chown:
        // int lchown(const char *pathname, uid_t user, gid_t group);
        case __NR_lchown:
        // int mknod(const char *pathname, umode_t mode, unsigned dev);
        case __NR_mknod:
        {
            if (!resolve_dfd_path(&event->fileop.path1, AT_FDCWD, (void *)event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int rename(const char *oldname, const char *newname);
        case __NR_rename:
        // int link(const char *oldname, const char *newname);
        case __NR_link:
        // int symlink(const char *oldname, const char *newname);
        case __NR_symlink:
        {
            if (!resolve_dfd_path(&event->fileop.path1, AT_FDCWD, (void *)event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
            if (!resolve_dfd_path(&event->fileop.path2, AT_FDCWD, (void *)event->a[1], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int ftruncate(unsigned int fd, unsigned long length);
        case __NR_ftruncate:
        // int fchmod(unsigned int fd, mode_t mode);
        case __NR_fchmod:
        // int fchown(unsigned int fd, uid_t user, gid_t group);
        case __NR_fchown:
        {
            if (!resolve_fd_path(&event->fileop.path1, event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_fd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int openat(int dirfd, const char *pathname, int flags);
        // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
        case __NR_openat: // syscall id #s might be kernel specific
        // int mknodat(int dfd, const char *pathname, int mode, unsigned dev);
        case __NR_mknodat: // syscall id #s might be kernel specific
        // int fchownat(int dfd, const char *pathname, uid_t user, gid_t group, int flag);
        case __NR_fchownat: // syscall id #s might be kernel specific
        // int unlinkat(int dfd, const char *pathname, int flag);
        case __NR_unlinkat: // syscall id #s might be kernel specific
        // int fchmodat(int dfd, const char *pathname, mode_t mode);
        case __NR_fchmodat: // syscall id #s might be kernel specific
        {
            int dfd = event->a[0];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[1], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int renameat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
        case __NR_renameat: // syscall id #s might be kernel specific
        // int renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);
        case __NR_renameat2: // syscall id #s might be kernel specific
        // int linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
        case __NR_linkat: // syscall id #s might be kernel specific
        {
            int dfd = event->a[0];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[1], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
            }
            dfd = event->a[2];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[3], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a3 0x%lx\n", event->syscall_id, event->a[3]);
                event->status |= STATUS_VALUE;
                }
            break;
        }

        // int symlinkat(const char *oldname, int newdfd, const char *newname);
        case __NR_symlinkat: // syscall id #s might be kernel specific
        {
            if (!resolve_dfd_path(&event->fileop.path1, AT_FDCWD, (void *)event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
            int dfd = event->a[1];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[2], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a2 0x%lx\n", event->syscall_id, event->a[2]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int execve(const char *filename, char *const argv[], char *const envp[]);
        case __NR_execve: 
        // int execveat(int dfd, const char *filename, char *const argv[], char *const envp[]);
        case __NR_execveat: 
        {
            if (event->return_code == 0) {
                // read the more reliable cmdline from task_struct->mm->arg_start
                u64 arg_start = deref_ptr(task, config->mm_arg_start);
                u64 arg_end = deref_ptr(task, config->mm_arg_end);
                int arg_len = arg_end - arg_start;
                if (arg_len > (CMDLINE_MAX_LEN - 1))
                    arg_len = CMDLINE_MAX_LEN - 1;

                if (bpf_probe_read(&event->execve.cmdline, arg_len & (CMDLINE_MAX_LEN - 1), (void *)arg_start) < 0) {
                    BPF_PRINTK("ERROR, execve(%d), failed to read cmdline from mm\n", event->syscall_id);
                    event->status |= STATUS_VALUE;
                }
                // add nul terminator just in case
                event->execve.cmdline[CMDLINE_MAX_LEN - 1] = 0x00;
                event->execve.cmdline[arg_len & (CMDLINE_MAX_LEN - 1)] = 0x00;
                event->execve.cmdline_size = arg_len;
            } else {
                // execve failed so the task_struct has the parent cmdline
                // if extract_cmdline() failed then cmdline will be empty,
                // so report this as an error
                const char **argv;
                if (event->syscall_id == __NR_execve)
                    argv = (const char **)event->a[1];
                else
                    argv = (const char **)event->a[2];

                if (!extract_commandline(&event->execve, argv, cpu_id)) {
                    BPF_PRINTK("ERROR, execve(%d), failed to get cmdline\n", event->syscall_id);
                    event->status |= STATUS_VALUE;
                }
            }
            break;
        }
    }
}

// check and send
__attribute__((always_inline))
static inline void check_and_send_event(void *ctx, event_s *event, config_s *config)
{
    bool send_event = true;

    if (!event->status)
        send_event = true;
    else {
        if ((event->status & STATUS_VALUE) &&
            (config->active[event->syscall_id & (SYSCALL_ARRAY_SIZE - 1)] & ACTIVE_PARSEV))
            send_event = false;
        if ((event->status & ~STATUS_VALUE) &&
            (config->active[event->syscall_id & (SYSCALL_ARRAY_SIZE - 1)] & ACTIVE_NOFAIL))
            send_event = false;
    }

    if (send_event) {
        bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
    } else {
        BPF_PRINTK("ERROR, Unable to finish event... dropping\n");
    }
}
 
#endif
