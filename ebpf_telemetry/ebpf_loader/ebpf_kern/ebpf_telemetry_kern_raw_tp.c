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


#include "ebpf_kern_common.h"

// x64 syscall macros
#define SYSCALL_PT_REGS_PARM1(x) ((x)->di)
#define SYSCALL_PT_REGS_PARM2(x) ((x)->si)
#define SYSCALL_PT_REGS_PARM3(x) ((x)->dx)
#define SYSCALL_PT_REGS_PARM4(x) ((x)->r10)
#define SYSCALL_PT_REGS_PARM5(x) ((x)->r8)
#define SYSCALL_PT_REGS_PARM6(x) ((x)->r9)
#define SYSCALL_PT_REGS_RC(x)    ((x)->ax)

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
            dlen = bpf_probe_read_str(&temp[(PATH_MAX - size - dlen) & (PATH_MAX - 1)], PATH_MAX, &temp[PATH_MAX]);
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

__attribute__((always_inline))
static inline bool extract_commandline(event_s *e, struct pt_regs* r, u32 map_id)
{
    const char **argv; 
    volatile const char *argp;
    int dlen;
    unsigned int i;
    char *temp = NULL;

    // nullify string in case of error
    e->data.execve.cmdline[0] = 0x00;
    e->data.execve.args_count = 0;
    e->data.execve.cmdline_size  = 0;

    // retrieve temporary filepath storage
    temp = bpf_map_lookup_elem(&tempcmdline_array, &map_id);
    if (!temp)
        return false;
   
    // get the args
    if (bpf_probe_read(&argv, sizeof(argv), (void *)&SYSCALL_PT_REGS_PARM2(r)) != 0)
        return false;
    
    #pragma unroll // no loops in eBPF, but need to get all args....
    for (int i = 0; i < CMDLINE_MAX_ARGS && e->data.execve.cmdline_size < CMDLINE_MAX_LEN; i++) {
        if (bpf_probe_read(&argp, sizeof(argp), (void*) &argv[i]) != 0 || !argp)
            break;

        dlen = bpf_probe_read_str(&temp[e->data.execve.cmdline_size & (CMDLINE_MAX_LEN - 1)], CMDLINE_MAX_LEN, (void*) argp);
        if (dlen <= 0)
            return false;

        e->data.execve.args_count++;
        e->data.execve.cmdline_size += dlen;
    }

    // copy from temporary cmdline to actual cmdline
    bpf_probe_read(e->data.execve.cmdline, e->data.execve.cmdline_size & (CMDLINE_MAX_LEN - 1), temp);

    return true;
}

__attribute__((always_inline))
static inline bool resolve_dfd_path(event_path_s *dfd_path, int dfd, void *path_arg, void *task, config_s *config)
{
    char *pathname = NULL;
    int byte_count;

    if (0 == bpf_probe_read(&pathname, sizeof(pathname), path_arg) ){
        if (0 >= (byte_count = bpf_probe_read_str(dfd_path->pathname, 
                                                    sizeof(dfd_path->pathname), 
                                                    (void *)pathname))){
            BPF_PRINTK("ERROR, reading pathname, returned %ld\n", byte_count);
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

    // check if dfd is valid
    int max_fds = deref_ptr(task, config->max_fds);
    if (dfd < 0 || dfd > MAX_FDS || max_fds <= 0 || dfd > max_fds) {
        dfd_path->dfd_path[0] = 'U';
        return false;
    }

    // resolve the dfd to the dfd_path
    void **fd_table = (void **)deref_ptr(task, config->dfd_table);
    if (!fd_table) {
        dfd_path->dfd_path[0] = 'U';
        return false;
    }

    void *file = NULL;
    if (bpf_probe_read(&file, sizeof(file), &fd_table[dfd & MAX_FDS]) != 0 || !file) {
        dfd_path->dfd_path[0] = 'U';
        return false;
    } else {
        deref_filepath_into(dfd_path->dfd_path, file, config->dfd_path, config);
    }
    return true;
}

__attribute__((always_inline))
static inline unsigned long read_positive_arg(void *arg)
{
    unsigned long val = -1;
    if (bpf_probe_read(&val, sizeof(val), arg) != 0 || val < 0)
        val = -1;
    return val;
}

__attribute__((always_inline))
static inline void init_event(event_s *event, unsigned long syscall_id, unsigned int pid)
{
    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end   = CODE_BYTES;
    event->version          = VERSION;
    event->status           = 0;
    event->syscall_id       = syscall_id;
    event->pid              = pid;
}

__attribute__((always_inline))
static inline void set_event_args(event_s *event, struct pt_regs *regs)
{
    bpf_probe_read(&event->a[0], sizeof(event->a[0]), &SYSCALL_PT_REGS_PARM1(regs));
    bpf_probe_read(&event->a[1], sizeof(event->a[1]), &SYSCALL_PT_REGS_PARM2(regs));
    bpf_probe_read(&event->a[2], sizeof(event->a[2]), &SYSCALL_PT_REGS_PARM3(regs));
    bpf_probe_read(&event->a[3], sizeof(event->a[3]), &SYSCALL_PT_REGS_PARM4(regs));
    bpf_probe_read(&event->a[4], sizeof(event->a[4]), &SYSCALL_PT_REGS_PARM5(regs));
    bpf_probe_read(&event->a[5], sizeof(event->a[5]), &SYSCALL_PT_REGS_PARM6(regs));
}

__attribute__((always_inline))
static inline bool set_event_exe_info(event_s *event, void *task, struct pt_regs *regs, config_s *config)
{
    void *path;
    void *dentry;
    void *inode;

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

__attribute__((always_inline))
static inline bool set_event_exit_info(event_s *event, void *task, struct pt_regs *regs, config_s *config)
{
    void *cred;
    char notty[] = "(none)";

    if (0 != bpf_probe_read(&event->return_code, sizeof(s64), (void *)&SYSCALL_PT_REGS_RC(regs))){
        BPF_PRINTK("ERROR, failed to get return code, exiting syscall %lu\n", event->syscall_id);
        event->status = -1;
    }

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
        BPF_PRINTK("ERROR, ACCEPT failed to deref creds\n");
        event->status = -1;

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
    deref_string_into(event->comm, sizeof(event->comm), task, config->comm);
    deref_filepath_into(event->exe, task, config->exe_path, config);
    deref_filepath_into(event->pwd, task, config->pwd_path, config);
    set_event_exe_info(event, task, regs, config);

    if (event->status == -1)
        return false;
    else
        return true;
}

 
SEC("raw_tracepoint/sys_enter")
__attribute__((flatten))
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 cpu_id = bpf_get_smp_processor_id();
    event_s *event = NULL;
    u32 config_id = 0;
    config_s *config;
    u32 userland_pid = 0;
    int dfd = 0;
    void *task = NULL;

    // bail early for syscalls we aren't interested in
    unsigned long long syscall = ctx->args[1];
    if ( 
            (syscall != __NR_execve)
         && (syscall != __NR_open)
         && (syscall != __NR_openat)
         && (syscall != __NR_truncate)
         && (syscall != __NR_rename)
         && (syscall != __NR_renameat)
         && (syscall != __NR_renameat2)
         && (syscall != __NR_rmdir)
         && (syscall != __NR_creat)
         && (syscall != __NR_link)
         && (syscall != __NR_linkat)
         && (syscall != __NR_unlink)
         && (syscall != __NR_unlinkat)
         && (syscall != __NR_symlink)
         && (syscall != __NR_symlinkat)
         && (syscall != __NR_chmod)
         && (syscall != __NR_fchmodat)
         && (syscall != __NR_chown)
         && (syscall != __NR_lchown)
         && (syscall != __NR_fchownat)
         && (syscall != __NR_mknod)
         && (syscall != __NR_mknodat)
         && (syscall != __NR_accept)
         && (syscall != __NR_accept4)
         && (syscall != __NR_connect)
       )
        return 0;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    userland_pid = config->userland_pid;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == userland_pid)
        return 0;

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &cpu_id);
    if (!event)
        return 0;

    // retrieve the register state
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // initialise the event
    init_event(event, ctx->args[1], pid_tid >> 32);
    set_event_args(event, regs);
    
    // arch/ABI      arg1  arg2  arg3  arg4  arg5  arg6  arg7  
    // ------------------------------------------------------
    // x86-64        rdi   rsi   rdx   r10   r8    r9    -

    // get the task struct
    task = (void *)bpf_get_current_task();

    switch(event->syscall_id)
    {
        // int open(const char *pathname, int flags, mode_t mode);
        case __NR_open:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            break;
        }

        // int openat(int dirfd, const char *pathname, int flags);
        // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
        case __NR_openat: // syscall id #s might be kernel specific
        {
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM1(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path1, dfd, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            break;
        }

        // int rename(const char *oldname, const char *newname);
        case __NR_rename:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            resolve_dfd_path(&event->data.fileop.path2, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            break;
        }

        // int renameat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
        // int renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);
        case __NR_renameat: // syscall id #s might be kernel specific
        case __NR_renameat2: // syscall id #s might be kernel specific
        {
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM1(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path1, dfd, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM3(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path2, dfd, (void *)&SYSCALL_PT_REGS_PARM4(regs), task, config);
            break;
        }

        // int link(const char *oldname, const char *newname);
        case __NR_link:
        {

            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            resolve_dfd_path(&event->data.fileop.path2, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            break;
        }

        // int linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
        case __NR_linkat: // syscall id #s might be kernel specific
        {

            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM1(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path1, dfd, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM3(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path2, dfd, (void *)&SYSCALL_PT_REGS_PARM4(regs), task, config);
            break;
        }

        // int symlink(const char *oldname, const char *newname);
        case __NR_symlink:
        {

            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            resolve_dfd_path(&event->data.fileop.path2, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            break;
        }

        // int symlinkat(const char *oldname, int newdfd, const char *newname);
        case __NR_symlinkat: // syscall id #s might be kernel specific
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM2(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path2, dfd, (void *)&SYSCALL_PT_REGS_PARM3(regs), task, config);
            break;
        }

        // int chown(const char *pathname, uid_t user, gid_t group);
        // int lchown(const char *pathname, uid_t user, gid_t group);
        case __NR_chown:
        case __NR_lchown:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            event->data.fileop.uid = read_positive_arg((void *)&SYSCALL_PT_REGS_PARM2(regs));
            event->data.fileop.gid = read_positive_arg((void *)&SYSCALL_PT_REGS_PARM3(regs));
            break;
        }

        // int fchownat(int dfd, const char *pathname, uid_t user, gid_t group, int flag);
        case __NR_fchownat: // syscall id #s might be kernel specific
        {
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM1(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path1, dfd, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            event->data.fileop.uid = (int)read_positive_arg((void *)&SYSCALL_PT_REGS_PARM3(regs));
            event->data.fileop.gid = (int)read_positive_arg((void *)&SYSCALL_PT_REGS_PARM4(regs));
            break;
        }
        
        // int unlink(const char *pathname);
        case __NR_unlink:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            break;
        }

        // int unlinkat(int dfd, const char *pathname, int flag);
        case __NR_unlinkat: // syscall id #s might be kernel specific
        {
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM1(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path1, dfd, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            break;
        }
        
        // int chmod(const char *pathname, mode_t mode);
        case __NR_chmod:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            break;
        }

        // int fchmodat(int dfd, const char *pathname, mode_t mode);
        case __NR_fchmodat: // syscall id #s might be kernel specific
        {
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM1(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path1, dfd, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            break;
        }
        
        // int mknod(const char *pathname, umode_t mode, unsigned dev);
        case __NR_mknod:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            break;
        }

        // int mknodat(int dfd, const char *pathname, int mode, unsigned dev);
        case __NR_mknodat: // syscall id #s might be kernel specific
        {
            if (bpf_probe_read(&dfd, sizeof(dfd), (void *)&SYSCALL_PT_REGS_PARM1(regs)) != 0 || dfd <= 0)
                dfd = AT_FDCWD;
            resolve_dfd_path(&event->data.fileop.path1, dfd, (void *)&SYSCALL_PT_REGS_PARM2(regs), task, config);
            break;
        }
        
        // int truncate(const char *pathname, long length);
        case __NR_truncate:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            break;
        }

        // int rmdir(const char *pathname);
        case __NR_rmdir:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            break;
        }

        // int creat(const char *pathname, int mode);
        case __NR_creat:
        {
            resolve_dfd_path(&event->data.fileop.path1, AT_FDCWD, (void *)&SYSCALL_PT_REGS_PARM1(regs), task, config);
            break;
        }

        // int execve(const char *filename, char *const argv[], char *const envp[]);
        case __NR_execve: 
        {
            if (0 == extract_commandline(event, regs, cpu_id)){
                BPF_PRINTK("ERROR, EXECVE(%lu): failed to get cmdline\n", event->syscall_id);
                event->status = -1;
            }

            break;
        }
        
        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        case __NR_connect: 
        {
            struct sockaddr *addr;
                        
            if (0 == bpf_probe_read(&addr, sizeof(addr), (void *)&SYSCALL_PT_REGS_PARM2(regs))){
                if (0 != bpf_probe_read(&event->data.socket.addr, sizeof(event->data.socket.addr), (void *)addr)){
                    BPF_PRINTK("ERROR, CONNECT(%lu): failed to get socket info\n", event->syscall_id);
                    event->status = -1;
                }
            }
        }

        case __NR_accept4:
        case __NR_accept:
            
            if (0 != bpf_probe_read(&event->data.socket.addrp, sizeof(event->data.socket.addrp), (void *)&regs->si)){
                BPF_PRINTK("ERROR, ACCEPT(%lu): failed to get socket addr info\n", event->syscall_id);
                event->status = -1;
            }
                        
            break;
        
    }

    // store event in the hash
    long ret = 0;
    if (0 != (ret = bpf_map_update_elem(&events_hash, &pid_tid, event, BPF_ANY))){
        BPF_PRINTK("ERROR, HASHMAP: failed to update event map, %ld\n", ret);
    }

    return 0;
}

SEC("raw_tracepoint/sys_exit")
__attribute__((flatten))
int sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    u32 config_id = 0;
    config_s *config;
    u32 userland_pid = 0;
    void *task;
    void *cred;
    char notty[] = "(none)";
    char *temppath = NULL;
    
    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    userland_pid = config->userland_pid;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == userland_pid)
        return 0;

    // retrieve map storage for event
    // this was mostly completed on the preceding sys_enter
    // if the pid_tid is in our map then we must have stored it
    event = bpf_map_lookup_elem(&events_hash, &pid_tid);
    if (!event)
        // otherwise bail
        return 0;

    // get the task struct
    task = (void *)bpf_get_current_task();

    // if the event is incomplete we may not want to process further. 
    if (0 != event->status){
        BPF_PRINTK("ERROR, sys_enter failed, stopping sys_exit processing %lu\n", event->syscall_id);
    } 
        
    set_event_exit_info(event, task, regs, config);

    switch(event->syscall_id)
    {
        case __NR_accept4:
        case __NR_accept:
        {
            if (0 != bpf_probe_read(&event->data.socket.addr, 
                                     sizeof(event->data.socket.addr), 
                                     (void *)event->data.socket.addrp)){
                BPF_PRINTK("ERROR, ACCEPT failed to retrieve addr info\n");
                event->status = -1;
            }
            break;
        }
    }

    // Pass the final result to user space if all is well
    if (0 == event->status){
        bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
    }
    else{
        BPF_PRINTK("ERROR, Unable to finish event... dropping\n");
    }
   
    // Cleanup
    bpf_map_delete_elem(&events_hash, &pid_tid);

    return 0;
}

char _license[] SEC("license") = "GPL";
