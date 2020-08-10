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

// generic sys_enter argument struct for traditional tracepoints. Note that
// some or all of the 'a' array can't be derefenced depending on how many
// arguments a syscall expects; attempts to do so will cause the verifier
// to reject it.
struct tracepoint__syscalls__sys_enter {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    __u64 a[6];
};

// all sys_exit arguments are the same for traditional tracepoints.
struct tracepoint__syscalls__sys_exit {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
     long ret;
};


// check if this is an event to process
__attribute__((always_inline))
static inline event_s *sys_enter_check_and_init(u32 syscall, u64 pid_tid)
{
    u32 cpu_id = bpf_get_smp_processor_id();
    event_s *event = NULL;
    u32 config_id = 0;
    config_s *config;
    u32 userland_pid = 0;
    char syscall_flags = 0;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return NULL;

    userland_pid = config->userland_pid;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == userland_pid)
        return NULL;

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &cpu_id);
    if (!event)
        return NULL;

    // initialise the event
    init_event(event, syscall, pid_tid >> 32);

    return event;
}

// complete and store event
__attribute__((always_inline))
static inline void sys_enter_complete_and_store(event_s *event, u32 syscall, u64 pid_tid)
{
    // check syscall conditions
    if (check_event_filters(event->a, syscall)) {
        // store event in the hash
        long ret = 0;
        if ((ret = bpf_map_update_elem(&events_hash, &pid_tid, event, BPF_ANY)) != 0){
            BPF_PRINTK("ERROR, HASHMAP: failed to update event map, %ld\n", ret);
        }
    }
}

// sys_enter for 0 arguments
SEC("tracepoint/syscalls/sys_enter0")
__attribute__((flatten))
int sys_enter0(struct tracepoint__syscalls__sys_enter *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    u32 syscall = args->__syscall_nr;

    event = sys_enter_check_and_init(syscall, pid_tid);
    if (!event)
        return 0;

    sys_enter_complete_and_store(event, syscall, pid_tid);
    return 0;
}

// sys_enter for 1 argument
SEC("tracepoint/syscalls/sys_enter1")
__attribute__((flatten))
int sys_enter1(struct tracepoint__syscalls__sys_enter *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    u32 syscall = args->__syscall_nr;

    event = sys_enter_check_and_init(syscall, pid_tid);
    if (!event)
        return 0;

    event->a[0] = args->a[0];

    sys_enter_complete_and_store(event, syscall, pid_tid);
    return 0;
}

// sys_enter for 2 arguments
SEC("tracepoint/syscalls/sys_enter2")
__attribute__((flatten))
int sys_enter2(struct tracepoint__syscalls__sys_enter *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    u32 syscall = args->__syscall_nr;

    event = sys_enter_check_and_init(syscall, pid_tid);
    if (!event)
        return 0;

    event->a[0] = args->a[0];
    event->a[1] = args->a[1];

    sys_enter_complete_and_store(event, syscall, pid_tid);
    return 0;
}

// sys_enter for 3 arguments
SEC("tracepoint/syscalls/sys_enter3")
__attribute__((flatten))
int sys_enter3(struct tracepoint__syscalls__sys_enter *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    u32 syscall = args->__syscall_nr;

    event = sys_enter_check_and_init(syscall, pid_tid);
    if (!event)
        return 0;

    event->a[0] = args->a[0];
    event->a[1] = args->a[1];
    event->a[2] = args->a[2];

    sys_enter_complete_and_store(event, syscall, pid_tid);
    return 0;
}

// sys_enter for 4 arguments
SEC("tracepoint/syscalls/sys_enter4")
__attribute__((flatten))
int sys_enter4(struct tracepoint__syscalls__sys_enter *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    u32 syscall = args->__syscall_nr;

    event = sys_enter_check_and_init(syscall, pid_tid);
    if (!event)
        return 0;

    event->a[0] = args->a[0];
    event->a[1] = args->a[1];
    event->a[2] = args->a[2];
    event->a[3] = args->a[3];

    sys_enter_complete_and_store(event, syscall, pid_tid);
    return 0;
}

// sys_enter for 5 arguments
SEC("tracepoint/syscalls/sys_enter5")
__attribute__((flatten))
int sys_enter5(struct tracepoint__syscalls__sys_enter *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    u32 syscall = args->__syscall_nr;

    event = sys_enter_check_and_init(syscall, pid_tid);
    if (!event)
        return 0;

    event->a[0] = args->a[0];
    event->a[1] = args->a[1];
    event->a[2] = args->a[2];
    event->a[3] = args->a[3];
    event->a[4] = args->a[4];

    sys_enter_complete_and_store(event, syscall, pid_tid);
    return 0;
}

// sys_enter for 6 arguments
SEC("tracepoint/syscalls/sys_enter6")
__attribute__((flatten))
int sys_enter6(struct tracepoint__syscalls__sys_enter *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    event_s *event = NULL;
    u32 syscall = args->__syscall_nr;

    event = sys_enter_check_and_init(syscall, pid_tid);
    if (!event)
        return 0;

    event->a[0] = args->a[0];
    event->a[1] = args->a[1];
    event->a[2] = args->a[2];
    event->a[3] = args->a[3];
    event->a[4] = args->a[4];
    event->a[5] = args->a[5];

    sys_enter_complete_and_store(event, syscall, pid_tid);
    return 0;
}

// sys_exit
SEC("tracepoint/syscalls/sys_exit")
__attribute__((flatten))
int sys_exit(struct tracepoint__syscalls__sys_exit *args)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 cpu_id = bpf_get_smp_processor_id();
    event_s *event = NULL;
    u32 config_id = 0;
    config_s *config;
    u32 userland_pid = 0;
    void *task;
    void *cred;
    char notty[] = "(none)";
    char *temppath = NULL;
    bool send_event = true;
    
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
    if (!task)
        event->status |= STATUS_NOTASK;
    else
        set_event_exit_info(event, task, config);

    // set the return code
    event->return_code = args->ret;

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
                int j = arg_end - arg_start;

                if (bpf_probe_read(&event->execve.cmdline, j & (CMDLINE_MAX_LEN - 1), (void *)arg_start) < 0) {
                    BPF_PRINTK("ERROR, execve(%d), failed to read cmdline from mm\n", event->syscall_id);
                    event->status |= STATUS_VALUE;
                }
                // add nul terminator just in case
                event->execve.cmdline[CMDLINE_MAX_LEN - 1] = 0x00;
                event->execve.cmdline[j & (CMDLINE_MAX_LEN - 1)] = 0x00;
                event->execve.cmdline_size = j;
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
        }
    }

    // Pass the final result to user space if all is well or it satisfies config
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
        bpf_perf_event_output(args, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
    } else {
        BPF_PRINTK("ERROR, Unable to finish event... dropping\n");
    }
   
    // Cleanup
    bpf_map_delete_elem(&events_hash, &pid_tid);

    return 0;
}

char _license[] SEC("license") = "GPL";

