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

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format:
struct tracepoint__syscalls__sys_enter_openat {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    __u64 dfd;
    const char *filename;
    __u64 flags;
    __u64 mode;
};

struct tracepoint__syscalls__sys_enter_open {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    const char *filename;
    __u64 flags;
    __u64 mode;
};

struct tracepoint__syscalls__sys_enter_execve {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    const char *filename;
    const char *const * argv; 
    const char *const * envp; 
};

struct tracepoint__syscalls__sys_enter_connect {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    int fd;
    struct sockaddr * uservaddr;
    int addrlen;   
};

struct tracepoint__syscalls__sys_enter_accept {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    int fd;
    struct sockaddr * upeer_sockaddr;
    int * upeer_addrlen;   
};

struct tracepoint__syscalls__sys_exit {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
     long ret;
};

SEC("tracepoint/syscalls/sys_enter_open")
int bpf_myprog(struct tracepoint__syscalls__sys_enter_open *args)
{
    volatile const char *pathname;
    event_s *event = NULL;
    u32 map_id = 0;

    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (!event)
        return 0;

    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end = CODE_BYTES;
    event->version    = VERSION;
    event->pid        = bpf_get_current_pid_tgid();
    event->syscall_id = args->__syscall_nr;

    bpf_probe_read(&pathname, sizeof(pathname), (void *)&args->filename); //read addr into char*
    bpf_probe_read_str(event->data.openat.filename, sizeof(event->data.openat.filename), (void *)pathname); // read str from char*

    bpf_perf_event_output(args, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_myprog2(struct tracepoint__syscalls__sys_enter_execve *args)
{
    u32 pid_tid = bpf_get_current_pid_tgid();
    u32 map_id = 0;
    event_s *event = NULL;
    u32 config_id = 0;
    config_s *config;
    u32 userland_pid = 0;
    
    volatile const char *filename;
    volatile const char *argp;
    const char **argv;
    unsigned int ret;
    
    //retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (!event)
        return 0;

    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end = CODE_BYTES;
    event->version    = VERSION;
    event->pid        = pid_tid;
    event->syscall_id = args->__syscall_nr;

    // get filename 
    bpf_probe_read(&filename, sizeof(filename), (void *)&args->filename); //read addr into char*
    bpf_probe_read_str(event->data.execve.exe, sizeof(event->data.execve.exe), (void *)filename); // read str from char*
    
    bpf_probe_read(&argv, sizeof(argv), (void *)&args->argv); // read argv[]

    event->data.execve.args_count = 0;
    event->data.execve.args_size  = 0;
    #pragma unroll // no loops in eBPF, but need to get all args....
    for (int i = 1; i < TOTAL_MAX_ARGS; i++) {
        bpf_probe_read(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;

        // This is important or the verifier will reject without a bounds check
        if (event->data.execve.args_size > ARGSIZE )
            break;
        
        ret = bpf_probe_read_str(&event->data.execve.cmdline[event->data.execve.args_size], ARGSIZE, (void*) argp);
        if (ret > ARGSIZE)
            break;

        if ( ret > 0 ){ 
            event->data.execve.args_count++;
            event->data.execve.args_size += ret;
        }
    }
    
    bpf_perf_event_output(args, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
        
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int bpf_myprog3(struct tracepoint__syscalls__sys_enter_connect *args)
{
    event_s *event = NULL;
    struct sockaddr *addr;
    u32 map_id = 0;

    //retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (!event)
        return 0;

    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end = CODE_BYTES;
    event->version    = VERSION;
    event->pid        = bpf_get_current_pid_tgid();
    event->syscall_id = args->__syscall_nr;

    bpf_probe_read(&addr, sizeof(addr), &args->uservaddr);
    bpf_probe_read(&event->data.socket.addr, sizeof(event->data.socket.addr), (void *)addr);

    bpf_perf_event_output(args, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int bpf_myprog4(struct tracepoint__syscalls__sys_enter_accept *args)
{
    event_s *event = NULL;
    struct sockaddr_in *addr;
    u32 map_id = 0;
    u32 key = bpf_get_current_pid_tgid();
    u32 value = 1;

    //retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (!event)
        return 0;

    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end = CODE_BYTES;
    event->version    = VERSION;
    event->pid        = key;
    event->syscall_id = args->__syscall_nr;

    bpf_probe_read(&addr, sizeof(struct sockaddr_in *), (void *)&args->upeer_sockaddr);    
    bpf_map_update_elem(&events_hash_single, &key, &addr, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int bpf_myprog5(struct tracepoint__syscalls__sys_exit *args)
{
    event_s *event = NULL;
    struct sockaddr_in *addr = NULL;
    u32 key = bpf_get_current_pid_tgid();
    u32 map_id = 0;

    //retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (!event)
        return 0;

    addr = bpf_map_lookup_elem(&events_hash_single, &key);
    if (!addr)
        return 0;

    bpf_probe_read(&event->data.socket.addrp, 
                   sizeof(event->data.socket.addr), 
                   (void *)addr);
    bpf_probe_read(&event->data.socket.addr, 
                    sizeof(event->data.socket.addr), 
                   (void *)event->data.socket.addrp);

    if (!event->data.socket.addrp)
        return 0;

    char fmt[] = "ACCEPT EXIT: %u %lx\n";
    bpf_trace_printk(fmt, sizeof(fmt), key, event->data.socket.addrp);

    bpf_perf_event_output(args, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
    
    return 0;
}

char _license[] SEC("license") = "GPL";
