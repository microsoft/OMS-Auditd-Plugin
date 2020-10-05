/*
    EBPF Perf Output POC

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

#include <stdint.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/fcntl.h>
#include <sys/socket.h>
#include <linux/string.h>
#include <asm/unistd_64.h>
#include <asm/ptrace.h>
#include "event_defs.h"

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

// debug tracing can be found using:
// #cat /sys/kernel/debug/tracing/trace_pipe

#ifdef DEBUG_K
#define BPF_PRINTK( format, ... ) \
    char fmt[] = format; \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__ );
#else
#define BPF_PRINTK ((void)0);
#endif

// missing stddef.h defines
#define NULL ((void *)0)
typedef int bool;
#define true 1
#define false 0


struct bpf_map_def SEC("maps") event_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(uint32_t),
	.max_entries = 512, // 512 CPUs - this needs to accommodate most systems so make this big
                        // Also, as this map is quite small (8 bytes per entry), we could potentially
                        // make this even bigger and it woulnd't cost much
};

// create a hash to hold events between sys_enter and sys_exit
struct bpf_map_def SEC("maps") events_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(event_s),
    .max_entries = 10240,
};

struct tracepoint__syscalls__sys_enter_open {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    const char *filename;
    __u64 flags;
    __u64 mode;
};

struct tracepoint__syscalls__sys_exit_open {
    __u64 pad;
    __u32 __syscall_nr;
    __u32 pad2;
    __u64 ret;
};

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct tracepoint__syscalls__sys_enter_open *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint32_t map_id = 0;
    event_s event;

    map_id = bpf_get_smp_processor_id();

    __builtin_memset(&event, 0, sizeof(event));

    event.code_bytes_start = CODE_BYTES;
    event.code_bytes_end = CODE_BYTES;
    event.version = VERSION;
    event.syscall_id = args->__syscall_nr;
    event.pid = pid_tid >> 32;
    event.path_ptr = (void *)args->filename;

    // store event in the hash
    bpf_map_update_elem(&events_hash, &pid_tid, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int sys_exit_open(struct tracepoint__syscalls__sys_exit_open *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint32_t map_id = 0;
    event_s *event = NULL;
    event_s e;

    // retrieve map storage for event
    // this was mostly completed on the preceding sys_enter
    // if the pid_tid is in our map then we must have stored it
    event = bpf_map_lookup_elem(&events_hash, &pid_tid);
    if (!event)
        // otherwise bail
        return 0;

    __builtin_memset(&e, 0, sizeof(e));

    e.code_bytes_start = event->code_bytes_start;
    e.code_bytes_end = event->code_bytes_end;
    e.version = event->version;
    e.syscall_id = event->syscall_id;
    e.pid = event->pid;
    e.return_code = args->ret;
    bpf_probe_read_str(e.path, sizeof(e.path), event->path_ptr);

    bpf_perf_event_output(args, &event_map, BPF_F_CURRENT_CPU, &e, sizeof(event_s));
    bpf_map_delete_elem(&events_hash, &pid_tid);

    return 0;
}

char _license[] SEC("license") = "GPL";
