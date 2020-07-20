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

#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/string.h>
#include <bpf_tracing.h>
#include "event_defs.h"

struct bpf_map_def SEC("maps") event_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 512, // 512 CPUs - this needs to accommodate most systems so make this big
                        // Also, as this map is quite small (8 bytes per entry), we could potentially
                        // make this even bigger and it woulnd't cost much
};

// create a map to hold the event as we build it - too big for stack
struct bpf_map_def SEC("maps") event_storage_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(event_s),
    .max_entries = 512, // same as max_entries for above event_map
};

// create a hash to hold events between sys_enter and sys_exit
struct bpf_map_def SEC("maps") events_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(event_s),
    .max_entries = 10240,
};

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 map_id = 0;
    event_s *event = NULL;

    // bail early for syscalls we aren't interested in
    unsigned long long syscall = ctx->args[1];
    if ( (syscall != __NR_open)    &&
         (syscall != __NR_openat) )
        return 0;

    map_id = bpf_get_smp_processor_id();

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (!event)
        return 0;

    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end = CODE_BYTES;
    event->version = VERSION;
    event->syscall_id = ctx->args[1];
    event->pid = pid_tid >> 32;

    // store event in the hash
    bpf_map_update_elem(&events_hash, &pid_tid, event, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 map_id = 0;
    event_s *event = NULL;
    volatile struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // retrieve map storage for event
    // this was mostly completed on the preceding sys_enter
    // if the pid_tid is in our map then we must have stored it
    event = bpf_map_lookup_elem(&events_hash, &pid_tid);
    if (!event)
        // otherwise bail
        return 0;

    bpf_probe_read(&event->return_code, sizeof(s64), (void *)&PT_REGS_RC(regs));

    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
    bpf_map_delete_elem(&events_hash, &pid_tid);

    return 0;
}

char _license[] SEC("license") = "GPL";
