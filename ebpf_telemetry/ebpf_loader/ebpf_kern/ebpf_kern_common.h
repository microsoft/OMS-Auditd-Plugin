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

struct bpf_map_def SEC("maps") event_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, //BPF_MAP_TYPE_HASH doesnt stack....
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 512, // 512 CPUs - this needs to accommodate most systems as this is CO:RE
                        // Also, as this map is quite small (8 bytes per entry), we could potentially
                        // make this event bigger and it woulnd't cost much
};
/* note: the alternative would be to transmit the number of CPUs from userland in a shared map and then
   dynamically build/size this map accordingly.  The trade off of potentially wasing <=4K on this map
   and limiting ourselves to systems with <= 512 CPUs seems fair.
*/

// create a map to hold the event as we build it - too big for stack
struct bpf_map_def SEC("maps") event_storage_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(event_s),
    .max_entries = 1,
};

// create a hash to hold events between sys_enter and sys_exit
struct bpf_map_def SEC("maps") events_hash_single = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct sockaddr_in *),
    .max_entries = 10240,
};

struct bpf_map_def SEC("maps") events_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(event_s),
    .max_entries = 10240,
};

// create a map to hold the configuration
struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(config_s),
    .max_entries = 1,
};

// create a map to hold a temporary filepath as it's being constructed
struct bpf_map_def SEC("maps") filepath_temp = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = PATH_MAX * 2,
    .max_entries = 1,
};

// create a map to hold the temporary d_names as they're read in
struct bpf_map_def SEC("maps") d_entry_temp = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = 256,
    .max_entries = 128,
};

// create a map to hold a temporary d_name as it's being constructed
struct bpf_map_def SEC("maps") d_temp = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = PATH_MAX,
    .max_entries = 1,
};

#endif
