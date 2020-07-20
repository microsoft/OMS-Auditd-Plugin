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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/compiler_types.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <libbpf.h>
#include <sys/resource.h>
#include <bpf.h>
#include <perf-sys.h>
#include <libbpf.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <types.h>
#include <sys/utsname.h>
#include "event_defs.h"

#define MAP_PAGE_SIZE 1024

static int    event_map_fd          = 0;
static struct bpf_object  *bpf_obj  = NULL;

static struct bpf_program *bpf_sys_enter = NULL;
static struct bpf_program *bpf_sys_exit  = NULL;

static struct bpf_link    *bpf_sys_enter_link = NULL;
static struct bpf_link    *bpf_sys_exit_link  = NULL;

unsigned int total_events = 0;
unsigned int bad_events = 0;
void *last_ptr = NULL;

static void bpf_close_all(){
    
    bpf_link__destroy(bpf_sys_enter_link);
    bpf_link__destroy(bpf_sys_exit_link);

    bpf_object__close(bpf_obj);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    total_events ++;
    event_s *event = (event_s *)data;
    if ( (size > sizeof(event_s)) && // make sure we have enough data
         (event->code_bytes_start == CODE_BYTES) && // garbage check...
         (event->code_bytes_end == CODE_BYTES) && // garbage check...
         (event->version    == VERSION) )     // version check...
    {   
        printf("PID:%u SYS:%llu RET:%lld ptr=%p", event->pid, event->syscall_id, event->return_code, data);
    } else {
        bad_events++;
        printf("bad data arrived: ptr=%p, expected size=%ld, actual size=%d", data, sizeof(event_s), size);
        if (size > sizeof(event_s))
            printf(", start=0x%016lx, end=0x%016lx", event->code_bytes_start, event->code_bytes_end);
    }
    if (last_ptr)
        printf(", diff=0x%08lx (%ld)\n", data - last_ptr, data - last_ptr);
    else
        printf("\n");
    last_ptr = data;

}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
    //assert(0);
}

void intHandler(int code) {
    
    printf("\nStopping....\n");
    bpf_close_all();
    printf("total events: %d, bad events: %d (%f)\n", total_events, bad_events, (double)bad_events / total_events);
   
    exit(0);
}

int main(int ac, char *argv[])
{
    printf("EBPF Perf Output POC to demonstrate event corruption\n");
    printf("Current size of event sample: %ld. Change this in event_defs.h to see problem of going beyond 64K\n", sizeof(event_s));
    
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    char filename[256] = "kern.o";

    setrlimit(RLIMIT_MEMLOCK, &lim);

    bpf_obj = bpf_object__open(filename);
    if (libbpf_get_error(bpf_obj)) {
        printf("ERROR: failed to open prog: '%s'\n", strerror(errno));
        return 1;
    }

    if ( 
          ( NULL != ( bpf_sys_enter = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/sys_enter")))  &&
          ( NULL != ( bpf_sys_exit  = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/sys_exit")))   )
    {
        bpf_program__set_type(bpf_sys_enter, BPF_PROG_TYPE_RAW_TRACEPOINT);
        bpf_program__set_type(bpf_sys_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
        return 1;
    }

    if (bpf_object__load(bpf_obj)) {
        printf("ERROR: failed to load prog: '%s'\n", strerror(errno));
        return 1;
    }

    event_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "event_map");
    if ( 0 >= event_map_fd){
        printf("ERROR: failed to load event_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_sys_enter_link = bpf_program__attach_raw_tracepoint(bpf_sys_enter, "sys_enter");
    bpf_sys_exit_link = bpf_program__attach_raw_tracepoint(bpf_sys_exit, "sys_exit");
        
    if ( (libbpf_get_error(bpf_sys_enter_link)) || 
         (libbpf_get_error(bpf_sys_exit_link))  )
        return 2;

    // from Kernel 5.7.1 ex: trace_output_user.c 
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb;
    int ret;

    pb_opts.sample_cb = print_bpf_output;
    pb_opts.lost_cb = handle_lost_events;
    pb_opts.ctx     = NULL;
    pb = perf_buffer__new(event_map_fd, MAP_PAGE_SIZE, &pb_opts); // param 2 is page_cnt == number of pages to mmap.
    ret = libbpf_get_error(pb);
    if (ret) {
        printf("ERROR: failed to setup perf_buffer: %d\n", ret);
        return 1;
    }

    signal(SIGINT, intHandler);

    printf("Running...\n");

    while ((ret = perf_buffer__poll(pb, 1000)) >= 0 ) {
        // go forever
    }

    bpf_close_all();

    return 0;
}

