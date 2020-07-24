/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <sys/utsname.h>
#include "ebpf_telemetry_config.h"
#include "ebpf_loader/ebpf_telemetry_loader.h"
#include "event_defs.h"
#include <assert.h>

//Notes:
//https://github.com/vmware/p4c-xdp/issues/58
//https://github.com/libbpf/libbpf/commit/9007494e6c3641e82a3e8176b6e0b0fb0e77f683
//https://elinux.org/images/d/dc/Kernel-Analysis-Using-eBPF-Daniel-Thompson-Linaro.pdf
//https://kinvolk.io/blog/2018/02/timing-issues-when-using-bpf-with-virtual-cpus/
//https://blogs.oracle.com/linux/notes-on-bpf-3
//https://elixir.free-electrons.com/linux/latest/source/samples/bpf/bpf_load.c#L339
//https://stackoverflow.com/questions/57628432/ebpf-maps-for-one-element-map-type-and-kernel-user-space-communication

unsigned int total_events = 0;
unsigned int bad_events = 0;
struct utsname uname_data;

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    total_events++;
    event_s *event = (event_s *)data;
    if ( (size > sizeof(event_s)) && // make sure we have enough data
         (event->code_bytes_start == CODE_BYTES) && // garbage check...
         (event->code_bytes_end == CODE_BYTES) && // garbage check...
         (event->version    == VERSION) )     // version check...
    {   
        printf("timestamp=%ld.%ld ", event->bootns / (1000 * 1000 * 1000), event->bootns % (1000 * 1000 * 1000));
        printf("node=%s arch=%s syscall=%lu success=%s exit=%ld ", uname_data.nodename, uname_data.machine, event->syscall_id, (event->return_code >= 0 ? "yes" : "no"), event->return_code);
        printf("a0=%lx a1=%lx a2=%lx a3=%lx ", event->a[0], event->a[1], event->a[2], event->a[3]);
        printf("ppid=%u pid=%u ", event->ppid, event->pid);
        printf("auid=%u uid=%u gid=%u euid=%u suid=%u fsuid=%u egid=%u sgid=%u fsgid=%u ", event->auid, event->uid, event->gid, event->euid, event->suid, event->fsuid, event->egid, event->sgid, event->fsgid);
        printf("tty=%s ses=%u comm=%s exe=%s cwd=%s \n", event->tty, event->ses, event->comm, event->exe, event->pwd);
//        printf("name="/usr/local/sbin/grep" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 path_name=["/usr/local/sbin/grep"] path_nametype=["UNKNOWN"] path_mode=[""] path_ouid=[""] path_ogid=[""] proctitle=/bin/sh /bin/egrep -q "(envID|VxID):.*[1-9]" /proc/self/status containerid=\n", 


        switch(event->syscall_id)
        {    
            case __NR_openat:
            case __NR_open:
            {
                printf(" %s\n", event->data.openat.filename);
                break;
            }

            case __NR_execve:
            {
                // For every null terminated argument in the array of args
                // print them all out together
                int args_count = 0; 
                for (int i = 0; i < event->data.execve.cmdline_size && args_count < event->data.execve.args_count; i++) {
                    
                    char c = event->data.execve.cmdline[i];
                    
                    if (c == '\0') {
                        args_count++;
                        putchar(' ');
                    } 
                    else {
                        putchar(c);
                    }    
                }
                printf("\n");
            }

            case __NR_accept:
            case __NR_connect: 
            {
                char   addr[INET_ADDRSTRLEN] = {0};
                
                if (event->data.socket.addr.sin_family == AF_INET){
                    inet_ntop(AF_INET, &event->data.socket.addr.sin_addr, addr, INET_ADDRSTRLEN);
                    printf(" %s %hu\n", addr, ntohs(event->data.socket.addr.sin_port) );
                }
                else{
                    printf("\n");
                }
                
            }
        }
    } else {
        bad_events++;
        printf("bad data arrived - start: 0x%016lx end: 0x%016lx\n", event->code_bytes_start, event->code_bytes_end);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stdout, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
    //assert(0);
}

void intHandler(int code) {
    
    printf("\nStopping....\n");
    ebpf_telemetry_close_all();

    printf("total events: %d, bad events: %d, ratio = %f\n", total_events, bad_events, (double)bad_events / total_events);
    printf("sizeof(event_s) = %ld\n", sizeof(event_s));
   
    exit(0);
}

int main(int argc, char *argv[])
{
    printf("EBPF_Telemetry v%d.%d\n\n", EBPF_Telemetry_VERSION_MAJOR, EBPF_Telemetry_VERSION_MINOR);

    if (uname(&uname_data) != 0) {
        printf("Failed to get uname\n");
        exit(1);
    }
    
    signal(SIGINT, intHandler);

    printf("Running...\n");

    ebpf_telemetry_start(print_bpf_output, handle_lost_events);

    return 0;
}

