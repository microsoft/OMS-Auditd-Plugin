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

unsigned long total_events = 0;
unsigned long bad_events = 0;
unsigned int num_lost_notifications = 0;
unsigned long num_lost_events = 0;
struct utsname uname_data;

void combine_paths(char *dest, event_path_s *path, char *pwd, bool resolvepath)
{
    char temp[PATH_MAX * 2];
    char abs_path[PATH_MAX];

    if (path->dfd_path[0] == 'A')
        snprintf(temp, PATH_MAX * 2, "%s", path->pathname);
    else if (path->dfd_path[0] == 'C')
        snprintf(temp, PATH_MAX * 2, "%s/%s", pwd, path->pathname);
    else if (path->dfd_path[0] != 'U')
        snprintf(temp, PATH_MAX * 2, "%s/%s", path->dfd_path, path->pathname);
    else
        snprintf(temp, PATH_MAX * 2, "%s", path->pathname);

    // don't resolve real path for symbolic links
    if (!resolvepath || !realpath(temp, dest))
        snprintf(dest, PATH_MAX, "%s", temp);
}

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
        printf("a0=%lx a1=%lx a2=%lx a3=%lx a4=%lx a5=%lx ", event->a[0], event->a[1], event->a[2], event->a[3], event->a[4], event->a[5]);
        printf("ppid=%u pid=%u ", event->ppid, event->pid);
        printf("auid=%u uid=%u gid=%u euid=%u suid=%u fsuid=%u egid=%u sgid=%u fsgid=%u ", event->auid, event->uid, event->gid, event->euid, event->suid, event->fsuid, event->egid, event->sgid, event->fsgid);
        printf("tty=%s ses=%u comm=%s exe=%s exe_mode=%o exe_ouid=%d exe_ogid=%d cwd=%s \n", event->tty, event->ses, event->comm, event->exe, event->exe_mode, event->exe_ouid, event->exe_ogid, event->pwd);
//        printf("name="/usr/local/sbin/grep" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 path_name=["/usr/local/sbin/grep"] path_nametype=["UNKNOWN"] path_mode=[""] path_ouid=[""] path_ogid=[""] proctitle=/bin/sh /bin/egrep -q "(envID|VxID):.*[1-9]" /proc/self/status containerid=\n", 


        switch(event->syscall_id)
        {    
            case __NR_open:
            case __NR_openat:
            case __NR_truncate:
            case __NR_rmdir:
            case __NR_creat:
            case __NR_unlink:
            case __NR_unlinkat:
            case __NR_chmod:
            case __NR_fchmodat:
            case __NR_mknod:
            case __NR_mknodat:
            {
                char abs_path[PATH_MAX];

                combine_paths(abs_path, &event->data.fileop.path1, event->pwd, true);
                printf(" %s\n", abs_path);
                break;
            }

            case __NR_chown:
            case __NR_lchown:
            case __NR_fchownat:
            {
                char abs_path[PATH_MAX];

                combine_paths(abs_path, &event->data.fileop.path1, event->pwd, true);
                printf(" %s  uid: %d, gid: %d\n", abs_path, event->data.fileop.uid, event->data.fileop.gid);
                break;
            }

            case __NR_rename:
            case __NR_renameat:
            case __NR_renameat2:
            case __NR_link:
            case __NR_linkat:
            case __NR_symlink:
            case __NR_symlinkat:
            {
                bool resolvepath = true;
                char abs_path1[PATH_MAX];
                char abs_path2[PATH_MAX];

                combine_paths(abs_path1, &event->data.fileop.path1, event->pwd, resolvepath);
                combine_paths(abs_path2, &event->data.fileop.path2, event->pwd, resolvepath);
                printf(" %s   %s\n", abs_path1, abs_path2);
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
    num_lost_notifications++;
    num_lost_events += lost_cnt;
    //assert(0);
}

void intHandler(int code) {
    
    printf("\nStopping....\n");
    ebpf_telemetry_close_all();

    printf("total events: %ld, bad events: %ld, ratio = %f\n", total_events, bad_events, (double)bad_events / total_events);
    printf("lost events: %ld, in %d notifications\n", num_lost_events, num_lost_notifications);
   
    exit(0);
}

int main(int argc, char *argv[])
{
    printf("EBPF_Telemetry v%d.%d\n\n", EBPF_Telemetry_VERSION_MAJOR, EBPF_Telemetry_VERSION_MINOR);

    if (sizeof(event_s) > MAX_EVENT_SIZE) {
        printf("sizeof(event_s) == %ld > %d!\n", sizeof(event_s), MAX_EVENT_SIZE);
        exit(1);
    }

    if (uname(&uname_data) != 0) {
        printf("Failed to get uname\n");
        exit(1);
    }
    
    signal(SIGINT, intHandler);

    printf("Running...\n");

    ebpf_telemetry_start(print_bpf_output, handle_lost_events);

    return 0;
}

