//ebpf program
//runs in kernel
#include <uapi/linux/ptrace.h>
#include <linux/sched.h> 

struct syscall_evt { //event we send to user space
    u32 pid; //kinda mimic our syscall dataclass
    u64 id;
    u64 args[6]; //pass raw syscall args now and we map them later in syscall helpers
};

BPF_PERF_OUTPUT(events); //perf buffer
//perf buffer is efficient way to transfer huge amoutns of events 
//uses shared memory between kernel and process to quickly let it write and let us read 

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    struct syscall_evt evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid = pid_tgid >> 32; //upper 32 bits are the pid
    evt.id  = args->id; //syscall id 
    //later we map the id to the name in syscall_helpers

    #pragma unroll //raw syscall args
    for (int i = 0; i < 6; i++) {
        evt.args[i] = args->args[i];
    }

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}