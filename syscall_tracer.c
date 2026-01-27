//ebpf program
//runs in kernel

#include <uapi/linux/ptrace.h>
#include <linux/sched.h> 

struct syscall_evt { //event we send to user space (mimic our SysCall dataclass)
    u32 pid;  
    u64 id;
    u64 args[6]; //raw args
};

BPF_PERF_OUTPUT(events); //perf buffer
//perf buffer is efficient way to transfer huge amoutns of events 
//uses shared memory between kernel and process to quickly let it write and let us read 

TRACEPOINT_PROBE(raw_syscalls, sys_enter) // tracepoint is just the callback for when something happens in the kernal (sys_enter is the event)
{
    struct syscall_evt evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid = pid_tgid >> 32; //upper 32 bits are the pid https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
    evt.id  = args->id; //syscall id 

    #pragma unroll //unroll loop like inline just for ebpf verifier
    for (int i = 0; i < 6; i++) {
        evt.args[i] = args->args[i];
    }

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}