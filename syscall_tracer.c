//ebpf program
//runs in kernel

//HEAVILY commented just to help me remember too cuz tihs looks way more complex than it is


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

TRACEPOINT_PROBE(raw_syscalls, sys_enter) // tracepoint is just the callback for when something happens in the kernal
//ebpf just so happens to have sys_enter callback which lets us have an event callback for each syscall
{
    struct syscall_evt evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid = pid_tgid >> 32; //upper 32 bits are the pid
    evt.id  = args->id; //syscall id 
    //later we map the id to the name in syscall_helpers

    #pragma unroll //unroll loop like inline just for ebpf verifier
    for (int i = 0; i < 6; i++) {
        evt.args[i] = args->args[i];
    }

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}