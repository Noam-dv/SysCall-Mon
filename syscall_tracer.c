//ebpf program
//runs in kernel
#include <uapi/linux/ptrace.h>
#include <linux/sched.h> 
struct syscall_evt { //event we send to user space
    u32 pid; //kinda mimic our syscall dataclass
    u64 id;
};

BPF_PERF_OUTPUT(events); //perf buffer
RAW_TRACEPOINT_PROBE(sys_enter) //raw tracepoint avoids struct mismatch shit
{
    struct syscall_evt evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid = pid_tgid >> 32; //upper 32 bits are the pid
    //stack overflow save
    evt.id  = ctx->args[1]; //syscall id (x86_64)
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}