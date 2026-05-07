//ebpf program
//runs in kernel

#include <uapi/linux/ptrace.h>
#include <linux/sched.h> 

struct syscall_evt { //event we send to user space (mimic our SysCall dataclass)
    u32 pid;  
    u64 id;
    u64 args[6]; //raw args
    char path[256];
};

BPF_PERF_OUTPUT(events); //perf buffer

TRACEPOINT_PROBE(raw_syscalls, sys_enter) { // setup tracepoint callback
    struct syscall_evt evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid = pid_tgid >> 32; //upper 32 bits are the pid https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
    evt.id  = args->id; //syscall id 

    // it gets mad about pointer arithmetic on ctx even with pragma unroll
    evt.args[0] = args->args[0];
    evt.args[1] = args->args[1];
    evt.args[2] = args->args[2];
    evt.args[3] = args->args[3];
    evt.args[4] = args->args[4];
    evt.args[5] = args->args[5];

    // deref path 
    // use else if so only one fires and verifier stays happy
    // only on specific events
    if (args->id == 59 || args->id == 2 || args->id == 4 ||
        args->id == 6 || args->id == 87 || args->id == 80 ||
        args->id == 21 || args->id == 133 || args->id == 76)
        bpf_probe_read_user_str(evt.path, sizeof(evt.path), (void *)args->args[0]);
    else if (args->id == 257 || args->id == 258)
        bpf_probe_read_user_str(evt.path, sizeof(evt.path), (void *)args->args[1]);
    else if (args->id == 82)
        bpf_probe_read_user_str(evt.path, sizeof(evt.path), (void *)args->args[0]);


    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}