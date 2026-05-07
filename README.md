## demo

![](showcase.gif)

# sysmon

a linux process monitor with real time syscall tracing and anomaly detection built with python and ebpf

---

## what it is

sysmon lets you pick a running process and watch every system call it makes in real time, the calls get categorized by type so you can see at a glance whether a process is doing file io, network activity, memory operations, etc

on top of that it runs a zscore based anomaly detector that builds a baseline of what normal looks like for the process and flags anything that deviates from it

the ui is built with pyqt6

---

## why linux

the original version of this was attempted on windows using etw (event tracing for windows) but windows only allows one kernel tracing session at a time and that slot is already taken by defender and other system components so real syscall tracing from user mode is simply not possible without a signed kernel driver

linux has strace and ebpf which are proper accessible interfaces for this kind of thing, no signing required

---

## how it works

### syscall tracing

sysmon uses ebpf via bcc to attach a tracepoint to each process you want to monitor, when a syscall fires the ebpf program writes event data into a perf ring buffer in kernel space, bcc maps that memory into the python process and we read events from it in a background thread

each event gets parsed using a syscall signature table that maps syscall numbers to argument names so you see something like `openat(dirfd=AT_FDCWD, path=/etc/hosts, flags=O_RDONLY)` instead of raw numbers (user strings dont get drefed so this is not entirely true)

### categories

every syscall gets bucketed into one of these

- FILE_IO - actual data read and write to files
- FS_META - filesystem structure like stat chmod rename
- PROCESS - exec fork exit signals
- MEMORY - mmap mprotect brk heap management
- IPC - pipes sockets between local processes
- NETWORK - connections to other machines
- EVENTS - epoll poll select waiting
- TIME - sleep nanosleep clock
- SECURITY - setuid capabilities privilege changes

### anomaly detection

the detector uses a rolling zscore model per syscall category, it tracks the rate of each category over time and computes a mean and standard deviation from recent history, when the current rate deviates significantly from the baseline a suspicion score from 0 to 10 gets assigned

things that raise the score

- sudden spike in total syscall volume
- spike in one specific call repeated many times
- process shifts from one dominant category to another like file heavy suddenly going network heavy
- a syscall category appears that has never been seen before for this process

---

## install

you need to be on linux with python3 and bcc installed

```bash
sudo apt install -y bpfcc-tools python3-bpfcc
pip install pyqt6 psutil
```

clone the repo

```bash
git clone https://github.com/yourname/sysmon
cd sysmon
```

---

## usage

has to run as root for ebpf access, use -E to keep your pip packages available

```bash
sudo -E python3 main.py
```

pick a process from the list, click trace, watch the events come in

---

## notes

- rate limiting and batched ui updates are used to handle high syscall volume, some samples may still be dropped under extreme load which is normal
- expressvpn or other vpn drivers can interfere with network event visibility
- tested on ubuntu with kernel 5.15+