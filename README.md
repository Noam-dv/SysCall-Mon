## logging ideas:
First main issue:
Threads conflicting - tkinter, then pyside6 all use a main thread and therefore i had DEBUG errors due to library specific threading needed

second issue:
```
[DEBUG] imported etw successfully
monitoring: [(11452, 'Notepad.exe')]
[DEBUG] __init__ with pids: [11452]
[DEBUG] tracking PID 11452 Notepad.exe
[DEBUG] started
[DEBUG] starting thread
[DEBUG] _run_trace() entered on thread
[DEBUG] loaded 2 providers
[DEBUG] creating etw instance
[DEBUG] etw instance created
[DEBUG] calling etw.start()
[DEBUG] thread started
[DEBUG] etw.start() stopped
[DEBUG] _run_trace() exiting
```

as you can see above, etw instance automatically closes.
this could be due to several reasons, but i think in my case its conflicting session names

after adding dynamic session name swe get the same result
im thinking we might be using outdated pywintrace usage ( i took code from example uses)

progress: 
after using DNS provider whcih is a user mode provider
events did fire so we know its not hte logic its more so permission issues or provider issues?
maybe im using dated providers
many network events (tcp ip events) arent working supposedly cuz i have expressvpn installed but ive never used it lol
??
vpn might be an issue i will add a warning if you enable network events 

looks like i ran into a real OS boundary
etw is simply not gonna be enough for system call tracing 
procmon uses private kernal tracing and is windows signed

after checking i can see i am elevated and have real admin perms 
idk why kernel providers are blocked

this project no longer seems realistic
one kernal tracer can be alive at once, and my anti virus is using it 
in practice:
only one kernel tracing session can be active ,windows already uses it, defender already owns it
vpn drivers hook into it
networking stack hooks into it
edr hooks into it
you cannot “share” it.

Starting from scratch: on ubuntu linux
linux has much less OS constraints, and has stuff such as strace that show that this is possible
i will move this project from linux, adn start from scratch (Even UI)
first new linux commit will be the simple UI with process data (icons, pids, mem and other shit maybe)

## LINUX COMMIT #1
made basic UI, used psutil to make helper functions
list basic processes, try to get icon (logic better in the future)
moved to PyQt6 heard it might be better ?
made some new UI 
tried to organize my code slightly better and document it a bit more

## LINUX COMMIT #2 AND #3
added simple sorting 
implemented more sturdy icon fetching logic cuz that really pissed me off that it was spamming the default icon
next we will start working on the systracer logic 
hopefully its easier on linux

## Sys call tracing starting
i first thought of using ptrace, but after reading a bit more i saw that a mor manual approach would be to use eBPF 
ill read about it a bit now

after reading i understand like in windows etw there will be TONS of clutter of system calls 
we will filter by type, similar to how i think procmon does it 
FILE IO, NETWORK, PROCESS categorys will be shown
rest will be ignored
maybe ill make a long long long list of all calls and let u enable basd on presets and enable manually? we will see 

todo: read more about ebpf understand better how it wokrs

i have written the first demo of systracer, it creates a new ebpf program for each pid we shadow ( maybe a better way tro do this later)
it will log the system calls of that pid, read them in real time and using the data we can parse (Which is kind of complicated to do) we trigger the event from the window to add to the screen

install with ```sudo apt install -y bpfcc-tools python3-bpfcc```
run with ```sudo -E python3 main.py```
-E keeps the environment making sure u dont need  to downlaod all ur pip packages all over again

after extendning this it works! i tried to trace python and got about a billion write syscalls displayed
### log:
```
noam@noam-VirtualBox:~/sysmon$ sudo -E python3 main.py\n
....
tracing pid 6978
Possibly lost 226 samples
...
Possibly lost 315 samples
QBasicTimer::start: QBasicTimer can only be used with threads started with QThread
Segmentation fault
```
theres so many calls that perf buffer overflows
i guess this is normal ill try to possibly filter systemcalls further
also we must use a qthread to work with the ui cuz we got a crash


### LAG
we will fix the lag
main issues are 
syscall rate (so fucking many)
textedit.append (expesnive)
50ms timer (drain the queue and add hundreds of lines)

we will rate limit, and batch ui updates

## working system calls
finally after so much work system calls log 
with litterally no detail tho so we'll work on that
lag still exists
we will haveto work on that

## categorization

### FILE_IO
actual data read write to files

### FS_META
filesystem structure and permissions not data itself but still important

### PROCESS
process creation exec exit signals basically program control

### MEMORY
virtual memory management mapping protection and heap stuff

### IPC
local process communication looks like network but isnt ( i dont really understand this one )

### NETWORK
networking to other machines

### EVENTS
waiting and notification syscalls (epoll poll type stuff)

### TIME
sleeping timers and clocks

### SECURITY
things that change authority

### OTHER
other

## anomaly detection
now the system tracer is kind of done (not really but for now its good to start on the main thing)

i would really like to implement anomaly detection

suspicious rate - 0-10

first we have to define what an anomaly is (brackets are how suspicious this is):
- sudden spikes in syscalls (5)
- sudden spike in a specific call , like a lot of the same call (6)
- syscall order that does not happen in base line (3 could happend cuz of dropped syscalls)
- process suddenly shifts from file heavy to net heavy (5)
- new behavior (brand new syscall that was never seen in this process) (3)

After reading a bit more i like the *statistical behavior modeling* approach much more
i will read about it more, but implement it later once i fix the lag 
cuz it still lags a LOT
