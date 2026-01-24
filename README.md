First main issue:
Threads conflicting - tkinter, then pyside6 all use a main thread and therefore i had DEBUG errors due to library specific threading needed

second issue:
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

as you can see above, etw instance automatically closes.
this could be due to several reasons, but i think in my case its conflicting session names

after adding dynamic session name swe get the same result
im thinking we might be using outdated pywintrace usage ( i took code from example uses)

PROGRESS !!
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