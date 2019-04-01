# -*- coding: utf-8 -*-

from bu6pwn.core import *

class DLResolve(object):
    def __init__(self, arch, addr_dynsym, addr_dynstr, addr_relplt, addr_version=None):
        if arch not in ['x86', 'x86_64' 'amd64']:
            warn("DLResolve : Architectire '%s' is not defined" % arch)
            info("DLResolve : Set arch 'x86'")
            arch = "x86"
        self.reloc_offset       = {}
        self.funcaddr           = {}
        self.arch               = arch
        self.addr_dynsym        = addr_dynsym
        self.addr_dynstr        = addr_dynstr
        self.addr_relplt        = addr_relplt
        self.addr_version       = addr_version

    def set_funcaddr(self, addr, dynstr):
        info("Adding function @ {:#x} -> {}".format(addr, dynstr))
        self.funcaddr.update({dynstr:addr})

    def resolve(self, addr_buf):
        d = {}
        dynstr = dynsym = relplt = b''


        addr_buf_dynstr = addr_buf
        for s,a in self.funcaddr.items():
            d.update({s:len(dynstr)})
            dynstr += s.encode()+b"\x00"

        addr_buf_dynsym = addr_buf_dynstr + len(dynstr)
        if self.arch == 'x86':
            align_dynsym = (0x10-(addr_buf_dynsym-self.addr_dynsym)%0x10)%0x10
        elif self.arch in ['x86', 'amd64']:
            align_dynsym = (0x18-(addr_buf_dynsym-self.addr_dynsym)%0x18)%0x18
        addr_buf_dynsym += align_dynsym

        for s,of in d.items():
            if self.arch == 'x86':
                dynsym  += pack_32(addr_buf_dynstr + of - self.addr_dynstr)
                dynsym  += pack_32(0)
                dynsym  += pack_32(0)
                dynsym  += pack_32(0x12)
            elif self.arch in ['x86_64','amd64']:
                dynsym  += pack_32(addr_buf_dynstr + of - self.addr_dynstr)
                dynsym  += pack_32(0x12)
                dynsym  += pack_64(0)
                dynsym  += pack_64(0)
                
        addr_buf_relplt      = addr_buf_dynsym + len(dynsym)
        if self.arch == 'x86':
            align_relplt     = 0
            r_info           = (addr_buf_dynsym - self.addr_dynsym) // 0x10
        elif self.arch in ['x86_64','amd64']:
            align_relplt     = (0x18-(addr_buf_relplt - self.addr_relplt)%0x18)%0x18
            r_info           = (addr_buf_dynsym - self.addr_dynsym) // 0x18
        addr_buf_relplt     += align_relplt

        if self.addr_version is not None:
            warn('check gnu version : [0x%08x] & 0x7fff' % (self.addr_version+r_info*2))
        
        for s,a in self.funcaddr.items():
            if self.arch == 'x86':
                self.reloc_offset.update({s : addr_buf_relplt + len(relplt) -self.addr_relplt})
                relplt  += pack_32(a)
                relplt  += pack_32(r_info << 8 | 0x7)
            elif self.arch in ['x86_64','amd64']:
                self.reloc_offset.update({s : (addr_buf_relplt + len(relplt) -self.addr_relplt)/0x18})
                relplt  += pack_64(a)
                relplt  += pack_32(0x7)
                relplt  += pack_32(r_info)
                relplt  += pack_64(0)
            r_info  += 1

        if align_dynsym:
            info('DLresolve : Auto padding dynsym size is 0x%d bytes' % align_dynsym)
        if align_relplt:
            info('DLresolve : Auto padding relplt size is 0x%d bytes' % align_relplt)
            
        return dynstr + b'@'*(align_dynsym) + dynsym + b'@'*(align_relplt) + relplt

    def offset(self,dynstr):
        if dynstr in self.reloc_offset:
            return self.reloc_offset[dynstr]
        else:
            warn('dynstr "%s" does not exist.' % dynstr)
            exit()

        

        


            