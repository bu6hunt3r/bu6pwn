from bu6pwn.core import *
from bu6pwn.ELF import ELF as ELF

class ROP(ELF):
    def __init__(self, *args, **kwargs):
        ELF.__init__(self, *args, **kwargs)
        if self.arch == 'i386':
            self.__class__ = type('ROP_I386', (ROP_I386,), {})
        if self.arch == 'x86-64':
            self.__class__ = type('ROP_X86_64', (ROP_X86_64,), {})
        if self.arch == 'arm':
            self.__class__ = type('ROP_ARM', (ROP_ARM,), {})
        else:
            raise Exception("unknown architecture: %r" % self.arch)
        
    def p(self, x):
        if self.wordsize == 8:
            return pack_64(x)
        else:
            return pack_32(x)
    
    def gadget(self, s):
        return self.search(s, xonly=True)
    
    def string(self, s):
        return s + b'\x00'
    
    def junk(self, n=1):
        return self.fill(self.wordsize * n)

    def load(self, blob, base=0):
        self._load_blobs += [(base, blob, True)]

    def scan_gadgets(self, regexp):
        for virtaddr, blob, is_executable in self._load_blobs:
            if not is_executable:
                continue

            for m in re.finditer(regexp, blob):
                if self.arch == 'arm':
                    arch = 'thumb'
                else:
                    arch = self.arch
                
                


    
