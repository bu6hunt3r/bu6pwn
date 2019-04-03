from bu6pwn.core import *
from bu6pwn.ELF import ELF as ELF
from capstone import *

class ROP(ELF):
    def __init__(self, *args, **kwargs):
        """
        Generates set of possible ROP gadgets
        @fpath  (required):  Filename to file which should be examined for possible gadgets
        @base   (optional):  Adjust memory rebase
        @debug  (optional):  Display ELF header info
        @nojop  (optional):  Boolean value defining whether to search for JOP gadgets also
        @all    (optional):  Boolean / delete duplicate gadgets
        @noretf (optional):  Boolean / define if blob should also be examined for far ret gadgets
        """
        ELF.__init__(self, *args, **kwargs)
        # if self.arch == 'i386':
        #     self.__class__ = type('ROP_I386', (ROP_I386,), {})
        # if self.arch == 'x86-64':
        #     self.__class__ = type('ROP_X86_64', (ROP_X86_64,), {})
        # if self.arch == 'arm':
        #     self.__class__ = type('ROP_ARM', (ROP_ARM,), {})
        # else:
        #     raise Exception("unknown architecture: %r" % self.arch)
        if self.arch not in ['i386', 'x86-64', 'arm']:
            raise Exception("unknown architecture: %r" % self.arch)
        
        self.options = Dotdict(kwargs)
        print(args)
        print(kwargs)
        print(self.options)

    def analyze(self):
        gadget_terminations = self.add_rop_gadgets() 
        if not self.options.nojop:
            gadget_terminations += self.add_jop_gadgets()
        
        gadgets = self.search_gadgets(gadget_terminations)
        gadgets = self.pass_clean(gadgets)

        if not self.options.all:
            gadgets = self.delete_duplicate_gadgets()
        
        return self.alpha_sortgadgets(gadgets)

    def add_rop_gadgets(self):
        gadgets = [
            b"\xc3",                # ret
            b"\xc2[\x00-\xff]{2}"   # ret <imm>
        ]
        if not self.options.noretf:
            # Far return: does not also pop IP, it also pops code segment (CS) 
            # throwback to older days when segmented memory models were common.
            gadgets += [
                b"\xc3",                # retf
                b"\xca[\x00-\xff]{2}"   # retf <imm>
            ]
        
        return gadgets

    def add_jop_gadgets(self):
        gadgets = [
            b"\xff[\x20\x21\x22\x23\x26\x27]{1}",      # jmp  [reg]
            b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}",  # jmp  [reg]
            b"\xff[\x10\x11\x12\x13\x16\x17]{1}",      # jmp  [reg]
            b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}"   # call [reg]
        ]

        return gadgets



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
                
                


    
