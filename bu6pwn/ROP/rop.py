from bu6pwn.core import *
from bu6pwn.ELF import ELF as ELF
from capstone import *
import struct

class ROP(ELF):
    def __init__(self, *args, **kwargs):
        """
        nojop=True, all=False, noretf=True
        Generates set of possible ROP gadgets
        @fpath  (required):  Filename to file which should be examined for possible gadgets
        @base   (optional):  Adjust memory rebase
        @debug  (optional):  Display ELF header info
        @nojop  (optional):  Boolean value defining whether to search for JOP gadgets also
        @all    (optional):  Boolean / delete duplicate gadgets
        @noretf (optional):  Boolean / define if blob should also be examined for far ret gadgets
        @depth  (optional):  Int / define depth for gadget search; default 3
        """
        self.debug = kwargs["debug"] if "debug" in kwargs else False
        self.base = kwargs["base"] if "base" in kwargs else 0 
        self.nojop = kwargs["nojop"] if "nojop" in kwargs else False
        self._all = kwargs["all"] if "all" in kwargs else False
        self.noretf = kwargs["noretf"] if "noretf" in kwargs else False
        self.depth = kwargs["depth"] if "depth" in kwargs else 3
        
        ELF.__init__(self, *args, debug=self.debug, base=self.base)


        if self.arch == 'i386':
            self.__class__ = type('ROP_I386', (ROP_I386,), {})
        if self.arch == 'x86-64':
            self.__class__ = type('ROP_X86_64', (ROP_X86_64,), {})
        if self.arch == 'arm':
            self.__class__ = type('ROP_ARM', (ROP_ARM,), {})
        # else:
        #     raise Exception("unknown architecture: %r" % self.arch)
        
        self.cs_arch = {
            'i386': (CS_ARCH_X86, CS_MODE_32),
            'x86-64': (CS_ARCH_X86, CS_MODE_64),
            'arm': (CS_ARCH_ARM, CS_MODE_ARM)
        }.get(self.arch, (None, None))

    def analyze(self, xonly=True):
        """
        Getting gadgets from actual binary
        """
        gadget_terminations = self.add_rop_gadgets() 
        if not self.nojop:
            gadget_terminations += self.add_jop_gadgets()
        
        gadgets = self.search_gadgets(gadget_terminations, xonly)
        gadgets = self.pass_clean(gadgets)

        if not self._all:
            gadgets = self.delete_duplicate_gadgets(gadgets)
        
        return self.alpha_sortgadgets(gadgets)
        return gadgets

    def add_rop_gadgets(self):
        gadgets = [
            b"\xc3",                # ret
            b"\xc2[\x00-\xff]{2}"   # ret <imm>
        ]
        if not self.noretf:
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
    
    def search_gadgets(self, gadget_terminations, xonly):
        """
        Will determine gadgets in exectubable segments
        @gadget_terminations (required):  Bytes / Gadget Terminations for ROP generation
        """
        ret = []

        arch = self.arch
        # vaddr = self._entry_point
        section = self.get_segments(xonly)

        vaddr = list(section.keys())[0]
        section = list(section.values())[0]

        md=Cs(self.cs_arch[0], self.cs_arch[1])

        if isinstance   (gadget_terminations, bytes):
            # print("BYTES")
            # print("PATT: {}".format(gadget_terminations))
            # all_ref_ret = [m.start() for m in re.finditer(re.escape(gadget_terminations), re.escape(section))]
            # all_ref_ret = [m.start() for m in re.finditer(re.compile(gadget_terminations), section)]
            # all_ref_ret=[ref for ref in range(len(section)) if section.startswith(gadget_terminations, ref)]
            all_ref_ret = [m.start() for m in re.finditer(re.escape(gadget_terminations), section)]
            # print(all_ref_ret)
            for ref in all_ref_ret:
                # print(type(ref))
                gadget = ""
                # bytes_ = section[ref:ref+len(gadget_terminations)]
                bytes_ = section[ref:ref+self.depth+1]
                decodes = md.disasm(bytes_, vaddr + ref)
                for decode in decodes:
                    # print(decode.mnemonic)
                    gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                    # print((hex(vaddr+ref[0]) + ":" + decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " "))
                if len(gadget) > 0:
                    ret += [{"file": os.path.basename(self.fpath), "vaddr": vaddr+ref, "gadget": gadget, "bytes": bytes_, "values": ""}]
                else:
                    ret = None
        elif isinstance(gadget_terminations, re.Pattern):
            # print("PATTERN")
            # print(gadget_terminations)
            # print("Termination({}): {}".format(type(termination), termination))
            # print("Section({}): {}".format(type(section), section))
            #all_ref_ret = [m.end() for m in re.finditer(gadget_terminations, section)]
            all_ref_ret = [m.start() for m in re.finditer(gadget_terminations, section)]
            # print(all_ref_ret)
            for ref in all_ref_ret:
                # for depth in range(1, self.depth + 1):
                # for depth in range(0, self.depth + 1):
                # bytes_ = section[ref - depth:ref]
                bytes_ = section[ref:ref+self.depth+1]
                # print("@{} -> {}".format(hex(ref), len(bytes_)))
                # decodes = md.disasm(bytes_, vaddr + ref - depth)
                decodes = md.disasm(bytes_, vaddr + ref + self.depth)
                gadget = ""
                for decode in decodes:
                    gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                    # print((hex(vaddr+ref-depth) + ":" + decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " "))
                if len(gadget) > 0:
                    # CHANGED
                    # gadget = gadget[:-3]
                    # gadget = gadget[:-depth]
                    # gadget = gadget[:self.depth]
                    # ret += [{"file": os.path.basename(self.fpath), "vaddr": vaddr+ref-depth, "gadget": gadget, "bytes": bytes_, "values": ""}]
                    # ret += [{"file": os.path.basename(self.fpath), "vaddr": vaddr+ref, "gadget": gadget, "bytes": bytes_, "values": ""}]
                    ret += [{"file": os.path.basename(self.fpath), "vaddr": vaddr+ref, "gadget": gadget.rstrip(), "bytes": bytes_, "values": ""}]
        
        return ret

    def pass_clean(self, gadgets):
        new = []
        br = ["ret"]
        if not self.noretf:
            br += ["retf"]
        if not self.nojop:
            br += ["jmp", "call"]
        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if len([m.start() for m in re.finditer("ret", gadget["gadget"])]) > 1:
                continue
            new += [gadget]
        return new

    def delete_duplicate_gadgets(self, gadgets):
        gadgets_content_set = set()
        unique_gadgets = []
        for gadget in gadgets:
            gad = gadget["gadget"]
            if gad in gadgets_content_set:
                continue
            gadgets_content_set.add(gad)
            unique_gadgets += [gadget]
        return unique_gadgets

    def alpha_sortgadgets(self, current_gadgets):
        return sorted(current_gadgets, key=lambda gadget: gadget["gadget"])

    def p(self, x):
        if self.wordsize == 8:
            return pack_64(x)
        else:
            return pack_32(x)
    
    def search(self, s, xonly=True):
        _gadgets = []
        gadgets = self.analyze(xonly)
        for g in gadgets:
            m = re.findall(s, g["gadget"])
            if m:
                _gadgets.append(g)

        return _gadgets

    def gadget(self, *args, **kwargs):
        m=self.gadgets(*args, **kwargs)
        return m[0]['vaddr'] if m else None

    # def gadget(self, s):
    #     return self.search(s, xonly=True)
    
    def string(self, s):
        return s.encode() + b'\x00'
    
    def junk(self, n=1):
        return self.fill(self.wordsize * n)

class ROP_I386(ROP):
    regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']


    def gadgets(self, keyword=None, reg=None, n=1):
        self.depth = n

        section = self.get_segments(xonly=True)
        vaddr = list(section.keys())[0]
        section = list(section.values())[0]

        table = {
            'pushad': b"\x60\xc3",
            'popad': b"\x61\xc3",
            'leave': b"\xc9\xc3",
            'ret': b"\xc3",
            'int3': b"\xcc",
            'int80': b"\xcd\x80",
            'call_gs10': b"\x65\xff\x15\x10\x00\x00\x00",
            'syscall': b"\x0f\x05",
        }

        if keyword in table:
            return self.search_gadgets(table[keyword], xonly=True)
        elif keyword is None:
            raise Exception("Should supply keyword")
        
        if reg:
            try:
                r = self.regs.index(reg)
            except:
                raise Exception("unexpected register: %r" % reg)
        
        else:
            r = self.regs.index('esp')

        if keyword == 'pop':
            if reg:
                chunk1=bytearray()
                chunk1.append(0x58+r)
                chunk1.append(0xc3)
                chunk2=bytearray()
                chunk2.append(0x8f) 
                chunk2.append(0xc0+r)
                chunk2.append(0xc3)
                
                for c in [chunk1, chunk2]:
                    return self.search_gadgets(bytes(c), xonly=True)
            else:
                #skip esp
                chunk=re.compile(b"[\x5d-\x5f]{%d}\xc3" % n)
                #chunk=re.compile(b"(?:(?:[\x58-\x5b]|[\x5d-\x5f])|\x8f[\xc0-\xc3\xc5-\xc7]){%d}\xc3" % n)
                #chunk1=re.compile(b"[\x58-\x5b\x5d-\x5f]{%d}\xc3" % n)
                #chunk2=re.compile(b"\x8f[\xc0-\xc3\xc5-\xc7]{%d}\xc3" % n)

                #for c in [chunk1, chunk2]:
                return self.search_gadgets(chunk, xonly=True)
        
        elif keyword == 'call':
            chunk=bytearray()
            chunk.append(0xff)
            chunk.append(0xd0+r)
            return self.search_gadgets(bytes(chunk), xonly=True)

        elif keyword == 'jmp':
            chunk=bytearray()
            chunk.append(0xff)
            chunk.append(0xe0+r)
            return self.search_gadgets(bytes(chunk), xonly=True)

        elif keyword == 'jmp_ptr':
            chunk=bytearray()
            chunk.append(0xff)
            chunk.append(0x20+r)
            return self.search_gadgets(bytes(chunk), xonly=True)

        elif keyword == 'push':
            chunk1=bytearray()
            chunk1.append(0x50+r)
            chunk1.append(0xc3)
            chunk2=bytearray()
            chunk2.append(0xff)
            chunk2.append(0xf0+r)
            chunk2.append(0xc3)

            for c in [chunk1, chunk2]:
                return self.search_gadgets(bytes(c), xonly=True)
        
        elif keyword == 'pivot':
            # chunk1: xchg REG, esp
            # chunk2: xchg esp, REG
            if r == 0:
                chunk1 = bytearray()
                chunk1.append(0x94)
                chunk1.append(0xc3)
            else:
                chunk1 = bytearray()
                chunk1.append(0x87)
                chunk1.append(0xe0+r)
                chunk1.append(0xc3)

            chunk2 = bytearray()
            chunk2.append(0x87)
            chunk2.append(0xc4+8*r) 
            chunk2.append(0xc3)

            for c in [chunk1, chunk2]:
                return self.search_gadgets(bytes(c), xonly=True)

        elif keyword == 'loop':
            chunk1 = b'\xeb\xfe'
            chunk2 = b'\xe9\xfb\xff\xff\xff'

            for c in [chunk1, chunk2]:
                return self.search_gadgets(bytes(c), xonly=True)
        else:
            # search directly
            return None
    
    def call(self, addr, *args):
        if isinstance(addr, str):
            try:
                addr = self.plt(addr)
            except:
                raise Exception("%s seems not to be in PLT" % addr)
        
        buf = self.pack(addr)
        buf += self.pack(self.gadget('pop', n=len(args)))
        for n in range(0, len(args)):
            buf += self.pack(args[n])
        return buf
        
    def call_chain_ptr(self, *calls, **kwargs):
        raise Exception('supports x86-64 only')
    
    def dl_resolve_data(self, base, name):
        jmprel=self.dynamic('JMPREL')
        relent=self.dynamic('RELENT')
        symtab=self.dynamic('SYMTAB')
        syment=self.dynamic('SYMENT')
        strtab=self.dynamic('STRTAB')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
        addr_sym, padlen_sym = self.align(addr_reloc+relent, symtab, syment)
        addr_symstr = addr_sym + syment

        r_info = (((addr_sym - symtab) // syment) << 8) | 0x7
        st_name = addr_symstr - strtab

        buf = self.fill(padlen_reloc).encode()
        buf += struct.pack('<II', base, r_info)                      # Elf32_Rel
        buf += self.fill(padlen_sym).encode()
        buf += struct.pack('<IIII', st_name, 0, 0, 0x12)             # Elf32_Sym
        buf += self.string(name)

        return buf

    def dl_resolve_call(self, base, *args):
        jmprel=self.dynamic('JMPREL')
        relent=self.dynamic('RELENT')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
        reloc_offset = addr_reloc - jmprel

        buf = pack_32(self._section['.plt'][0])
        buf += pack_32(reloc_offset)
        buf += pack_32(self.gadget('pop', n=len(args)))
        for n in range(0, len(args)):
            buf += pack_32(args[n])

        return buf
    
    def syscall(self, number, *args):
        try:
            arg_regs = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
            buf = self.p([self.gadget('pop', 'eax'), number])
            for arg_reg, arg in zip(arg_regs, args):
                buf += self.p([self.gadget('pop', arg_reg), arg])
        except ValueError:
            # popad = pop edi, esi, ebp, esp, ebx, edx, ecx, eax
            args = list(args) + [0] * (6-len(args))
            buf = self.p([self.gadget('popad'), args[4], args[3], args[5], 0, args[0], args[2], args[1], number])
        buf += self.p(self.gadget('int80'))
        return buf

    def retfill(self, size, buf=''):
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        s = self.fill(buflen % self.wordsize).encode()
        s += (pack_32(self.gadget('ret'))) * (buflen // self.wordsize)
        return s

    def pivot(self, esp):
        buf = pack_32(self.gadget('pop', reg="ebp"))
        buf += pack_32(esp-self.wordsize)
        buf += pack_32(self.gadget('leave'))
        return buf