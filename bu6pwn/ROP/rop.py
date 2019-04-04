from bu6pwn.core import *
from bu6pwn.ELF import ELF as ELF
from capstone import *


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
        
        self.cs_arch = {
            'i386': (CS_ARCH_X86, CS_MODE_32),
            'x86-64': (CS_ARCH_X86, CS_MODE_64),
            'arm': (CS_ARCH_ARM, CS_MODE_ARM)
        }.get(self.arch, (None, None))

    def analyze(self):
        """
        Getting gadgets from actual binary
        """
        gadget_terminations = self.add_rop_gadgets() 
        if not self.nojop:
            gadget_terminations += self.add_jop_gadgets()
        
        gadgets = self.search_gadgets(gadget_terminations)
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
    
    def search_gadgets(self, gadget_terminations):
        """
        Will determine gadgets in exectubable segments
        @gadget_terminations (required):  Bytes / Gadget Terminations for ROP generation
        """
        ret = []

        arch = self.arch
        # vaddr = self._entry_point
        section = self.get_exec_segments()

        vaddr = list(section.keys())[0]
        section = list(section.values())[0]

        md=Cs(self.cs_arch[0], self.cs_arch[1])

        for termination in gadget_terminations:
            # print("Termination({}): {}".format(type(termination), termination))
            # print("Section({}): {}".format(type(section), section))
            all_ref_ret = [m.end() for m in re.finditer(termination, section)]
            # print(all_ref_ret)
            for ref in all_ref_ret:
                for depth in range(1, self.depth + 1):
                    bytes_ = section[ref - depth:ref]
                    decodes = md.disasm(bytes_, vaddr + ref - depth)
                    gadget = ""
                    for decode in decodes:
                        gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                        # print((hex(vaddr+ref-depth) + ":" + decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " "))
                    if len(gadget) > 0:
                        gadget = gadget[:-3]
                        ret += [{"file": os.path.basename(self.fpath), "vaddr": vaddr+ref-depth, "gadget": gadget, "bytes": bytes_, "values": ""}]
        
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
            print(insts)
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
                
                


    
