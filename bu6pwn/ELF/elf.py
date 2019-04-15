# -*- coding: utf-8 -*-

from bu6pwn.core import *
import os
from elftools.elf import elffile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.relocation import RelocationSection, RelocationHandler
from elftools.elf.constants import SHN_INDICES
import struct
import random
import re

class ELF(object):
    def __init__(self, fpath, base=0, debug=False):
        """
        Generates set of possible ROP gadgets
        @fpath (required):  Filename to ELF file to analyze
        @base  (optional):  Adjust memory rebase
        @debug (optional):  Display ELF header info
        """
        def env_with(d):
            env = os.environ.copy()
            env.update(d)
            return env

        self.fpath = fpath
        self.base = base
        self.sec = dict(relro=False, bind_now=False, stack_canary=False, nx=False, pie=False, rpath=False, runpath=False, dt_debug=False)

        if not os.path.exists(fpath):
            raise Exception("file not found: %r" % fpath)

        self._debug = debug
        
        self._entry_point = None
        self._section = {}
        self._dynamic = {}
        self._got = {}
        self._plt = {}
        self._symbol = {}
        self._load_blobs = []
        self._string = {}

        plt_size_map = {
            'i386': (0x10, 0x10),
            'x86-64': (0x10, 0x10),
            'arm': (0x14, 0xc),
        }

        self.regexp = {
            'string': b'([\s\x21-\x7e]{4,})\x00',
        }

        stream = open(self.fpath, 'rb')
        p = elffile.ELFFile(stream)

        self.p = p

        value = p.elfclass
        if value == 32:
            self.wordsize = 4
        elif value == 64:
            self.wordsize = 8
        else:
            raise Exception("unsupported ELF Class: %r" % value)

        value = p.header["e_type"]
        if value == 'ET_EXEC':
            self.sec["pie"] = False
        elif value == 'ET_DYN':
            self.sec["pie"] = True
        else:
            raise Exception("unsupported ELF Type: %r" % value)
        
        value = p.header["e_machine"]
        if value == 'EM_386':
            self.arch = 'i386'
        elif value == 'EM_X86_64':
            self.arch = 'x86-64'
        elif value == 'EM_ARM':
            self.arch = 'arm'
        else:
            raise Exception("unsupported ELF Machine: %r" % value)
        
        value = p.header["e_entry"]
        if value:
            self._entry_point = value

        self.fill_sections()
        self.load_segments()
        self.check_nx()
        self.populate_got_plt()
        
        if self._debug:
            self.show()

    def got(self, name=""):
        if name != "":
            return self._got[name.encode()]
        else:
            return self._got

    def plt(self, name=""):
        if name != "":
            return self._plt[name.encode()]
        else:
            return self._plt

    def dynamic(self, name):
        if name in self._dynamic.keys():
            return self._dynamic[name]
        else:
            return None
    
    def has_dynamic(self):
        return bool(self._dynamic)


    def string(self, s):
        return s.encode()+b"\x00"

    def fill(self, size, buf=b''):
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        return ''.join(random.choice(chars) for i in range(buflen))

    def align(self, addr, origin, size):
        padlen = size - ((addr-origin) % size)
        return (addr+padlen, padlen)

    def show(self):
        self._sec_info = "\n"
        for k, v in self.sec.items():
            self._sec_info += "\t{}: {}".format(k, v) + "\n"

        self._section_info = "\n"
        for k, v in self._section.items():
            if k != "":
                t_str = "\t"+"Name: {}".format(k.ljust(20))
                self._section_info += t_str
                t_str = "Address: {:#x}".format(v[0]).ljust(20)
                self._section_info += t_str
                t_str = "Size: {}".format(k.ljust(20))
                self._section_info += t_str + "\n"
        self._section_info += "\n\t--------------------\n"
        self._section_info += "\tDynamic sections\n\n"
        for k, v in self._dynamic.items():
            self._section_info += "\t{} -> {:#x}".format(k, v) + "\n"

        self._header_info = """
        ELF ({})
        Wordsize: {}
        PIC: {}
        Architecture: {}
        Entry Point: {:#x}

        --------------------
        Sections
        {}
        --------------------
        Security parameters
        {}
        """.format(self.fpath, self.wordsize, self.sec["pie"], self.arch, self._entry_point, self._section_info, self._sec_info)
        info("{}".format(self._header_info))

    def check_nx(self):
        for ph in self.p.iter_segments():
            if ph.header.__getattribute__("p_type") == "PT_GNU_RELRO":
                self.sec["relro"] = True
            if ph.header.__getattribute__("p_type") == "PT_GNU_STACK":
                self.sec["nx"] = True

    def populate_got_plt(self):
        plt = self.p.get_section_by_name('.plt')
        got = self.p.get_section_by_name('.got')

        if not plt:
            return

        # Find the relocation section for PLT
        try:
            rel_plt = next(s for s in self.p.iter_sections() if
                           s.header.sh_info == self.p.get_section_by_name('.plt') and
                           isinstance(s, RelocationSection))
        except StopIteration:
            # Evidently whatever android-ndk uses to build binaries zeroes out sh_info for rel.plt
            rel_plt = self.p.get_section_by_name('.rel.plt') or self.p.get_section_by_name('.rela.plt')

        if not rel_plt:
            warn("Couldn't find relocations against PLT to get symbols")
            return

        if rel_plt.header.sh_link != SHN_INDICES.SHN_UNDEF:
            # Find the symbols for the relocation section
            sym_rel_plt = self.p.get_section(rel_plt.header.sh_link)

            # Populate the GOT
            for rel in rel_plt.iter_relocations():
                sym_idx = rel.entry.r_info_sym
                symbol = sym_rel_plt.get_symbol(sym_idx)
                name = symbol.name.encode('ascii')
                self._got[name] = rel.entry.r_offset

        # Depending on the architecture, the beginning of the .plt will differ
        # in size, and each entry in the .plt will also differ in size.
        offset = None
        multiplier = None

        # Map architecture: offset, multiplier
        header_size, entry_size = {
            'i386': (0x10, 0x10),
            'amd64': (0x10, 0x10),
            'arm': (0x14, 0xC),
            'aarch64': (0x20, 0x20),
        }.get(self.arch, (0, 0))

        # Based on the ordering of the GOT symbols, populate the PLT
        for i, (addr, name) in enumerate(sorted((addr, name)
                                                for name, addr in self._got.items())):
            self._plt[name] = plt.header.sh_addr + header_size + i * entry_size

        # print("GOT")
        # print(self.got)
        # print("PLT")
        # print(self.plt)

    def fill_sections(self):
 
        R=RelocationHandler(self.p)
        relocs=[]

        for s in self.p.iter_sections():
            if isinstance(s, DynamicSection):
                for tag in s.iter_tags():
                    # Get JMPREL section
                    if tag.entry["d_tag"] == "DT_JMPREL":
                        self._dynamic.update({"JMPREL":tag.entry["d_val"]})
                    # Get RELENT section
                    if tag.entry["d_tag"] == "DT_RELENT":
                        self._dynamic.update({"RELENT":tag.entry["d_val"]})
                    # Get SYMTAB section
                    if tag.entry["d_tag"] == "DT_SYMTAB":
                        self._dynamic.update({"SYMTAB":tag.entry["d_val"]})
                    # Get STRTAB section
                    if tag.entry["d_tag"] == "DT_STRTAB":
                        self._dynamic.update({"STRTAB":tag.entry["d_val"]})
                    # Get SYMENT section
                    if tag.entry["d_tag"] == "DT_SYMENT":
                        self._dynamic.update({"SYMENT":tag.entry["d_val"]})

            elif isinstance(s, RelocationSection):
                #symtable = self.p.get_section(s.header['sh_link'])
                # for section in self.p.iter_sections():
                for r in s.iter_relocations():
                    relocs.append((r['r_offset'], r['r_info'], r['r_info_sym'], r['r_info_type']))

            elif not isinstance(s, DynamicSection):
                self._section.update({s.name:(s.header["sh_addr"], s.data_size)})

        # for r in relocs:
        #     # print(r[2])
        #     d = self.p.get_section_by_name('.dynsym').data()
        #     offset_symtab = r[2]*0x10
        #     offset_strtab=unpack_8(d[offset_symtab:offset_symtab+1])
        #     #print(hex(offset_strtab))
        #     s = self.p.get_section_by_name('.dynstr').data()[offset_strtab:]
        #     #print("Addr: {} - {}".format(hex(r[0]), s.index(b"\x00")))
        #     _symstr = s[:s.index(b"\x00")]
        #     # i=0
        #     # while not b'\x00' in s:
        #     #     _symstr += s[i]
        #     #     i+=1
        #     #print(_symstr)
        #     # # print(hex(offset_strtab))
        #     #print(hex(self.dynamic('STRTAB')+offset_strtab*16))
        #     #print(offset_strtab)

        #     self._got.update({_symstr:r})

        # print(self._got)

    def load_segments(self):
        for ph in self.p.iter_segments():
            if ph["p_type"] == 'PT_LOAD':
                virtaddr = ph['p_vaddr']
                is_executable = bool(ph.header['p_flags'] & 0x1)
                with open(self.fpath, 'rb') as f:
                    f.seek(ph.header['p_offset'])
                    blob = f.read(ph.header['p_memsz'])
                
                self._load_blobs.append((virtaddr, blob, is_executable))
                for m in re.finditer(self.regexp['string'], blob):
                    self._string[virtaddr+m.start()] = m.group(1)
            
            # for tag in ph.iter_tags():
            #     if tag['d_tag'] == 'DT_PLTGOT':
            #         print("FOUND PLT")

    def get_segments(self, xonly):
        segs = {}
        for seg in self._load_blobs:
            if xonly == True:
                if seg[-1] == True:
                    segs.update({seg[0]:seg[-2]})
            else:
                segs.update({seg[0]:seg[-2]})
        
        return segs



    def offset(self, offset):
        return self.base + offset

    def pack(self, x):
        if self.wordsize == 8:
            return pack_64(x)
        else: 
            return pack_32(x)

    def search(self, s, xonly =False):
        if isinstance(s, int):
            s = self.p(s)
        elif isinstance(s, str):
            s = s.encode()
        
        for virtaddr, blob, is_executable in self._load_blobs:
            if xonly and not is_executable:
                continue

            retype = type(re.compile('search'))
            if isinstance(s, retype):
                for m in re.finditer(s, blob):
                    addr = self.offset(virtaddr + m.start())
                    if self.arch == 'arm' and xonly and addr %2 != 0:
                        continue
                    return addr
            else:
                i = -1
                while True:
                    i =blob.find(s, i+1)
                    if i == -1:
                        break
                    addr = self.offset(virtaddr + i)
                    if self.arch == 'arm' and xonly and addr % 2 != 0:
                        continue
                    return addr
        else:
            return ValueError()