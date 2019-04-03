#!/usr/bin/env python3
#-*- coding: utf-8 -*-
import sys
import os
from struct import pack, unpack
from base64 import b64decode, b64encode
from time import sleep
import re

class Dotdict(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = Dotdict(value)
            self[key] = value

def debug(function):
    def wrapped(*args, **kwargs):
        args_repr=[repr(a) for a in args]
        kwargs_repr=[f"{k}={v!r}" for k,v in kwargs.items()]
        print("Function {}'s args: {}".format(function.__name__, args_repr))
        print("Function {}'s kwargs: {}".format(function.__name__, kwargs_repr))
        print("Function {} returns: {}".format(function.__name__, function(*args, **kwargs)))
        return function(*args, **kwargs)
    return wrapped

NULL                = 0
# <unistd.h>
STDIN_FILENO        = 0
STDOUT_FILENO       = 1
STDERR_FILENO       = 2
SEEK_SET            = 0
SEEK_CUR            = 1
SEEK_END            = 2
# <bits/fcntl-linux.h>
O_RDONLY            = 0o0000
O_WRONLY            = 0o0001
O_RDWR              = 0o0002
O_CREAT             = 0o0100
O_APPEND            = 0o2000
# <bits/mman-linux.h>
PROT_NONE           = 0b000
PROT_READ           = 0b001
PROT_WRITE          = 0b010
PROT_EXEC           = 0b100
MAP_SHARED          = 0b001
MAP_PRIVATE         = 0b010
MAP_ANONYMOUS       = 0x20

PREV_INUSE          = 0b001
IS_MMAPED           = 0b010
IS_NON_MAINARENA    = 0b100

fsb_len     =   lambda x:         "%6$"+str(x if x>0 else 0x10000+x) + "x" if x!=0 else ""
heap_sb     =   lambda x,y:       (x&~0b111)|y
pack_8      =   lambda x:         pack('<B' if x > 0 else '<b',x)
pack_16     =   lambda x:         pack('<H' if x > 0 else '<h',x)
pack_32     =   lambda x:         pack('<I' if x > 0 else '<i',x)
pack_64     =   lambda x:         pack('<Q' if x > 0 else '<q',x)
unpack_8    =   lambda x,s=False: unpack('<B' if not s else '<b',x)[0]
unpack_16   =   lambda x,s=False: unpack('<H' if not s else '<h',x)[0]
unpack_32   =   lambda x,s=False: unpack('<I' if not s else '<i',x)[0]
unpack_64   =   lambda x,s=False: unpack('<Q' if not s else '<q',x)[0]
mold_32     =   lambda x:         (x+'\x00'*(4-len(x)))[:4]
mold_64     =   lambda x:         (x+'\x00'*(8-len(x)))[:8]
rol         = lambda val, r_bits, max_bits: \
              (val << r_bits%max_bits) & (2**max_bits-1) | \
              ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
ror         = lambda val, r_bits, max_bits: \
              ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
              (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
lib_path    = lambda p,l:     re.search(r'%s => ([^\s]+)' % l, LocalShell().get_output('ldd %s' % p)).group(1) if LocalShell().exists('ldd') else None

#===============

color       = {'N':9,'R':1,'G':2,'Y':3,'B':4,'M':5,'C':6,'W':7}
console     = {'bold'       : '\x1b[1m', \
               'c_color'    : lambda c: '\x1b[%dm'%(30+color[c]), \
               'b_color'    : lambda c: '\x1b[%dm'%(40+color[c]), \
               'reset'      : '\x1b[0m'}

template    = console['bold']+'%s%s%s'+console['reset']
message     = lambda c,t,x: sys.stderr.write(template % (console['c_color'](c), t, console['c_color']('N')+x) + '\n')
info        = lambda x:     message('B', '[+]', x)
proc        = lambda x:     message('G', '[*]', x)
warn        = lambda x:     message('Y', '[!]', x)
fail        = lambda x:     message('R', '[-]', x)

if os.name == 'nt':
    try:
        from colorama import init as color_init
        color_init()
    except:
        fail('module "colorama" is not importable')

#===============

class Environment(object):
    def __init__(self, *envs):
        self.__env = None
        self.env_list = list(set(envs))
        for env in self.env_list:
            setattr(self, env, dict())
    
    def set_item(self, name, **obj):
        if obj.keys() != self.env_list:
            fatal("Environment : '%s' envoronment does not match" % name)
            return

        for env in obj:
            getattr(self, env).update({name:ibj[env]})
    
    def select(self, env=None):
        if env is not None and env not in self.env_list:
            warn("Environment : '%s' is not defined" % env)
            env = None
        
        while env is None:
            sel = input("Select Environment\n%s ..." % str(self.env_list))
            if not sel:
                env = self.env_list[0]
            elif sel in self.env_list:
                env = sel
            else:
                for e in self.env_list:
                    if e.startswith(self):
                        env = e
                        break
        
        info("Environment : set environment '%s'" % env)
        for name, obj in getattr(self, env).items():
            setattr(self, name, obj)
        self.__env = env
    
    def check(self, env):
        return self.__env == env

