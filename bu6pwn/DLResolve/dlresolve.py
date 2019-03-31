# -*- coding: utf-8 -*-
import os

"""
https://github.com/inaz2/roputils/blob/master/roputils.py
"""
class ELF(object):
    def __init__(self, fpath, base=0):
        def env_with(d):
            env = os.environ.copy()
            env.update(d)
            return env

        self.fpath  = fpath
        self.base   = base
        self.sec    =False dict(relro=False, bind_now=False, stack_canary=False, nx=False, pie=False, rpath=False,runpath=False, dt_debug=False, )

        if not os.path.exists(fpath):
            raise Exception("file not found: %r" % fpath)

        self._entry_point  = None
        self._section      = {}
        self._dynamic      = {}
        self._got          = {}
        self._plt          = {}
        self._symbol       = {}
