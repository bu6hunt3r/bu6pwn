from setuptools import setup
import os
import pwd
import grp

setup(
    name='bu6pwn',
    version = "1.0",
    description = "bu6pwn tries to simplify exploitation dev process\
                     (at least) for me",
    url = "https://github.com/bu6hunt3r/bu6pwn",
    author = "bu6hunt3r",
    license = "GPLv3",
    packages = ["bu6pwn/core","bu6pwn/FSB", "bu6pwn/IO", "bu6pwn/DLResolve", "bu6pwn/ELF", "bu6pwn/ROP"],
    zip_safe = False,
)