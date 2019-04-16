from bu6pwn.core import *
import socket
from threading import Thread, Event
from subprocess import Popen, PIPE
import os
import select
import sys
import re
from telnetlib import Telnet
from contextlib import contextmanager

class Proc(object):
    """
    Enables the possibility to communicate to local processes or remote services via sockets.
    @timoeout   (optional): Sets timeout for connections in secs
    @display    (optional): Displays the communication verbosely
    @debug      (optional): Enables th possibilty to attach a debugger immediately after starting the process
    @host       (optional): Remote process host ip
    @port       (optional): Remote process host port
    """
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.get('timeout', 0.1)
        self.display = kwargs.get('display', False)
        self.debug = kwargs.get('debug', False)

        if 'host' in kwargs and 'port' in kwargs:
            self.s = socket.create_connection(kwargs['host'], kwargs['port'])
        else:
            self.s = self.connect_process(args)
        
    def connect_process(self, cmd):
        def run_server(s, e, cmd):
            c, addr = s.accept()
            s.close()

            try:
                p = Popen(cmd, stdin=c, stdout=c, stderr=c, preexec_fn=lambda: os.setsid())
            except Exception as err:
                c.close()
                e.set()
                raise err
            
            if self.debug:
                input("\x1b[32mpid %s is running, attach the debugger if needed. Hit enter to continue...\x1b[0m" % p.pid)
            
            e.set()
            p.wait()
            c.close()
        
        s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 0)) # INADDR_ANY, INPORT_ANY
        s.listen(1)     # Backlog 1 connection

        e = Event()
        t = Thread(target=run_server, args=(s, e, cmd))
        t.daemon = True
        t.start()
        c=socket.create_connection(s.getsockname())
        e.wait()
    
        return c

    def write(self, s):
            select.select([], [self.s], [])
            self.s.sendall(s)

            if self.display:

                printable = re.sub(b'[^\s\x20-\x7e]', b'.', s)
                sys.stdout.write("\x1b[33m%s\x1b[0m" % printable.decode())  # yellow
                sys.stdout.flush()

    def read(self, size=-1, timeout=1):
        if size < 0:
            chunk_size = 8192
            buf = b''
            while True:
                chunk = self.read(chunk_size, timeout)
                buf += chunk
                if len(chunk) < chunk_size:
                    break
            return buf

        if not timeout:
            timeout = self.timeout

        buf = b''
        while len(buf) < size:
            rlist, wlist, xlist = select.select([self.s], [], [], timeout)
            if not rlist:
                break
            chunk = self.s.recv(size-len(buf))
            if not chunk:
                break
            buf += chunk

        if self.display:
            printable = re.sub(b'[^\s\x20-\x7e]', '.', buf)
            sys.stdout.write("\x1b[36m%s\x1b[0m" % printable.decode())  # cyan
            sys.stdout.flush()

        return buf

    def read_until(self, s):
        buf = bytearray(self.read(len(s), None))
        while not buf.endswith(s):
            buf += (self.read(1, None))
        return buf

    def expect(self, regexp):
        buf = b''
        m = None
        while not m:
            buf += self.read(1, None)
            m = re.search(regexp, buf)
        return m

    def readline(self):
        return self.read_until(b'\n')

    def writeline(self, s):
        return self.write(s+b'\n')

    def shutdown(self, writeonly=False):
        if writeonly:
            self.s.shutdown(socket.SHUT_WR)
        else:
            self.s.shutdown(socket.SHUT_RDWR)

    def close(self):
        self.s.close()

    def interact(self, shell_fd=None):
        check_cmd = b'echo "\x1b[32mgot a shell!\x1b[0m"'  # green

        buf = self.read()
        sys.stdout.write(buf.decode())

        if shell_fd is not None:
            self.write(check_cmd + b'\n')
            sys.stdout.write(self.read())
            self.write(b"exec /bin/sh <&%(fd)d >&%(fd)d 2>&%(fd)d\n" % {'fd': shell_fd})

        t = Telnet()
        t.sock = self.s
        t.interact()
        self.shutdown()
        self.close()

    @contextmanager
    def listen(self, port=0, is_shell=False):
        check_cmd = 'echo "\x1b[32mgot a shell!\x1b[0m"'  # green

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port))
        s.listen(1)

        yield s.getsockname()

        c, addr = s.accept()
        s.close()
        if is_shell:
            c.sendall(check_cmd + '\n')
            sys.stdout.write(c.recv(8192))

        t = Telnet()
        t.sock = c
        t.interact()
        c.close()

    def pipe_output(self, *args):
        p = Popen(args, stdin=self.s, stdout=PIPE)
        stdout, stderr = p.communicate()
        return stdout

    def read_p64(self):
        return pack_64(self.read(8, None))

    def read_p32(self):
        return pack_32(self.read(4, None))

    def write_p64(self, s):
        return self.write(pack_64(s))

    def write_p32(self, s):
        return self.write(pack_32(s))