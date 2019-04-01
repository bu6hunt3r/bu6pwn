#!/usr/bin/env python
#-*- coding: utf-8 -*-

from bu6pwn.core import *

class LocalShell(object):
    def __init__(self, env=None):
        from subprocess import call, check_output

        self.__call = call
        self.__check_output = check_output
        self.env = env

    def call(self, cmd, output=True):
        cmd = cmd.split(' ')
        if not output:
            devnull = open(os.devnull, 'w')
            ret = self.__call(cmd, stdout=devnull, stderr =devnull, env=self.env)
            devnull.close()
        else:
            ret = self.__call(cmd, env=self.env)
        return ret

    def get_output(self, cmd):
        return self.__check_output(cmd.split(' '), env=self.env)

    def exists(self, cmd):
        try:
            self.call(cmd, False)
            return True
        except:
            return False
class Communicate:    
    def __init__(self, target, mode='SOCKET', disp=True, **args):
        self.disp = disp
        
        if mode not in ['SOCKET','LOCAL','SSH']:
            warn('Communicate : mode "%s" is not defined' % mode)
            info('Communicate : Set mode "SOCKET"')
            mode = 'SOCKET'
        self.mode = mode
        self.is_alive = True
        
        self.show_mode = None
        self.hexdump = None

        # for legacy exploit
        if isinstance(target, tuple):
            target = {'host':target[0], 'port':target[1]}
        elif isinstance(target, str):
            target = {'program':target}

        # environment
        if self.mode!='SOCKET':
            env_dict    = dict()
            env_str     = ''
            if 'env' in args and isinstance(args['env'] ,dict):
                env_dict.update(args['env'])
                for e in args['env'].items():
                    info('set env "%s": %s' % e)
                    env_str += '%s="%s" ' % e

        if self.mode=='SOCKET':
            import socket
            
            rhp = (target['host'],target['port'])
            if self.disp:
                proc('Connect to %s:%d' % rhp)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(args['to'] if 'to' in args else 1.0)
            self.sock.connect(rhp)

            self.timeout = socket.timeout
            
        elif self.mode=='LOCAL':
            import subprocess
                        
            if self.disp:
                proc('Starting program: %s' % target['program'])
            if 'GDB' in args and isinstance(args['GDB'] ,(int,long)):
                shell = True
                wrapper = ('--wrapper env %s --' % env_str) if env_str else ''    
                target['program'] = 'gdbserver %s localhost:%d %s' % (wrapper, args['GDB'], target['program'])
            elif 'ASLR' in args and args['ASLR']==False:
                shell = True
                target['program'] = 'ulimit -s unlimited; %s setarch i386 -R %s' % (env_str, target['program'])
            else:
                shell = False
                if isinstance(target['program'], str):
                    target['program'] = target['program'].split(' ')

            self.wait = ('wait' in args and args['wait'])
                
            self.proc = subprocess.Popen(target['program'], shell=shell, env=env_dict, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            info('PID : %d' % self.proc.pid)
            self.set_nonblocking(self.proc.stdout)
            if target['program'][0]=='gdbserver':
                info(self.read_until()[:-1])
                proc(self.read_until()[:-1])
                info(self.read_until()[:-1])
                raw_input('Enter any key to continue...')

            self.timeout = None
            
        elif self.mode=='SSH':
            import paramiko
            import socket
            
            if self.disp:
                proc('Connect SSH to %s@%s:%d' % (target['username'],target['host'],target['port']))
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(target['host'], username=target['username'], password=target['password'], port=target['port'])
            self.channel = self.ssh.get_transport().open_session()
            self.channel.settimeout(args['to'] if 'to' in args else 1.0)
            #self.channel.get_pty()
            if 'program' in target:
                if 'ASLR' in args and args['ASLR']==False:
                    target['program'] = 'ulimit -s unlimited; %s setarch i386 -R %s' % (env_str, target['program'])
                elif env_str:
                    target['program'] = '%s %s' % (env_str, target['program'])
                self.channel.exec_command(target['program'])

            self.timeout = socket.timeout

    def set_show(self, mode=None):
        if mode in ['RAW', 'HEXDUMP']:
            self.show_mode = mode
        else:
            self.show_mode = None
            
        if self.show_mode=='HEXDUMP' and self.hexdump is None:
            try:
                from hexdump import hexdump
                self.hexdump = hexdump
            except:
                fail('module "hexdump" is not importable')
                self.show_mode = None;

    def show(self, c, t, data):
        sys.stdout.write(template % (console['c_color'](c), '\n[%s]' % t, ''))
        if self.show_mode=='RAW':
            sys.stdout.write(data)
        elif self.show_mode=='HEXDUMP':
            sys.stdout.write('\n')
            self.hexdump(data)

    def set_nonblocking(self,fh):
        import fcntl

        fd = fh.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        
    def send(self,msg):
        if self.show_mode is not None:
            self.show('C', 'SEND', msg)
            
        try:
            if self.mode=='SOCKET':
                self.sock.sendall(msg.encode())
            elif self.mode=='LOCAL':
                self.proc.stdin.write(msg.encode())
            elif self.mode=='SSH':
                self.channel.sendall(msg.encode())
        except:
            self.is_alive = False

    def sendln(self,msg):
        self.send(msg+'\n')

    def sendnull(self,msg):
        self.send(msg+'\x00')
        
    def read(self,num=4):
        sleep(0.05)
        rsp = ''
        try:
            if self.mode=='SOCKET':
                rsp = self.sock.recv(num)
            elif self.mode=='LOCAL':
                rsp = self.proc.stdout.read(num)
            elif self.mode=='SSH':
                rsp = self.channel.recv(num)
        except:
            pass

        if self.show_mode is not None:
            self.show('Y', 'READ', rsp)
        return rsp

    def read_all(self):
        sleep(0.05)
        try:
            rsp = ''
            while True:
                if self.mode=='SOCKET':
                    rcv = self.sock.recv(512)
                elif self.mode=='LOCAL':
                    rcv = self.proc.stdout.read()
                elif self.mode=='SSH':
                    rcv = self.channel.recv(512)

                if rcv:
                    rsp += rcv
                else:
                    break
        except:
            pass
        
        if self.show_mode is not None:
            self.show('Y', 'READ', rsp)
        return rsp

    def read_until(self,term='\n',contain=True):
        rsp = b''
        while not (rsp.decode().endswith(term)):
            try:
                if self.mode=='SOCKET':
                    rsp += self.sock.recv(1)
                elif self.mode=='LOCAL':
                    rsp += self.proc.stdout.read(1)
                elif self.mode=='SSH':
                    rsp += self.channel.recv(1)
            except self.timeout:
                if not (rsp.decode().endswith(term) if isinstance(term, str) else any([rsp.decode().endswith(x) for x in term])):
                    warn('read_until: not end with "%s"(timeout)' % str(term).strip())
                break
            except:
                sleep(0.05)
        
        if self.show_mode is not None:
            self.show('Y', 'READ', rsp)
            
        if not contain:
            rsp = rsp.decode()[:rsp.decode().rfind(term)]
        return rsp

    def __del__(self):
        if self.mode=='SOCKET':
            self.sock.close()
            if self.disp:
                proc('Network Disconnect...')
        elif self.mode=='LOCAL':
            if self.wait:
                self.proc.communicate(None)
            elif self.proc.poll() is None:
                self.proc.terminate()
            if self.disp:
                proc('Program Terminate...')
        elif self.mode=='SSH':
            self.channel.close()
            if self.disp:
                proc('Session Disconnect...')
                
        if self.disp:
            input('Enter any key to close...')