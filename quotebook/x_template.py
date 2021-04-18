#!/usr/bin/env python
"""Exploit script template."""
from pwn import *

context.log_level = 'info'

BINARY = './quotebook'
HOST = '167.71.54.126'
PORT = 4444


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


p = remote(HOST, PORT)
p.interactive()
