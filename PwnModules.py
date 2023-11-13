"""
@author: RedLeaves
@date: 2023-4-24
Pwntools-Extern Functions
开源包，任何人都可以使用并修改！
"""

from LibcSearcher import *
from pwn import *

__version__ = '1.3'

def leak_addr(i, io_i):
	if i == 0:
		address_internal = u32(io_i.recv(4))
		return address_internal
	if i == 1:
		address_internal = u64(io_i.recvuntil(b'\x7f')[:6].ljust(8, b'\x00'))
		return address_internal
	if i == 2:
		address_internal = u64(io_i.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
		return address_internal

def libc_remastered(func, addr_i):
	libc_i = LibcSearcher(func, addr_i)
	libc_base_i = addr_i - libc_i.dump(func)
	sys_i = libc_base_i + libc_i.dump('system')
	sh_i = libc_base_i + libc_i.dump('str_bin_sh')
	return libc_base_i, sys_i, sh_i


def libc_remastered_ol(func, addr_i):
	libc_i = LibcSearcher(func, addr_i, online=True)
	libc_base_i = addr_i - libc_i.dump(func)
	sys_i = libc_base_i + libc_i.dump('system')
	sh_i = libc_base_i + libc_i.dump('str_bin_sh')
	return libc_base_i, sys_i, sh_i

def debug(io):
	gdb.attach(io)
	pause()

def get_int_addr(io, num):
	return int(io.recv(num), 16)

def show_addr(msg, *args, **kwargs):
    msg = f'\x1b[01;38;5;90m{msg}\x1b[0m'
    colored_text = '\x1b[01;38;5;90m' + ': ' + '\x1b[0m'

    for arg in args:
        hex_text = hex(arg)
        colored_hex_text = f'\x1b[01;38;5;90m{hex_text}\x1b[0m'
        print(f"{msg}{colored_text}{colored_hex_text}")

    for key, value in kwargs.items():
        hex_text = hex(value)
        colored_hex_text = f'\x1b[01;38;5;90m{hex_text}\x1b[0m'
        print(f"{msg}{colored_text}{key}{colored_hex_text}")

