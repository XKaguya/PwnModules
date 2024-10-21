## An Open-Source Pwntools External functions library.

## Usage:

1. `pip install PwnModules`
2. `from PwnModules import *`

## Features:

### Format String Helper

#### fmt_canary

* **Prototype:** `fmt_canary()`

* **Parameters:**

  * While using `fmt_canary()` function, It will automaticly exploit the Canary's offset on the stack.

  * Be advised, This function only works for simple problems.

#### fmtstraux

* **Prototype:**  `fmtstraux(int size, bool x64)`

* **Parameters:**

  * `Size`  The number of `%p`

  * `x64 ` The system arch

#### fmtgen

* **Prototype:** `fmtgen(char character, int size, int num, char separator)`

* **Parameters:**

  * `character`  By default `p`

  * `size`  The number of `%character`

  * `num`  From `num`  start

  * `separator` by default `-`

#### fmtstr_payload_64

* **Prototype:** `fmtstr_payload_64(int offset, dictionary writes, int numbwritten=0, write_size='byte')`
* Same as the pwntools's `fmtstr_payload`  , But from other ppl's hand.

### IO_FILE_plus_struct

* The extern of the default IO_FILE_Struct.
* Supports `House of Apple`

### Basic Functions

#### debug

* **Prototype:** `debug(IOStream io, int breakpoint)`
* **Parameters:**
  * `io`  Ignorable, Will be fill by global `ioStream`
  * `breakpoint`  Ignorable, Will be `None` by default.

#### get_libc_base

* **Prototype:** `get_libc_base(string name, int addr)`
* **Parameters:**
  * `name` The name of leaked function.
  * `addr` The Address of leaked function.

#### get_utils

* **Prototype:** `get_utils(string binaryPath, bool local, string ip, int port)`
* **Parameters:**
  * `binaryPath` The path of binary file.
  * `local` Is using remote connect or local file.
  * `ip` The remote host ip address.
  * `port` The remote host ip port.

#### init_env

* **Prototype:** `init_env(int arch, string logLevel)`
* **Parameters:**
  * `arch` The context system arch.
  * `logLevel` The context log level.

#### leak_addr

* **Prototype:** `leak_addr(int i)`
* **Parameters:**
  * `i` Mode.
    * Mode 0 ---- > x86
    * Mode 1 ---- > Big Endian for x64
    * Mode 2 ---- > Little Endian for x64
    * Mode 3 ---- > Directly receive 8 bytes.

#### libc_search

* **Prototype:** `libc_search(string funcName, int leakedAddr, bool onlineMode)`
* **Parameters:**
  * `funcName` The leaked function name.
  * `leakedAddr` The leaked function address.
  * `onlineMode` Decides the function if going to search online.

#### payload_generator

* **Prototype:** `payload_generator(int paddingSize, int libcBaseAddr, bool stackAligned)`
* **Parameters:**
  * `paddingSize` The size of padding.
  * `libcBaseAddr` The libc base address.
  * `stackAligned` Is the stack aligned needed.

#### recv_int_addr

#### Ret2Csu

* **Prototype:** `Ret2Csu(payload, r12, rdi, r14, r13, csu_front, csu_rear, syscallAddr)`

* **Parameters:**
  * `payload`: The forward Payload.
  *  `r12`, `rdi`, `r14`, `r13`: Register values.  
    * `R12`  `call [r12+rbx*8]`
    * `RDI`  The first argument.
    * `R14`  The second argument.
    * `R15`  The third argument.
  *  `csu_front`, `csu_rear`: Addresses for the CSU gadget.  
  * `syscallAddr`: The address for the syscall gadget.

#### search_one_gadget

* **Prototype:**  `search_one_gadget(int index)`
* **Parameters:**
  * `index` The index of one_gadget list.

#### search_reg_gadgets

* **Prototype:** `search_reg_gadgets(string reg)`
* **Parameters:**
  * `reg` The register or string.

#### show_addr

* **Prototype:**  `show_addr(string msg, int addr)`
* **Parameters:**
  * `msg` The output msg.
  * `addr` The addr that will be print.

#### sym_addr

* **Prototype:**  `sym_addr(string sym)`
* **Parameters:** 
  * `sym` The target function's name.  By default this function will return `libcBaseAddress, system, binsh`

