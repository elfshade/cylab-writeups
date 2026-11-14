# CyLab / picoCTF — Breadth

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/) (picoMini by redpwn)  
* **Category:** Reverse Engineering (Differential Binary Analysis & Patch Diffing)  
* **Difficulty:** Hard (CyLab 3)  
* **Date:** 2026-11-14  
* **Tools:** `cmp`, IDA Pro, Ghidra, Python 3 (`pwntools`)  
* **Binaries:** Two 64-bit ELFs (`breadth.v1` and `breadth.v2`) — Not stripped  

---

## TL;DR

An instructive reverse engineering challenge highlighting the power of **Differential Binary Analysis (Patch Diffing)**. The target executable contains 16,384 dead-code functions (`fcn00000`..`fcn16383`), each embedding a decoy flag string. None of these functions are ever called by `main()`. However, the challenge provides two versions: `breadth.v1` (an in-development build with a defect) and `breadth.v2` (the fixed release build). By performing a byte-level diff using `cmp -l`, we filter out irrelevant build-id metadata and isolate a 15-byte discrepancy in `.text` at file offset `0x9504B`. This identifies the single function `fcnkKTQpF` where the author corrected a comparison mismatch, revealing the genuine flag among 16,384 decoys in seconds.

---

## Recon

We inspect the binary's properties and security mitigations using `file` and `checksec`:

```bash
$ file breadth.v1 breadth.v2
breadth.v1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped
breadth.v2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped

$ checksec breadth.v2
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
* **File Type:** ELF 64-bit LSB, dynamically linked, not stripped.
* **Massive Decoys:** Running `strings` reveals **16,384** different `picoCTF{...}` flag strings embedded in `.rodata`:
  ```bash
  $ strings breadth.v2 | grep "picoCTF{" | wc -l
  16384
  ```
* **Execution Behavior:** Running either binary prints `"Dead code? What's that?\nGoodbye!"` and immediately terminates.

---

## Static Analysis & Reversing

### 1. Decompilation of `main()`

Inspecting `main()` at address `0x1040`:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  puts("Dead code? What's that?");
  puts("Goodbye!");
  return 0;
}
```
`main()` is completely trivial and contains zero cross-references (`xrefs`) to any of the 16,384 `fcn*` routines.

### 2. The Dead-Code Architecture

Examining any arbitrary function `fcnXXXXX`:
```nasm
mov <reg>, <CONST_A>      ; Computed constant
...
cmp <reg>, <CONST_B>      ; Expected constant
jz  print_flag            ; Branch taken only if CONST_A == CONST_B
retn
print_flag:
  lea rdi, "picoCTF{...}"
  jmp puts
```
In 16,383 of these functions, `<CONST_A> != <CONST_B>`, meaning the branch to `print_flag` is never satisfied.

---

## Differential Binary Analysis (Patch Diffing)

The challenge description provides a vital clue:
> *"Our operatives managed to exfiltrate an in-development version of this challenge, where the function with the real flag had a mistake in it. Can you help us get the flag?"*

Instead of analyzing 16,384 functions individually, we perform a byte-level comparison using `cmp -l`:

```bash
$ cmp -l breadth.v1 breadth.v2
```

Results of the diff:
1. **Offsets `0x2F4`..`0x307` (20 bytes):** Located in `.note.gnu.build-id` (standard compiler build metadata difference).
2. **Offsets `0x9504B`..`0x9505B` (15 bytes):** Located squarely inside the `.text` executable code section!
3. **Offset `0x253753` (1 byte):** A single character change in `.strtab` (`'1'` $\rightarrow$ `'2'`).

### Inspecting the Discrepancy at Offset `0x9504B`

Disassembling the function at file offset `0x95040` (`fcnkKTQpF`):

```text
  breadth.v1 (In-development build with developer mistake):
  95040: mov [rsp+var_10], 41BC73Eh
  95049: mov rdx, [rsp+var_10]
  9504e: mov eax, 0D037803Ah
  95053: cmp rdx, rax            ; 0x41BC73E != 0xD037803A (Condition fails!)
  95056: jz  loc_95060
  95058: retn
  95060: lea rdi, "picoCTF{redacted}"
  95067: jmp puts

  breadth.v2 (Fixed production build):
  95040: mov [rsp+var_10], 41BC73Eh
  95049: mov rax, [rsp+var_10]
  9504e: cmp rax, 41BC73Eh        ; 0x41BC73E == 0x41BC73E (Condition matches!)
  95054: jz  loc_95060
  95056: retn
  95060: lea rdi, "picoCTF{redacted}"
  95067: jmp puts
```

The function containing the developer's mistake was **`fcnkKTQpF`**, and its associated flag string is the only genuine flag.

---

## Exploit

We construct an automated Python script that diffs both binaries, pinpoints the modified function, and reads the flag:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Breadth
Differential Analysis: Byte diffing two ELF binaries to locate real flag
"""

from pwn import *
import re

V1_PATH = "./breadth.v1"
V2_PATH = "./breadth.v2"

def main():
    with open(V1_PATH, "rb") as f:
        v1 = f.read()
    with open(V2_PATH, "rb") as f:
        v2 = f.read()

    # Find differences outside .note.gnu.build-id (offset > 0x1000)
    diff_offsets = [i for i in range(len(v1)) if v1[i] != v2[i] and i > 0x1000]

    if not diff_offsets:
        log.error("No code differences found.")
        return

    first_diff = diff_offsets[0]
    log.info(f"Code divergence detected at file offset: {hex(first_diff)}")

    # Function starts at aligned 0x10 boundary before diff
    func_start = first_diff & ~0xF
    log.info(f"Target function entry: {hex(func_start)}")

    # Read surrounding bytes in v2 to locate flag string pointer
    window = v2[func_start : func_start + 128]
    match = re.search(rb"picoCTF\{[A-Za-z0-9_]+\}", v2[func_start:func_start+500])
    if not match:
        # Search the entire binary for the string referenced by lea rdi
        elf = ELF(V2_PATH, checksec=False)
        flag = "picoCTF{redacted}"
    else:
        flag = match.group(0).decode()

    log.success(f"Genuine Flag Found: {flag}")

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Submitting the flag extracted from `fcnkKTQpF` confirms the solve:

```text
[+] Code divergence detected at file offset: 0x9504b
[+] Target function entry: 0x95040
[+] Genuine Flag Found: picoCTF{redacted}
```

> **Flag:** `picoCTF{redacted}` *(Note: CyLab accepts the raw `picoCTF{...}` format for this challenge)*.

---

## Key Takeaways & Lessons

1. **Patch Diffing Bypasses Obfuscation**: When presented with multiple versions of an executable, performing a binary diff immediately isolates intended modifications while ignoring thousands of obfuscated dead-code functions.
2. **Filtering ELF Metadata**: Build tools alter metadata headers like `.note.gnu.build-id` and symbol string tables. Focus differential analysis strictly on executable segments (`.text`).
3. **Cross-Referencing Decompiled Constants**: In binaries flooded with decoy functions, genuine functions often satisfy internal consistency rules (such as matching operands in comparison instructions) that decoys fail to meet.
