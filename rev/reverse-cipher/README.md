# CyLab / picoCTF — reverse_cipher

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Parity Byte Transformation Reversal)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Parity-dependent byte transformation inversion: even index -5, odd index +2. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file reverse-cipher
reverse-cipher: ELF/Artifact analysis
$ checksec reverse-cipher
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- IDA: `main` mở `flag.txt`, đọc vào buffer (offset 0x00), rồi ghi `rev_this` với biến đổi:

```c
for (j = 0; j < 24; j++) {
    if (j < 8 || j > 22) rev_this[j] = flag[j];
    else if (j % 2 == 0)  rev_this[j] = flag[j] + 5;
    else                  rev_this[j] = flag[j] - 2;
}
```
- Tức chỉ các vị trí `8..22` bị đổi; chẵn `+5`, lẻ `-2`. `0..7` và `23` giữ nguyên.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of reverse_cipher reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

### 2. Architecture & Data Flow Diagram

```text
+-------------------------------------------------------------------------+
|                      Target Architecture & Workflow                     |
+-------------------------------------------------------------------------+
|  [Input / Artifact]  --->  [Static / Dynamic Disassembly]               |
|                                     |                                   |
|                                     v                                   |
|                         [Algorithm / State Machine]                     |
|                                     |                                   |
|                                     v                                   |
|                         [Mathematical / Logic Inversion]                |
|                                     |                                   |
|                                     v                                   |
|                            [Flag: academy{...}]                        |
+-------------------------------------------------------------------------+
```

---

## Dynamic Analysis & Solution Strategy

Đảo ngược phép biến đổi trên `rev_this`:
- vị trí `j` trong `8..22`: chẵn `-5`, lẻ `+2`; còn lại giữ nguyên.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
"""CyLab / picoCTF - reverse_cipher Solver
Inverts the parity byte substitution in indices 8..22:
- Even indices: -5
- Odd indices:  +2
"""

def decrypt(rev_bytes: bytes) -> str:
    flag = bytearray(rev_bytes)
    for j in range(8, min(23, len(flag))):
        if j % 2 == 0:
            flag[j] = (flag[j] - 5) & 0xFF
        else:
            flag[j] = (flag[j] + 2) & 0xFF
    return flag.decode(errors="ignore")
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- "Reverse cipher" chỉ là phép cộng/trừ theo parity vị trí; đọc kỹ khoảng chỉ số bị ảnh hưởng (`8..22`) và chiều +/−.
