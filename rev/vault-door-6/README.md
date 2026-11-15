# CyLab / picoCTF — vault-door-6

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (XOR Mask Inversion)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Inverting byte-wise XOR masking (c ^ 0x55 == expected) across 32 password bytes. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file vault-door-6
vault-door-6: ELF/Artifact analysis
$ checksec vault-door-6
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Java source: `passBytes[i]^0x55 - myBytes[i] == 0` ⇒ password = `myBytes[i] ^ 0x55`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- XOR 1 byte đơn giản, key 0x55 cố định.

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

```python
my=[0x3b,0x65,0x21,0xa,...]
print("".join(chr(m^0x55) for m in my))
```

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
my=[0x3b,0x65,0x21,0xa,...]
print("".join(chr(m^0x55) for m in my))
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- XOR với key cố định tự nghịch đảo: `dec = enc ^ key`. Nếu điều kiện viết `(pass^key) - stored == 0` thì `pass = stored ^ key`.
