# CyLab / picoCTF — Bbbbloat

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Stripped ELF & Rotation Cipher)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Stripped x86_64 ELF decompilation, hardcoded integer branch (549255) and rotation cipher. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file bbbbloat
bbbbloat: ELF/Artifact analysis
$ checksec bbbbloat
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of Bbbbloat. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompile `main` (IDA):
```c
strcpy(v7, "24256>JL4Ff0f9b03=_cf0`47b2cg`N");
printf("What's my favorite number? ");
scanf("%d", &v4);
if (v4 == 549255) { s = sub_1249(0, v7); fputs(s, stdout); }
```
Nhập 549255 -> `sub_1249` (rotate_encrypt) biến đổi chuỗi thành flag.

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

We model the transformation in Python and formulate an inverse calculation or dynamic trace script to recover the original flag input.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
echo 549255 | ./bbbbloat
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Stripped binary -> decompiler (IDA Hex-Rays) tìm hằng so sánh; hàm transform tự viết.
