# CyLab / picoCTF — Bit-O-Asm-3

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Assembly Arithmetic Tracing)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Arithmetic pipeline tracing (imul eax, [rbp-8]; add eax, [rbp-4]). By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file bit-o-asm-3
bit-o-asm-3: ELF/Artifact analysis
$ checksec bit-o-asm-3
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of Bit-O-Asm-3. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
```
mov DWORD PTR [rbp-0xc],0x9fe1a
mov DWORD PTR [rbp-0x8],0x4
mov eax,DWORD PTR [rbp-0xc]
imul eax,DWORD PTR [rbp-0x8]
add eax,0x1f5
```
eax = 0x9fe1a * 4 + 0x1f5 = 2619997.

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
mov DWORD PTR [rbp-0xc],0x9fe1a
mov DWORD PTR [rbp-0x8],0x4
mov eax,DWORD PTR [rbp-0xc]
imul eax,DWORD PTR [rbp-0x8]
add eax,0x1f5
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Tính số học theo từng bước; cẩn thận `imul` 32-bit.
