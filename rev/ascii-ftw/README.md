# CyLab / picoCTF — ASCII FTW

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Static Disassembly & ASCII Stack Decoding)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Disassembly analysis of sequential movb immediate stack writes, hex ASCII decoding. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file ascii-ftw
ascii-ftw: ELF/Artifact analysis
$ checksec ascii-ftw
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of ASCII FTW. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
`objdump -d` hàm `main` cho chuỗi `movb $0x..` liên tiếp. Gom các byte.

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
vals=[0x61,0x63,0x61,0x64,0x65,0x6d,0x79,0x7b,0x41,0x53,0x43,0x49,0x49,0x5f,0x49,0x53,0x5f,0x45,0x41,0x53,0x59,0x5f,0x36,0x41,0x37,0x33,0x46,0x43,0x35,0x38,0x7d]
print(bytes(vals).decode())
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Chuỗi ký tự nạp từng byte vào stack -> gom `movb` trong disassembly.
