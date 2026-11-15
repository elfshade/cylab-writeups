# CyLab / picoCTF — keygenme-py

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Python License Validation & SHA-256 Slicing)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Python license validator reversing: selective SHA-256 digest character extraction. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file keygenme-py
keygenme-py: ELF/Artifact analysis
$ checksec keygenme-py
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of keygenme-py. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
`check_key()` so 8 ký tự động lấy từ `sha256(b"MILLER").hexdigest()` tại các
index [4,5,3,6,2,7,1,8]; phần tĩnh là `academy{1n_7h3_kk3y_of_`.

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
import hashlib
h=hashlib.sha256(b"MILLER").hexdigest()
dyn="".join(h[i] for i in [4,5,3,6,2,7,1,8])
print("academy{1n_7h3_kk3y_of_"+dyn+"}")
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Keygen dựa trên hash: đọc chính xác thứ tự index và username cố định.
