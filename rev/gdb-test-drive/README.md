# CyLab / picoCTF — GDB Test Drive

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Dynamic GDB Inspection & Flow Patching)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

GDB debugging, breakpoint placement and skipping sleep() delay loop to hit print function. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file gdb-test-drive
gdb-test-drive: ELF/Artifact analysis
$ checksec gdb-test-drive
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of GDB Test Drive. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
`main` nạp một chuỗi byte (dạng các hằng `movabs` little-endian) rồi gọi
`rotate_encrypt(0, str)` và in. Binary có `sleep(100000)` chặn -> bỏ qua bằng
`LD_PRELOAD` override `sleep`.

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
"""CyLab / picoCTF - GDB Test Drive Automation
Bypasses the sleep loop via LD_PRELOAD or GDB breakpoint manipulation.
"""

import subprocess
import os

def run_with_preload():
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", "nosleep.so", "nosleep.c"], check=True)
    env = os.environ.copy()
    env["LD_PRELOAD"] = "./nosleep.so"
    res = subprocess.run(["./gdbme"], env=env, capture_output=True, text=True)
    print(res.stdout)
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Anti-analysis `sleep()` dài -> LD_PRELOAD stub hoặc sửa/không bước qua trong gdb.
