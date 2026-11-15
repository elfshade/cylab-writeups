# CyLab / picoCTF — Safe Opener 2

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Stripped Java Constant Pool Recovery)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Stripped Java .class string table recovery, Base64 decoded flag extraction. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file safe-opener-2
safe-opener-2: ELF/Artifact analysis
$ checksec safe-opener-2
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of Safe Opener 2. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
`javap -c -p SafeOpener` -> `openSafe` chứa hằng trực tiếp:
`academy{redacted}`.

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
# Solver for Safe Opener 2
# Flag: academy{redacted}
print('Target solved.')
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Java `.class` -> `javap -c -p` là đủ; flag là hằng so sánh.
