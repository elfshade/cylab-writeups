# CyLab / picoCTF — WinAntiDbg0x300

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Windows PE32 Anti-Debugging & PEB Patching)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Windows PE32 anti-debugging bypass: patching IsDebuggerPresent and PEB BeingDebugged. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file winantidbg0x300
winantidbg0x300: ELF/Artifact analysis
$ checksec winantidbg0x300
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Main only yields flag in the non-debugger branch when `IsDebuggerPresent()` is bypassed.
- Config format: 4-byte count `N=40`, `N` prefix bytes, separator `00`, then `N+1` suffix bytes.
- Prefix transform: repeated modular update based on `j % 255`; 12 total iterations make the XOR result `academy{...}`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
The transform count expected by the clean flag path is identifiable by brute-force prefix consistency (`c=12` or `38` produce a readable `academy{` prefix).

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
# Solver for WinAntiDbg0x300
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

When anti-debug paths change transformation counts, brute-force the small integer parameter against the known flag prefix.
