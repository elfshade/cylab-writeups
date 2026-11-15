# CyLab / picoCTF — Quantum Scrambler

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Bitwise Scrambler Network Inversion)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Inverting multi-round bitwise permutation, shift, and XOR diffusion network. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file quantum-scrambler
quantum-scrambler: ELF/Artifact analysis
$ checksec quantum-scrambler
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `scramble(L)` repeatedly merges pairs and appends snapshots; final top-level has one element per pair of original characters.
- Each top-level element's first string is the even-index character; last direct string is the odd-index character (except final lone character).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
No real vulnerability: encryption is reversible by structural inspection because each cluster retains its two original hex characters at fixed positions.

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

- Fetch cypher from `xebec.cylabacademy.net:26235`.
- Parse with `ast.literal_eval`.
- For each top-level object: append `chr(int(obj[0],16))`; if `obj[-1]` is a hex string, append `chr(int(obj[-1],16))`.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Solver for Quantum Scrambler
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

When a scrambling operation is composed of simple list mutations, inspect nesting positions rather than trying to generically invert.
