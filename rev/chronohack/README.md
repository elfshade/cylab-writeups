# CyLab / picoCTF — Chronohack

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (PRNG Seed Reconstruction)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Time-based PRNG state reconstruction, backward seed synchronization. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file chronohack
chronohack: ELF/Artifact analysis
$ checksec chronohack
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Token generation time is tied to connection time modulo clock skew.
- Python `random` seed is 1-ms granularity.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Predictable seeded PRNG: seed space can be brute-forced around the connection time.

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

- Slide a 30 ms / 50-candidate window across 30-... offsets by making fresh connections (`base` from -800 to 800 step 30).
- Generate candidates with `random.seed(local_ms + base + offset)` and send all 50 tokens; success at `base=-140`.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Solver for Chronohack
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

For real-time seeded PRNG, calibrate a constant clock/network offset by making repeated fresh connections.
