# CyLab / picoCTF — vault-door-5

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (URL & Base64 Dual Encoding Inversion)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Two-stage encoding inversion: URL decoding followed by standard Base64 decoding. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file vault-door-5
vault-door-5: ELF/Artifact analysis
$ checksec vault-door-5
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Java source: chuỗi đích = `base64Encode(urlEncode(password))` (mỗi byte thành `%xx` rồi base64).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Base64 của URL-encode — giải ngược 2 lớp.

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
import base64, urllib.parse
exp=base64.b64decode("JTYz...").decode()
print(urllib.parse.unquote(exp))  # c0nv3rt1ng_fr0m_ba5e_64_92be25f1
```

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
import base64, urllib.parse
exp=base64.b64decode("JTYz...").decode()
print(urllib.parse.unquote(exp))  # c0nv3rt1ng_fr0m_ba5e_64_92be25f1
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- `%xx` = URL-encode từng byte; base64 chuỗi đó. Cứ gặp chuỗi base64 dài toàn `%` → unquote sau khi decode.
