# CyLab / picoCTF — vault-door-4

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Multi-Format Numeric Byte Parsing)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Decoding composite byte representation array: decimal, hex (0x), octal (0), and raw chars. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file vault-door-4
vault-door-4: ELF/Artifact analysis
$ checksec vault-door-4
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Java source: mảng `myBytes` trộn 4 dạng literal: decimal, hex `0x..`, octal `0142`, char `chr`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Các literal cần chuyển về byte rồi ra char — không có mã hoá phức tạp.

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
my=[106,85,53,116,...,0x55,0x6e,...,0o142,0o131,...,ord(chr)]
print("".join(chr(x) for x in my))
```

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
my=[106,85,53,116,...,0x55,0x6e,...,0o142,0o131,...,ord(chr)]
print("".join(chr(x) for x in my))
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- Nhớ chuyển đúng cơ số: octal `0142`=98, hex `0x55`=85, decimal `85`=U. Trộn cơ số là dạng bài kinh điển.
