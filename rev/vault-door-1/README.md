# CyLab / picoCTF — vault-door-1

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Sparse Character Index Reconstruction)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Java source code analysis, reconstructing 32-character string from sparse index checks. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file vault-door-1
vault-door-1: ELF/Artifact analysis
$ checksec vault-door-1
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Java source: `checkPassword` so sánh password 32 ký tự qua loạt `password.charAt(i) == 'x'` rải rác (không theo thứ tự).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Không có lỗ hổng runtime — flag hardcode dưới dạng các điều kiện `charAt`.

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

- Gom từng vị trí `password.charAt(i)=='x'` thành mảng 32 ký tự rồi join:
```python
c = ['?']*32
c[0]='d'; c[1]='3'; c[2]='5'; c[3]='c'; c[4]='r'; c[5]='4'; c[6]='m'; c[7]='b'
c[8]='l'; c[9]='3'; c[10]='_'; c[11]='t'; c[12]='H'; c[13]='3'; c[14]='_'; c[15]='c'
c[16]='H'; c[17]='4'; c[18]='r'; c[19]='4'; c[20]='c'; c[21]='T'; c[22]='3'; c[23]='r'
c[24]='5'; c[25]='_'; c[26]='1'; c[27]='7'; c[28]='9'; c[29]='f'; c[30]='b'; c[31]='d'
print("".join(c))
```

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
c = ['?']*32
c[0]='d'; c[1]='3'; c[2]='5'; c[3]='c'; c[4]='r'; c[5]='4'; c[6]='m'; c[7]='b'
c[8]='l'; c[9]='3'; c[10]='_'; c[11]='t'; c[12]='H'; c[13]='3'; c[14]='_'; c[15]='c'
c[16]='H'; c[17]='4'; c[18]='r'; c[19]='4'; c[20]='c'; c[21]='T'; c[22]='3'; c[23]='r'
c[24]='5'; c[25]='_'; c[26]='1'; c[27]='7'; c[28]='9'; c[29]='f'; c[30]='b'; c[31]='d'
print("".join(c))
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- Pattern vault-door 1: biến các điều kiện so sánh rời rạc thành mảng char theo vị trí rồi nối lại.
- Luôn đọc kỹ `charAt(i)` — đếm index từ 0.
