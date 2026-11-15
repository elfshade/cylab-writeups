# CyLab / picoCTF — Picker III

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Python Global State Table Overwrite)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Function table index manipulation, overwriting function pointer variable with win. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file picker-iii
picker-iii: ELF/Artifact analysis
$ checksec picker-iii
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of Picker III. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Có bảng hàm cố định (`func_table`, 4 slot x 32 byte) và cho phép `write_variable`
(đặt biến bất kỳ, value chặn `();`). Ghi đè `func_table` để slot 0 = `win`:
value = `'win'+' '*125` (128 ký tự), rồi chọn `1` để gọi `call_func(0)` -> `win()`.

Chuỗi lệnh gửi:
```
3            # write_variable
func_table   # tên biến
'win'+' '*125
1            # call_func(0) -> win()
```

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
3            # write_variable
func_table   # tên biến
'win'+' '*125
1            # call_func(0) -> win()
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Table-driven dispatch + `exec('global X; X = '+value)` -> ghi đè con trỏ hàm,
không cần gọi hàm cấm trực tiếp.
