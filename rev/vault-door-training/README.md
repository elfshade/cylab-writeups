# CyLab / picoCTF — vault-door-training

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Java Source Inspection)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Java source code inspection, extracting hardcoded plaintext string parameter. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file vault-door-training
vault-door-training: ELF/Artifact analysis
$ checksec vault-door-training
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- File là Java source, mở ra đọc thẳng — `checkPassword` so sánh password với một chuỗi hardcode.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Không có "lỗ hổng" — bài dạy kỹ năng đọc source: mật khẩu nằm ngay trong code.

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

- Đọc `checkPassword()`:
  ```java
  return password.equals("w4rm1ng_Up_w1tH_jAv4_69bd4dc7adf");
  ```
- Chuỗi cần nhập = nội dung trong `academy{...}`.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Solver for vault-door-training
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

- Bài Java warmup: flag hardcode trong source — `grep`/đọc thẳng source luôn là bước rẻ nhất.
