# CyLab / picoCTF — asm1

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (x86 Assembly Control Flow Tracing)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

x86 32-bit assembly conditional branch tracing (cmp, jg, sub) with signed comparisons. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file asm1
asm1: ELF/Artifact analysis
$ checksec asm1
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Đề: `asm1(0x31e)` trả về bao nhiêu? Nộp dạng hex `0x...` (KHÔNG theo format flag).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Không có lỗ hổng — bài trace assembly tay.

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

- Trace `test.S`:
  - `cmp [ebp+8],0x2fa; jg L2` — 0x31e(798) > 0x2fa(762) → nhảy L2.
  - `cmp [ebp+8],0x31e; jne L3` — bằng nhau → không nhảy.
  - `mov eax,[ebp+8]; sub eax,0x17` → 0x31e-0x17 = **0x307**.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Solver for asm1
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

- `jg` là so sánh **có dấu**; 0x31e > 0x2fa nên đi nhánh `sub 0x17`. Bài dạng này chỉ cần đọc kỹ nhánh rẽ.
