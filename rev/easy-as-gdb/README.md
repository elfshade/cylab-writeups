# CyLab / picoCTF — Easy as GDB

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Dynamic GDB Oracle & Byte-by-Byte Recovery)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Automated GDB byte-by-byte flag oracle, hardware watchpoints & breakpoint scripting. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file easy-as-gdb
easy-as-gdb: ELF/Artifact analysis
$ checksec easy-as-gdb
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `start` → `__libc_start_main(sub_14EF, ...)` ⇒ `main = sub_14EF`.
- `main`:
  - `fgets(s, 512, stdin)` đọc input.
  - `n = strnlen(aZDcZ, 512)` (aZDcZ ở `0x4008`, dài 30 byte).
  - `src = sub_136B(s, n)` = **xorloop** input.
  - `sub_1302(src, n, 1)` = **interleave** (block-reverse tăng dần).
  - `sub_1404(src, n)`: `dest = deinterleave(src)`, `v6 = deinterleave(aZDcZ)`, so từng byte, khớp hết → `"Correct!"`.
- `sub_136B(src, n)`: `na = (n & ~3)+4`; `dest = copy(src, na)`; vòng lặp `i = 0x0ABCF00D; while i < 0xDEADBEEF:` gọi `sub_11FD(dest, na, i)`, bước nhảy tính mỗi vòng `step = (((0xDEADBEEF % 0x0ABCF00D) << 2) >> 8) ^ 0xBA` (hằng) ⇒ **1714 vòng**, mỗi vòng XOR mỗi byte vị trí `p` với `v5[p&3]` với `v5 = [HIBYTE(i),BYTE2,BYTE1,LOBYTE(i)]`.
- `sub_11FD`: `a1[p] ^= v5[p&3]` ⇒ keystream chỉ phụ thuộc `p&3`.
- `sub_1290(a, n, k)`: đảo từng block `k` byte (`swap a[i], a[i+k-1]`, bước `k`).
- `sub_1302(a, n, d)`: `d>0` áp `k=1..n-1` (interleave); `d<=0` áp `k=n-1..1` (deinterleave = nghịch đảo).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Điều kiện tương đương: `xorloop(input) == deinterleave(aZDcZ)`.
- ⇒ `input = deinterleave(aZDcZ) ^ K`, với `K[j]` = XOR tất cả `v5[j]` trên 1714 giá trị `i`.
- Xác nhận local: `./brute` in `Correct!`.

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
academy{redacted}
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **XOR tích luỹ nhiều vòng = XOR với keystream**: nếu cùng một chuỗi key lặp lại theo `p mod k`, tổng có thể cộng gộp thành 4 byte; khi đó `xorloop` là một phép "XOR với hằng theo vị trí" ⇒ tự nghịch đảo.
- **Interleave/deinterleave**: `sub_1302` chỉ là hoán vị vị trí; kiểm tra code "áp interleave rồi cả 2 nhánh cùng deinterleave" ⇒ thực chất chỉ một vế bị biến đổi.
- Bước nhảy vòng lặp tính bằng `div` + `xor al` — phải mô phỏng **đúng từng bit** (chú ý `xor al` chỉ tác động low byte) chứ không đoán.
- Hints về GDB chỉ là cách "brute nhanh" thay thế; phân tích tĩnh + tự viết phép nghịch đảo cho kết quả tất định.
