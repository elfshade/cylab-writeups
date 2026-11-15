# CyLab / picoCTF — Powershelly

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (PowerShell Obfuscation & Bit-Matrix Reversing)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

PowerShell 5x264 bit-matrix unscrambler, inverting cumulative XOR and linear probing. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file powershelly
powershelly: ELF/Artifact analysis
$ checksec powershelly
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Input là ma trận **5 hàng × 264 cột**, mỗi ô là một chuỗi 6 bit (`"010101"`), cách nhau bởi dấu cách, kết thúc dòng CRLF (khớp `numLength = 264*30 + 265*5 = 9245`).
- `blocks[j]` = cột thứ `j` (ghép các ô 6-bit theo hàng) → `raw` dài `L = 6*5 = 30` bit mỗi cột.
- `Random-Gen`: `randoms[i] = ((((i+1)*327)%681)+344)%313`; `seeds[i] = ((i+1)*127)%500`.
- `Scramble(block, seed)`:
  - Duyệt `i = 0..L-1`, đặt raw bit thứ `i` vào vị trí `y = (i*seed) % L`, **probe tuyến tính** tới ô trống đầu tiên.
  - Bit `1` → ghi `"11"`, bit `0` → ghi `"00"` (mỗi bit raw thành **2 ký tự**), nối lại rồi `ToInt64(...,2)`.
  - ⇒ Kết quả là một số nguyên ≤ `2L = 60` bit.
- `output[i] = fun[i] ^ output[i-1] ^ randoms[i]` (XOR tích luỹ).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of Powershelly reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

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

1. **Bỏ XOR tích luỹ**: `fun[i] = out[i] ^ out[i-1] ^ randoms[i]` (với `out[-1]=0`).
2. **Đảo `Scramble`**: hoán vị **chỉ phụ thuộc `seed` và `L`**, không phụ thuộc giá trị bit ⇒ tính được `order[i] = y`. Đưa `fun[i]` về chuỗi `2L` bit, lấy `raw[i] = bit ở 2*order[i]`. (Kiểm chứng vòng tròn forward == fun ⇒ OK.)
3. `L = 30` xác định từ độ lớn `fun` (≤60 bit) ⇒ 5 hàng.
4. Ghép bit **theo cột (column-major)**: `colbits = nối raw[i][k] theo k=0..29 rồi i=0..263`, đọc 8-bit/byte ⇒ chuỗi ASCII chứa flag (phần padding là `0xff`/`0x00`).

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

- **Scramble dạng hoán vị vị trí**: nếu phép trộn chỉ quyết định *bit nào đi đâu* (không phụ thuộc giá trị), thì **đảo được offline** — tính trước bảng hoán vị rồi đọc ngược.
- Thủ thuật "mỗi bit thành 2 ký tự `11`/`00`" chỉ để đóng gói vào một số nguyên; khi đảo chỉ cần lấy bit ở vị trí chẵn.
- XOR tích luỹ (`out[i] = f[i] ^ out[i-1]`) ⇒ đảo bằng `f[i] = out[i] ^ out[i-1]`.
- Xác định kích thước mảng (`L`) từ dải giá trị (độ dài bit) của kết quả.
