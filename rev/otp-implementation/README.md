# CyLab / picoCTF — OTP Implementation

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Alphabet Permutation Bijection Inversion)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Custom finite alphabet jumble() permutation bijection inversion and XOR decryption. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file otp-implementation
otp-implementation: ELF/Artifact analysis
$ checksec otp-implementation
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- IDA: chương trình nhận key hex từ input, `jumble()` các ký tự hex trước khi dùng.
- `jumble(c) % 16` trên các ký tự hex là một **song ánh**:
  ```
  '0':0 '1':2 '2':4 '3':6 '4':8 '5':10 '6':12 '7':14
  '8':1 '9':3 'a':5 'b':7 'c':9 'd':11 'e':13 'f':15
  ```
- Flag = `enc_flag XOR bytes.fromhex(key)`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of OTP Implementation reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

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

- Nghịch đảo song ánh để tìm `key` 100 ký tự hex sao cho `jumble`-ảnh bằng key gốc, rồi XOR `enc_flag`.
- (Trên thực tế `jumble` chỉ đổi thứ tự ký tự hex; hoàn tác rồi XOR.)

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

- Custom "jumble" trên tập ký tự hữu hạn ⇒ lập **bảng nghịch đảo** thay vì suy luận công thức.
- Tên bài cảnh báo: "custom jumbles aren't a good idea".
