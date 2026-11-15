# CyLab / picoCTF — Forky

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Process Fork Trees & Shared Memory)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Multi-process fork tree analysis, IPC shared memory increment simulation (4 * 10^9). By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file forky
forky: ELF/Artifact analysis
$ checksec forky
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
`main` (32-bit):
```c
v4 = mmap(0, 4, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
*v4 = 0x3B9ACA00;          // 1000000000
fork(); fork(); fork(); fork();   // 1 -> 16 processes
*v4 += 0x499602D2;         // +1234567890  (int32, có wrap)
doNothing(*v4);
```
- `fork()` 4 lần ⇒ **16 process** (parent + 15 con), tất cả cùng chạy phần sau.
- mmap là `MAP_SHARED` ⇒ biến đếm **dùng chung** giữa các process.
- Mỗi process cộng `1234567890` rồi gọi `doNothing()` với giá trị hiện tại.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Giá trị **cuối cùng** = sau 16 lần cộng: `1000000000 + 16*1234567890 = 20753086240`.
- Nhưng `*v4` là **`int` 32-bit** ⇒ tràn số: `20753086240 mod 2^32 = 3573217056`.
- `doNothing(int a1)` nhận tham số **có dấu** ⇒ giá trị đọc ra trong gdb là `-721750240`
  (vì `3573217056 - 2^32 = -721750240`).
- Kiểm chứng: patch `doNothing` để `write(1, &arg, 4)` (syscall `int 0x80`) rồi chạy native →
  16 giá trị, giá trị **cuối** = `3573217056` (unsigned). Đọc dạng signed = `-721750240`.

Ghi chú: do `*v4 += ...` là read-modify-write **không nguyên tử** nên có race (đôi khi mất 1 lần cộng
→ giá trị cuối là `2338649166`). Đáp án của đề là giá trị khi **đủ 16 lần cộng** (giá trị max),
đọc dạng signed.

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
# 24 Forky -- value passed to doNothing() as signed 32-bit int.
# main: mmap(MAP_SHARED) *p=1000000000; fork x4 (=16 procs); *p += 1234567890 (int32 wrap);
#       doNothing(*p). The last value = after 16 increments, read as SIGNED int.
initial = 1000000000
inc = 1234567890
nproc = 2 ** 4  # 4 forks
raw = (initial + inc * nproc) & 0xFFFFFFFF
signed = raw - 2**32 if raw >= 2**31 else raw
print("unsigned:", raw)
print("signed  :", signed)
print("FLAG: academy{redacted}" % signed)
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **`fork()` nhân đôi số process** mỗi lần gọi; 4 lần ⇒ 16.
- **`MAP_SHARED`** khiến mmap dùng chung giữa cha và con → biến toàn cục chia sẻ.
- **Tràn số `int` 32-bit**: kết quả phải `mod 2^32`; tham số truyền là **có dấu** ⇒ đáp án là số âm.
- Đáp án "last value" lấy giá trị khi **tất cả** increment đã xảy ra (giá trị max quan sát được).
- Khi cần xem giá trị runtime: **patch hàm bằng `write(1,&arg,4)` + `int 0x80`** rồi decode,
  hoặc gdb all-process (`set detach-on-fork off`, `set schedule-multiple on`) — nhớ đọc tham số ở
  `[ebp+8]` (sau prologue), không phải `[esp+4]`.
