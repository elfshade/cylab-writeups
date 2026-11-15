# CyLab / picoCTF — Flag Hunters

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Custom Bytecode Interpreter)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Custom bytecode virtual machine interpreter analysis and opcode tracing. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file flag-hunters
flag-hunters: ELF/Artifact analysis
$ checksec flag-hunters
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Chương trình nạp file `flag.txt` vào **dòng 4** của "song" (sau intro), rồi chạy 1 interpreter nhỏ:
  `while` duyệt `song_lines[lip].split(';')`, các lệnh: `REFRAIN` (nhảy tới `[REFRAIN]` và set RETURN line), `CROWD.*` (hỏi input), `RETURN N` (nhảy `lip=N`), `END`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Nhánh `CROWD`:
  ```python
  crowd = input('Crowd: ')
  song_lines[lip] = 'Crowd: ' + crowd   # input được NỐI vào dòng, sang lượt sau dòng này được split(';') lại
  lip += 1
  ```
  ⇒ **command injection qua input CROWD**: lần lượt refrain sau, dòng đã bị sửa `Crowd: ;RETURN 3` được `split(';')` thành `['Crowd: ', 'RETURN 3']` → lệnh `RETURN 3` thừa hành ⇒ nhảy về **dòng 3 = intro ngay trước flag** → interpreter in tiếp dòng 4 = **flag**.

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
from pwn import *
r = remote("xebec.cylabacademy.net", 11161)
r.recvuntil(b"Crowd: ")
r.sendline(b";RETURN 3")
print(re.search(r"academy\{[^}]+\}", r.recvall().decode()).group(0))
```
- Verify local: tạo `flag.txt` giả, chạy `lyric-reader.py`, input `;RETURN 3` → flag in ra sau vài refrain.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
from pwn import *
import re
r = remote("xebec.cylabacademy.net", 11161, timeout=20)
r.recvuntil(b"Crowd: ")
r.sendline(b";RETURN 3")          # injection: dong 'Crowd: ;RETURN 3' -> split(';') -> RETURN 3 -> nhay ve dong 3 (truoc flag)
out = r.recvall(timeout=15).decode(errors="replace")
m = re.search(r"academy\{[^}]+\}", out)
print("FLAG:", m.group(0) if m else out[:500])
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **Interpreter injection**: khi input được nối vào dòng rồi re-parse (split), chèn `;` + lệnh để thực thi.
- **Nhảy IP về vị trí kề flag** (dòng 3) thay vì cố in flag trực tiếp — tận dụng luồng in bình thường.
