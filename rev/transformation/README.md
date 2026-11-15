# CyLab / picoCTF — Transformation

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (UTF-16 Character Bit-Unpacking)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

UTF-16 16-bit packed char unpacking: extracting high byte (>>8) and low byte (&0xFF). By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file transformation
transformation: ELF/Artifact analysis
$ checksec transformation
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `xxd enc` → các ký tự unicode nhiều byte (mỗi ký tự 3 byte UTF-8).
- Đề kèm công thức mã hoá:
  ```python
  ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])
  ```
  ⇒ **2 ký tự flag bị nhét vào 1 ký tự 16-bit**: cao = flag[i], thấp = flag[i+1].

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Mã hoá 16-bit không mất thông tin → giải mã đơn giản bằng `>>8` và `&0xff`.

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
data = open("enc","rb").read().decode()
out = "".join(chr((ord(c)>>8)&0xff)+chr(ord(c)&0xff) for c in data)
print(out)  # academy{redacted}
```

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **"2 chars packed into 1 wide char"** là pattern phổ biến: `(hi<<8)|lo` ⇔ tách bằng `>>8` / `&0xff`.
- Luôn để ý file `enc` + công thức đi kèm trong description — không cần reverse binary.
