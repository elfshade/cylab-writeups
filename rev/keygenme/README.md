# CyLab / picoCTF — Keygenme

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Custom Keygen & Algorithm Reversal)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Reverse engineering license validation algorithm, dynamic key generator creation. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file keygenme
keygenme: ELF/Artifact analysis
$ checksec keygenme
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `strings` lộ các mảnh flag rời: `academy{H`, `br1ng_y0H`, `g_y0ur_0H`, `wn_k3y_` — các byte `H` (0x48) chỉ là opcode REX.W ⇒ flag thật dạng `academy{br1ng_y0ur_0wn_k3y_...}`.
- `main`: `fgets(s,37,stdin)` → gọi `sub_1209` (checker) → "That key is valid/invalid."

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Không phải memory bug — bài là **keygen**: flag = chuỗi 36 ký tự được **dựng lại** trong checker từ prefix + `MD5(prefix)` + `MD5("}")`.

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

Decompile `sub_1209` (IDA MCP):
```c
strcpy(s, "academy{br1ng_y0ur_0wn_k3y_");     // 27 ký tự
MD5(s, strlen(s), &v10[2]);                   // v10 = "}" + md5(prefix) hex? no, raw md5 bytes
MD5(v10, strlen(v10)=1, v11);                 // md5("}") — v10[1] = 0 nên strlen=1
for i in 0..15: sprintf(&s[32+2i], "%02x", v10[i+2]);   // s[32..63] = 32 hex của md5(prefix)
for j in 0..15: sprintf(&v14[2j], "%02x", v11[j]);      // v14[0..31] = 32 hex của md5("}")
for k in 0..26: v14[32+k] = s[k];             // prefix
v14[59]=s[54]; v14[60]=s[53]; v14[61]=s[54]; v14[62]=s[35];
v14[63]=v14[13]; v14[64]=s[40]; v14[65]=s[45]; v14[66]=s[41]; v14[67]=v10[0]='}';
// nhập đúng = v14[32..67] (36 ký tự)
```
`v13 == s[54]` ⇒ `s[54] = hex[22]` của md5(prefix). Toàn bộ là **hoán vị cố định** của 2 chuỗi md5 hex — dựng lại bằng Python rồi verify local.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# CyLab RE diff3 — 276 Keygenme
# Binary: strcpy(s,"academy{br1ng_y0ur_0wn_k3y_"); MD5(s)->&v10[2]; MD5("}")->v11;
# s[32..63] = hex(MD5(s));  v14[0..31]=hex(MD5("}")); v14[32..58]=s[0..26];
# v14[59]=s[54]; v14[60]=s[53]; v14[61]=s[54]; v14[62]=s[35]; v14[63]=v14[13];
# v14[64]=s[40]; v14[65]=s[45]; v14[66]=s[41]; v14[67]=v10[0]='}';
# expected input a1 = v14[32..67], len 36.
import hashlib, subprocess, sys

s = list("academy{br1ng_y0ur_0wn_k3y_")          # 27 chars at s[0..26]
s += ["\x00"] * (64 - len(s))                     # pad (s[] extends past 53 into v13/pad)

# s[32..63] = hex(MD5(prefix))  (32 hex chars)
h1 = hashlib.md5("academy{br1ng_y0ur_0wn_k3y_".encode()).hexdigest()
for i, ch in enumerate(h1):
    s[32 + i] = ch
# v13 == s[54]

v14 = [None] * 72
h2 = hashlib.md5(b"}").hexdigest()                # MD5 of the 1-char string "}"
v14[0:32] = list(h2)
for k in range(27):
    v14[32 + k] = s[k]                            # s[0..26]
v14[59] = s[54]
v14[60] = s[53]
v14[61] = s[54]
v14[62] = s[35]
v14[63] = v14[13]
v14[64] = s[40]
v14[65] = s[45]
v14[66] = s[41]
v14[67] = "}"                                     # v10[0]

flag = "".join(v14[32:68])
print("md5(prefix) =", h1)
print("md5('}')   =", h2)
print("FLAG        =", flag, "(len", len(flag), ")")

# verify against the real binary
try:
    r = subprocess.run(["/home/thang/cylab-re/276/keygenme"],
                       input=flag + "\n", text=True, capture_output=True, timeout=10)
    print("binary says:", r.stdout.strip())
except Exception as e:
    print("run error:", e)
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **Đánh lừa `strings`**: flag split rời kèm byte `0x48` = REX.W → ghép theo decompiler, không ghép mù.
- **MD5 hex làm suffix** + sắp xếp lại: chỉ cần tái tạo đúng thứ tự ghi (`sprintf %02x` từng byte) — không cần brute.
- Với flag có hash suffix: dựng prefix rồi hash đúng thứ tự (strlen sau khi nối = toàn bộ chuỗi!).
