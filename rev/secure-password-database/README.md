# CyLab / picoCTF — Secure Password Database

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Database Schema & Embedded Hash Analysis)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

SQLite schema and embedded hashing algorithm analysis in stripped native binary. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file secure-password-database
secure-password-database: ELF/Artifact analysis
$ checksec secure-password-database
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Symbol: `main`, `hash`, `make_secret`, global `obf_bytes`.
```
dest = calloc(90);
for (i=0;  i<=0xC; ++i) dest[i+60] = obf_bytes[i]^0xAA;   // 13 byte "khoá" ẩn trong dest[60..72]
fgets(s,50); strcpy(dest, s);                              // mật khẩu người dùng
fgets(nptr,20); v5 = atoi(nptr);
printf("You entered: %d\n", v5);
for (j=0; v5>=j && j<=89; ++j) printf("%d ", dest[j]);     // LEAK: in dest[0..min(v5,89)]
...
v10 = strtoul(s, &endptr, 10);
secret = make_secret(v13);          // djb2 của chuỗi deobf
if (secret == v10) { fopen("flag.txt"); print flag; }
```
- `make_secret`: `for (i=0; obf_bytes[i]; ++i) a1[i] = obf_bytes[i]^0xAA; a1[12]=0; return hash(a1);`
- `hash`: **djb2** — `h=5381; h = 33*h + (unsigned char)c;` (wrap 64-bit).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
1. **Info leak**: tuỳ chọn "độ dài mật khẩu" chỉ dùng để giới hạn vòng in (`v5 >= j && j <= 89`), nên nhập
   `v5 = 89` in **toàn bộ** `dest`, kể cả 13 byte "khoá" tại `dest[60..72]` = `obf_bytes[i]^0xAA`.
2. Thực chất khoá là **hằng số tĩnh**, nên không cần leak: `obf_bytes` cố định ⇒ tính thẳng hash.
   Secret = `"iUbh81!j*hn!"` (12 byte), `djb2` = `15237662580160011234`.

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

- Đơn giản nhất: gửi mật khẩu bất kỳ, `89`, rồi **hash hằng số**; server in `flag.txt`.
- (Đường "đúng ý đồ": dùng leak `dest[60..72]`, XOR `0xAA` ra chuỗi secret, tính `djb2` rồi gửi.)

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Secure Password Database (CyLab RE diff2, id 767)  -- "heartbleed.c"
# main: dest=calloc(90); dest[60+i] = obf_bytes[i]^0xAA; strcpy(dest,password);
#   prints dest[0..min(v5,89)] (length option -> leaks the deobfuscated key bytes)
#   then asks for a hash; make_secret() builds a1[i]=obf_bytes[i]^0xAA (until obf_bytes[i]==0),
#   a1[12]=0, returns djb2(a1). If hash matches -> prints flag.txt.
# The secret is STATIC -> hash constant:
#   obf_bytes = c3 ff c8 c2 92 9b 8b c0 80 c2 c4 8b 00 ..  -> deobf^0xAA = "iUbh81!j*hn!"
#   djb2 (h=5381; h=33*h+c) mod 2^64 -> 15237662580160011234
import re, sys, time
from pwn import remote, context

context.log_level = "error"
HOST, PORT = "xebec.cylabacademy.net", 28829
HASH = 15237662580160011234  # djb2("iUbh81!j*hn!")


def compute_hash():
    raw = bytes.fromhex("c3ffc8c2929b8bc080c2c48b")
    h = 5381
    for c in raw:
        h = (33 * h + (c ^ 0xAA)) & 0xFFFFFFFFFFFFFFFF
    return h


def solve_once():
    assert compute_hash() == HASH, "hash mismatch"
    r = remote(HOST, PORT, timeout=15)
    r.recvuntil(b"account:", timeout=10)
    r.sendline(b"A")                       # password
    r.recvuntil(b"password?", timeout=10)
    r.sendline(b"89")                      # length -> leak whole buffer
    leak = r.recvuntil(b"account!", timeout=10)
    r.sendline(str(HASH).encode())         # correct hash
    out = r.recvall(timeout=8).decode(errors="replace")
    r.close()
    m = re.search(r"academy\{[^}]*\}|picoCTF\{[^}]*\}", out)
    return m.group(0) if m else None, out


for attempt in range(6):
    try:
        f, out = solve_once()
        print("[out]", out.strip()[-120:])
        if f:
            print("[FLAG]", f)
            sys.exit(0)
    except Exception as e:
        print("[!]", attempt, e)
    time.sleep(1)
sys.exit(1)
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **"Print N bytes" leak**: biến `len` do user nhập điều khiển vòng lặp in buffer ⇒ đặt max để dump cả buffer,
  kể cả vùng dữ liệu "ẩn" (secret/key) nằm sau dữ liệu hợp lệ.
- Khi thấy `calloc` + gán hằng vào offset cố định + `strcpy` từ input ⇒ đoán ngay layout dễ lộ.
- **djb2**: `h=5381; h=h*33+c` — chuẩn, chỉ cần wrap 64-bit; nếu secret tĩnh thì hash là hằng số (không cần chạy binary).
- `obf_bytes[i]^0xAA` là XOR obfuscation đơn giản; trích bytes từ `.data` (IDAPython `idc.get_name_ea_simple`).
