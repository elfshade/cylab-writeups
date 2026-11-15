# CyLab / picoCTF — Hidden Cipher 1

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Embedded XOR Keystream Recovery)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

XOR keystream recovery from embedded cipher routine. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file hiddencipher
hiddencipher: ELF/Artifact analysis
$ checksec hiddencipher
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `file` → `no section header`, `strings` thấy `UPX!` ⇒ packed.
- `upx -d hiddencipher -o hiddencipher.unp` (`upx` có sẵn) → unpack OK, **not stripped**.
- Symbol: `get_secret`, `main`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- `get_secret()` ghi 6 byte vào global `s.0`: `53 33 43 72 33 74` = **`"S3Cr3t"`** (rồi NUL) và trả con trỏ.
- `main`: đọc `flag.txt`, rồi in `"Here your encrypted flag:"`; vòng `for i in 0..len-1`:
  `out = flag[i] ^ secret[i % 6]`, in `%02x`.
- ⇒ **Repeating-key XOR** với khoá `"S3Cr3t"`, chu kỳ **6** (magic `0x2aaaaaab` ở asm là phép chia lấy dư;
  kiểm chứng chu kỳ bằng cặp plain/cipher local thay vì suy diễn từ asm).

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

1. **Unpack UPX** (`upx -d`) — dữ liệu/chuỗi thật lộ ra.
2. Đọc `get_secret` → khoá `"S3Cr3t"`.
3. Lấy ciphertext hex từ server, XOR lại với khoá lặp chu kỳ 6.
   (Không cần bước này nếu suy khoá từ known-plaintext `academy{` — 8 byte đầu đã đủ xác định keystream.)

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# hiddencipher (CyLab RE diff2, id 745)
# UPX-packed. Unpack -> get_secret() builds "S3Cr3t"; main XORs flag[i] with key[i%6],
# prints hex. Repeating-key XOR with key "S3Cr3t".
import re, sys, time
from pwn import remote, context

context.log_level = "error"
HOST, PORT = "xebec.cylabacademy.net", 13237
KEY = b"S3Cr3t"


def solve_once():
    r = remote(HOST, PORT, timeout=15)
    out = r.recvall(timeout=8).decode(errors="replace")
    r.close()
    m = re.findall(r"[0-9a-fA-F]{2,}", out.split("encrypted flag:")[-1])
    hexstr = "".join(m)
    ct = bytes.fromhex(hexstr)
    pt = bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(ct))
    return pt.decode(errors="replace"), hexstr


for attempt in range(6):
    try:
        f, hx = solve_once()
        print("[ct]", hx)
        print("[pt]", f)
        if f.startswith(("academy{", "picoCTF{")):
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

- **UPX**: `upx -d` là bước đầu gần như bắt buộc khi thấy `UPX!`/`no section header`; sau unpack
  symbol trở lại → đọc thẳng `main`/`get_secret`.
- Nhận dạng **repeating-key XOR** nhanh nhất: lấy cặp plaintext–ciphertext local (flag fake) rồi XOR →
  thấy khoá lặp; đồng thời suy ra **chu kỳ** thật (đừng đoán từ magic-number trong asm).
- `get_secret` kiểu ghi từng byte vào global là dấu hiệu khoá hardcode ⇒ `objdump -s -j .data` hoặc
  đọc ngay các `mov byte [rip+..], imm` trong hàm.
- Flag thật luôn ở `flag.txt` **trên server**; dùng chính thuật toán để decode ciphertext remote.
