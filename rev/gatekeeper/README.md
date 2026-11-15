# CyLab / picoCTF — Gatekeeper

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Multi-Stage Validation Reversing)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Multi-stage password checking function analysis and static constraint solving. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file gatekeeper
gatekeeper: ELF/Artifact analysis
$ checksec gatekeeper
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Symbol: `main`, `is_valid_decimal`, `is_valid_hex`, `reveal_flag`. IDA decompile `main`:
```
scanf("%31s", s);            // s tối đa 31 ký tự
len = strlen(s);
if (is_valid_decimal(s))      v = atoi(s);
else if (is_valid_hex(s))     v = strtol(s, 0, 16);
else                          { puts("Invalid input."); return 1; }
if (v > 999) {
    if (v <= 9999) {
        if (len == 3) reveal_flag();
        else puts("Access Denied.");
    } else puts("Too high.");
} else puts("Too small.");
```
Điều kiện: `999 < v <= 9999` **và `strlen(s) == 3`**. Decimal 3 chữ số tối đa 999 (không thoả `>999`),
nhưng **hex 3 ký tự** như `"FFF"` = 4095 thoả mọi điều kiện. ⇒ input `FFF` (hoặc `fff`/`ABC`...).

`reveal_flag`: `fopen("/flag.txt")`, đọc hết flag vào `ptr`, rồi:
```
for (i=n-1; i>=0; --i) { putchar(ptr[i]); if ((i&3)==0) printf("ftc_oc_ip"); }
```
⇒ in flag **đảo ngược**, chèn literal rác `"ftc_oc_ip"` sau mỗi ký tự ở index gốc `i ≡ 0 (mod 4)`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of Gatekeeper reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

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

1. Gửi `FFF` → vào `reveal_flag`.
2. Nhận chuỗi sau `"Access granted: "`.
3. **Xoá mọi `"ftc_oc_ip"`** rồi **đảo ngược** chuỗi còn lại ⇒ flag.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# gatekeeper (CyLab RE diff2, id 731)
# Need a 3-char token whose parsed value is in (999, 9999]. Decimal 3 digits <= 999,
# so use hex: "FFF"=4095. reveal_flag prints the flag REVERSED and injects the literal
# junk "ftc_oc_ip" after each char at original index i where (i & 3) == 0.
# Recover: remove all "ftc_oc_ip" then reverse.
import re, sys, time
from pwn import remote, context

context.log_level = "error"
HOST, PORT = "chatelaine.cylabacademy.net", 16197
JUNK = "ftc_oc_ip"


def solve_once():
    r = remote(HOST, PORT, timeout=15)
    r.recvuntil(b"999 ): ", timeout=10)
    r.sendline(b"FFF")
    out = r.recvall(timeout=8).decode(errors="replace")
    r.close()
    body = out.split("Access granted:", 1)[-1]
    body = body.replace(JUNK, "")
    body = body.strip("\n").strip()
    flag = body[::-1].strip()
    return flag, out


for attempt in range(6):
    try:
        f, out = solve_once()
        print("[raw]", repr(out[-120:]))
        print("[flag]", f)
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

- **So sánh kiểu/độ dài là chìa khoá**: ràng buộc `strlen==3` + giá trị `>999` mâu thuẫn với decimal ⇒
  đường vòng là **hex** (chương trình tự nhận cả 2 định dạng). Luôn đọc hàm validate để biết định dạng nào được nhận.
- **Output biến đổi**: đảo ngược + chèn rác là dạng "obfuscation output" rẻ tiền — chỉ cần đọc vòng lặp
  của `reveal_flag` để biết cách hoàn tác (xoá rác trước, reverse sau; chú ý rác có thể nằm xen giữa).
- IDA MCP decompile `main`+`reveal_flag` cho tên biến/`scanf("%31s")`/`(i & 3)==0` rõ ràng ngay (nhanh, ~0.01s/hàm).
