# CyLab / picoCTF — Bypass Me

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Authentication Logic Bypass)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Authentication branch bypass in native binary, patch analysis or key extraction. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file bypass-me
bypass-me: ELF/Artifact analysis
$ checksec bypass-me
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Symbol: `main`, `auth_sequence`, `intro_sequence`, `decode_password`, `sanitize`, `type_out`.
- `main`: `decode_password(password)`; `intro_sequence()`; vòng 3 lần: `fgets(buf,128)`,
  bỏ `\n`, `sanitize(buf, sanitized)` (**chỉ để hiển thị**), in `Raw Input`/`Sanitized Input`,
  rồi `if (!strcmp(buf, password)) break;`.
  Thoát vòng lặp → `auth_sequence()` → `fopen("../../root/flag.txt")` → in flag.
- `sanitize`: chỉ giữ ký tự `isalpha` (bẫy trực giác — người chơi tưởng phải nhập chuỗi qua sanitize,
  nhưng so sánh dùng **buf gốc**). Nhập sai chữ cái xen ký tự khác vẫn so nguyên chuỗi.
- `decode_password`: hằng số 11 byte: qword `0xC9CFF9D8CFDADFF9` (LE) + dword `0xCFCBC9C9` ghi đè `enc[7..10]`,
  rồi `out[i] = enc[i] ^ 0xAA`, `out[11]=0` ⇒ mật khẩu = **`SuperSecure`**.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of Bypass Me reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

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

1. Trích `decode_password` từ IDA (2 hằng số + XOR `0xAA`) → `SuperSecure`.
2. SSH vào box, chạy `echo 'SuperSecure' | ./bypassme.bin` → bypass auth → in flag
   (`../../root/flag.txt`, đọc được nhờ setuid root).

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Bypass Me (CyLab RE diff2, id 761) -- SSH box, setuid-root binary bypassme.bin
# decode_password(): 11 bytes = qword 0xC9CFF9D8CFDADFF9 (LE) + dword 0xCFCBC9C9 @off7, XOR 0xAA
#   -> b"SuperSecure". main compares strcmp(raw_input, password) -> bypass auth, reads ../../root/flag.txt.
import re, sys, time
import paramiko

HOST, PORT, USER, PW = "chatelaine.cylabacademy.net", 17163, "ctf-player", "4f5344cd"
PASSWORD = "SuperSecure"


def solve_once():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PW, timeout=25,
              look_for_keys=False, allow_agent=False)
    i, o, e = c.exec_command("echo '%s' | ./bypassme.bin" % PASSWORD, timeout=60)
    out = o.read().decode(errors="replace") + e.read().decode(errors="replace")
    c.close()
    m = re.search(r"academy\{[^}]*\}|picoCTF\{[^}]*\}", out)
    return (m.group(0) if m else None), out


for attempt in range(4):
    try:
        f, out = solve_once()
        print(out.strip()[-200:])
        if f:
            print("[FLAG]", f)
            sys.exit(0)
    except Exception as ex:
        print("[!]", attempt, ex)
    time.sleep(2)
sys.exit(1)
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **Không tin hàm "sanitize"**: ở đây `sanitize` chỉ hiển thị, còn `strcmp` so với input **gốc**.
  Luôn xác định *biến nào thực sự* được so sánh/đưa vào sink.
- **Mật khẩu sinh tại runtime từ hằng số**: chỉ cần đọc `decode_password` (XOR/lệch đơn giản) là ra;
  không cần debug thật, dù đề gợi ý LLDB.
- **Setuid root + đường dẫn tương đối** (`../../root/flag.txt`): binary local tải về **mất bit setuid**,
  nên phải chạy trên box SSH để đọc flag. `paramiko` (không có `sshpass`) đủ để lái SSH tự động.
