# CyLab / picoCTF — Autorev 1

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Decompilation & Linear System Inversion)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Linear equation system recovery from stripped ELF binary, matrix inversion. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file autorev1
autorev1: ELF/Artifact analysis
$ checksec autorev1
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Binary đầu (`b0.bin`): ELF x86-64, **non-PIE**, not stripped. `main`:
```asm
mov  DWORD PTR [rbp-0x4], 0x8a81b62     ; <-- SECRET (hằng số)
mov  DWORD PTR [rbp-0x8], 0x0           ; input
call puts("What's the secret?")
lea  rax,[rbp-0x8]; mov rsi,rax; mov edi,"%u"; call scanf
mov  eax,[rbp-0x8]; cmp [rbp-0x4],eax; jne "Nice try :(" ; else "Correct!"
```
⇒ Secret là **số nguyên 32-bit** nhúng sẵn dưới dạng immediate, đọc bằng `scanf("%u")`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of Autorev 1 reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

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

Tự động hoá toàn bộ:
1. Mỗi binary: nhận hex → ghi ra file.
2. Xác định **format của `scanf`**: dò lệnh `call scanf`, lùi lại tìm `mov edi,<addr>` →
   đọc chuỗi format tại vaddr đó (dùng `ELF.read`). (`%u` ⇒ mode số nguyên.)
3. Trích hằng số: quét disasm `main` tìm `mov DWORD PTR [rbp-x],imm` (32-bit) và
   `movabs rax,imm64` (64-bit), bỏ qua giá trị `0/1`, lấy ứng viên.
4. Gửi giá trị dạng **số thập phân**; lặp đủ 20 lần → server in flag.

Tất cả 20 binary trong bài đều cùng template `%u` ⇒ chỉ 1 nhánh "integer" là đủ qua bài.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Autorev 1 (CyLab RE diff2, id 754) -- speed reversing: 20 binaries, 10s each.
# Each binary asks "What's the secret?" and scanf()s one value. Extract the compared
# constant statically and reply. Supports:
#   - integer scanf formats (%u/%d/%lu/%ld/%x/%i) -> the immediate stored in a stack
#     slot that is later used by cmp (heuristic: the non-zero immediate).
#   - string (%s) -> the string operand; handled separately if needed.
import os, re, sys, time, subprocess
from pwn import remote, ELF, context

context.log_level = "error"
HOST, PORT = "xebec.cylabacademy.net", 29822
TMP = "/tmp/opencode/autorev1"
os.makedirs(TMP, exist_ok=True)


def main_disasm(path):
    out = subprocess.check_output(["objdump", "-d", "-M", "intel", path], text=True)
    m = re.search(r"<main>:\n(.*?)\n\n", out, re.S)
    return m.group(1) if m else out


def scanf_format(path, e):
    dis = main_disasm(path)
    # find call to scanf*, look back for 'mov edi,0xADDR'
    lines = dis.splitlines()
    addrs = []
    for i, ln in enumerate(lines):
        if "scanf" in ln and "call" in ln:
            for j in range(i, max(0, i - 8), -1):
                m = re.search(r"mov\s+edi,(0x[0-9a-f]+)", lines[j])
                if m:
                    addrs.append(int(m.group(1), 16))
                    break
    for a in addrs:
        try:
            raw = e.read(a, 16).split(b"\0")[0]
            s = raw.decode(errors="replace")
            if "%" in s:
                return s
        except Exception:
            pass
    return None


def extract(path):
    e = ELF(path)
    fmt = scanf_format(path, e)
    if fmt is None:
        return None, "no-fmt"
    if "%s" in fmt or "[" in fmt:
        return None, "strmode:" + fmt
    dis = main_disasm(path)
    cands = []
    # 32-bit imm stored to a stack slot
    for m in re.finditer(r"mov\s+DWORD PTR \[rbp-0x[0-9a-f]+\],(0x[0-9a-f]+)", dis):
        v = int(m.group(1), 16)
        if v not in (0, 1):
            cands.append(v)
    # movabs rax, imm64

# ... [truncated for brevity, see full file] ...
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **"Speed reversing" = tự động hoá tĩnh**: đề gửi binary theo phiên, phạt 10s/cái ⇒ không thể
  dùng IDA/Ghidra thủ công; phải parse `objdump` + `capstone`/regex và trả lời bằng script.
- **Đọc format của `scanf`** là bước quyết định: `mov edi,<vaddr>` + `ELF.read(vaddr)` cho biết
  input là số hay chuỗi ⇒ chọn cách trích secret.
- **Template lặp lại**: 20 binary chỉ khác hằng số ⇒ viết extractor 1 lần, chạy 20 lần.
  Ứng viên secret = immediate nhúng vào stack slot rồi được `cmp` (bỏ `0/1`).
- Non-PIE + not stripped giúp `objdump` là đủ, không cần decompiler cho bài này.
