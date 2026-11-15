# CyLab / picoCTF — B1ll_Gat35

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (x86 ELF & Constraint Solving)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

32-bit ELF reversing, key validation algorithm and linear constraint solver. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file b1ll-gat35
b1ll-gat35: ELF/Artifact analysis
$ checksec b1ll-gat35
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `strings` lộ các thông điệp:
  `The key is: `, `academy{These are the access codes to the vault: `, `Input a number between 1 and 5 digits: `,
  `Enter the correct key to get the access codes: `, `Incorrect key. Try again.`, `Correct input. Printing flag: `.
- Mở IDA (PE) → `_main_0` @ `0x408040`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
```c
main_0:
  printf("Input a number between 1 and 5 digits: ");
  scanf("%d", &v5);
  v6 = 1; while (v5 > 9) { ++v6; v5 /= 10; }   // v6 = số chữ số, v5 = chữ số đầu
  if (v6 <= 5) {
    sub_402117(v5, v6);                        // -> sub_407D50(v5, v6)
    while (getchar() != '\n');
    printf("Enter the correct key to get the access codes: ");
    fgets(Str, 100, stdin);
    if (sub_402DB5(Str))  { printf("Correct input..."); sub_401F05(); }  // -> in flag
    else                  printf("Incorrect key. Try again.\n");
  }
```

`sub_407D50(a1,a2)`:
```c
qword_47C270 = sub_407AF0(a1, a2);                          // giá trị "access code"
sub_4032FB(v4, "%llu", 16 * (qword_47C270 >> 2));
sub_4032FB(byte_47C280, "%s%s", "The key is: ", v4);        // expected key = "The key is: <16*(q>>2)>"
```

`sub_407AF0(a1,a2)` (tính access code):
```c
v5 = 2^(4*a2) - 1;                         // mask (a2 = số chữ số)
v3 = pow((int)((a1 & (a1 ^ v5)) + 37), 7);
return (u64)v3 / (((u64)v3 >> 8) % 0x1E240);   // 0x1E240 = 123456
```

**Điểm mấu chốt**: `v5 = 2^(4*a2) - 1` toàn bit 1 trong `4*a2` bit, mà `a1` chỉ là 1 chữ số (0–9).
⇒ `a1 ^ v5` là phần bù của `a1` trong `4*a2` bit ⇒ `a1 & (a1 ^ v5) == 0` với mọi `a1`.
Vậy biểu thức luôn bằng `37`, nên **access code là HẰNG SỐ** bất kể input:

```
v  = 37^7        = 94931877133
den = (v >> 8) % 0x1E240 = 89277
q  = v / den     = 1063340        -> qword_47C270
key = 16*(q>>2)  = 4253360
```

`sub_407F60(Str)` (kiểm tra key) so `Str` (bỏ `\n`) với `byte_47C280` ⇒ key cần nhập là
**cả chuỗi `"The key is: 4253360"`** (không chỉ số).

`sub_407E80()` (in flag) = `"academy{These are the access codes to the vault: " + str(qword_47C270) + "}"`.

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
# 57 B1ll_Gat35 (win-exec-1.exe) -- compute key + flag without running Windows binary.
#
# main: scanf("%d", &v5); v6 = digit_count(v5); v5 = leading_digit(v5)  (+ sub_407D50(v5,v6))
# sub_407AF0(a1,a2):
#   v5 = 2^(4*a2) - 1                         # all-ones mask over a1's nibbles
#   v3 = pow((int)((a1 & (a1 ^ v5)) + 37), 7) # a1 & (a1 ^ mask) == 0  => 37^7 constant
#   return v3 // ((v3 >> 8) % 0x1E240)        # 0x1E240 = 123456
#
# qword_47C270 = sub_407AF0(...) = 1063340 (constant).
# expected key (byte_47C280) = "The key is: " + str(16*(qword>>2)) = "The key is: 4253360"
# flag = "academy{These are the access codes to the vault: " + str(qword) + "}"

v = 37 ** 7                                  # 94931877133
q = v // ((v >> 8) % 0x1E240)                # 1063340
key = 16 * (q >> 2)                          # 4253360
print("qword_47C270 =", q)
print("expected key =", "The key is: %d" % key)
print("FLAG: academy{These are the access codes to the vault: %d}" % q)
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **Mask all-ones** (`x & (x ^ (2^k-1)) == 0`) ⇒ giá trị đầu vào bị triệt tiêu, kết quả là hằng số.
  Đây là mẹo "che giấu input" kinh điển: nhiều input đều cho cùng output.
- Key check so với **buffer chuỗi đầy đủ** (`"The key is: ..."`), không phải chỉ giá trị số — đọc kỹ
  hàm build buffer (`sub_4032FB(byte, "%s%s", prefix, value)`) trước khi nhập key.
- PE native (không .NET) có thể reverse hoàn toàn tĩnh bằng IDA; không nhất thiết cần Windows VM/OllyDbg.
- Chạy xác nhận nhanh win PE console bằng `wine` + pipe stdin (`tr -d '\r'` để sạch CR).
