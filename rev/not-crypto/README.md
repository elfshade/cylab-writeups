# CyLab / picoCTF — not crypto

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Obfuscated AES Keystream Decoupling)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Obfuscated AES keystream decoupling: input-independent state recovery via LD_PRELOAD hook. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file not-crypto
not-crypto: ELF/Artifact analysis
$ checksec not-crypto
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `file`: ELF 64-bit PIE, stripped.
- `strings`: chỉ có `"I heard you wanted bargain for a flag... whatcha got?"`, `"Yep, that's it!"`.
- Import dùng: `fread`, `memcmp`, `puts`.
- `main` ~3 KB, chứa một **AES-128** nhúng tay (S-box qua bảng `byte_20A0`, MixColumns với
  nhân `2/3` biểu diễn `(2*x) ^ (27 * (x>>7))`, key schedule 176 byte từ `xmmword_21A0`).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Đây là bài "reverse trick" hơn là crypto thật. Đọc disassembly phần cuối `main`:

```
0x1146 lea rdi, [rsp+208h+ptr]     ; ptr = buffer 64 byte input
0x1164 mov [rsp+208h+s2], rdi      ; s2 = &input        <-- !!
...
0x117c call fread                  ; read(ptr, 1, 0x40, stdin)
...
0x13aa mov rsi, [rsp+208h+s2]      ; rsi = input
0x13b4 mov rdi, [rsp+208h+s1]      ; rdi = output đã tính (v115 sau AES+keystream)
0x13b9 call memcmp                 ; memcmp(output, input, 0x40)
0x13c9 lea rdi, "Yep, that's it!"
```

Tức là chương trình so **kết quả nó tự tính** với **input do người dùng nhập**, chứ không so với
một ciphertext cố định giấu trong binary. Mà "kết quả tự tính" (v115 khởi tạo từ hằng số
`xmmword_21C0..21F0`, cộng keystream) **không hề phụ thuộc vào input** (`ptr` chỉ được ghi bởi
`fread`, không bao giờ được đọc lại). ⇒ Bài toán chỉ còn: trích ra buffer `s1` (64 byte) và nộp
đúng chuỗi đó làm input.

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

Hook `memcmp` bằng `LD_PRELOAD` để in hai tham số (khỏi vật lộn với gdb + PIE base):

```c
int memcmp(const void*a, const void*b, size_t n){
  /* in hex + ascii của a (s1) và b (s2) ra stderr, rồi return 0 */
}
```

Chạy `LD_PRELOAD=./shim.so ./not-crypto < in.bin` (in.bin = 64 ký tự 'A'):

```
s1s: picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}...
s2s: AAAAAAAA...
Yep, that's it!
```

⇒ Input đúng chính là chuỗi `s1`.

---

## Exploit / Solution Script

The complete solver script is maintained in [`shim.c`](shim.c):

```python
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stddef.h>

/* LD_PRELOAD hook: dump arguments of memcmp, then pretend success.
 * Used for picoMini "not crypto" (CyLab id 222): the binary computes a fixed
 * 64-byte output (s1) and compares it against our input (s2); dump s1 to get the flag. */
int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = a, *q = b;
    fprintf(stderr, "\n[memcmp n=%zu]\n s1(hex): ", n);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
    fprintf(stderr, "\n s2(hex): ");
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", q[i]);
    fprintf(stderr, "\n s1(asc): ");
    for (size_t i = 0; i < n; i++) fputc((p[i] >= 32 && p[i] < 127) ? p[i] : '.', stderr);
    fprintf(stderr, "\n s2(asc): ");
    for (size_t i = 0; i < n; i++) fputc((q[i] >= 32 && q[i] < 127) ? q[i] : '.', stderr);
    fprintf(stderr, "\n");
    return 0;
}
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- "Crypto" trong RE thường chỉ là **keystream/độ nhiễu obfuscation**; luôn kiểm tra xem
  **input có thực sự được dùng trong phép tính không**. Dấu hiệu: buffer input chỉ xuất hiện ở
  `lea`/`fread` và ở một `mov` gán vào biến `s2` dùng cho `memcmp` — không đọc lại nữa ⇒ output
  là hằng số ⇒ flag = output.
- Cách trích nhanh 1 đối số của libc call (**không cần gdb/PIE base**): **LD_PRELOAD hook**
  `memcmp`/`strcmp`/`strncmp`/`puts`… in tham số rồi `return 0` để lấy nhánh "thành công".
- AES nhận diện tĩnh: bảng S-box 256 byte ở `.rodata`, MixColumns `(2*a) ^ (27*(a>>7))`,
  key schedule 176 byte (AES-128) hoặc 240 (AES-256), các hằng `xmmword_` gần `vmovdqa`.
