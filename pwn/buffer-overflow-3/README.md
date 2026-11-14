# buffer overflow 3 (CyLab / picoCTF 2019 — Pwn, difficulty 3)

## Đề bài / file đính kèm
- CyLab challenge id **260** (`buffer overflow 3`), `nc xebec.cylabacademy.net 32048`.
- Kèm `vuln` + `vuln.c`. 32-bit i386, dynamically linked, **not stripped**, **No PIE (0x8048000)**, Partial RELRO, NX, "No canary found" (checksec không thấy vì canary là biến toàn cục copy tay).
- Có hàm `win()` @`0x08049236` in `flag.txt`.

## Recon
- Nguồn: `char global_canary[4]` đọc từ `canary.txt` (hằng số mỗi instance), `vuln()` copy 4 byte vào biến stack `char canary[4]`, rồi `read(0, buf, count)` với `count` do người dùng nhập (`sscanf`) → **overflow tuỳ ý**.
- Cuối `vuln()`: `if (memcmp(canary, global_canary, 4)) { báo lỗi; exit(0); }` → nếu canary còn nguyên thì in "Ok... Now Where's the Flag?" rồi `ret`.
- Layout stack (từ disassembly): `buf`@`ebp-0x50` (64B), `canary`@`ebp-0x10`, `x`@`ebp-0xc`, pad@`ebp-0x8`, saved ebx@`ebp-0x4`, saved ebp@`ebp`, **ret@`ebp+4`** ⇒ offset `buf→canary = 64`, `buf→ret = 0x54 = 84`.

## Lỗ hổng phát hiện
- `read(0, buf, count)` không giới hạn `count` ⇒ stack overflow đè được cả canary lẫn return address.
- "Canary" là **giá trị tĩnh đọc từ file**, giống nhau ở MỌI tiến trình của instance ⇒ **brute-force được** (khác canary thật sinh từ `%gs:0x14`).

## Kỹ thuật khai thác — brute-force canary theo byte (bit-flip style)
Vì `memcmp` so 4 byte, nếu các byte ta **chưa ghi** vẫn là canary gốc thì chỉ cần khớp dần từng byte:
1. Với `i = 0..3`, thử `g = 0..255`, gửi `count = 64+i+1`, payload = `"A"*64 + canary_known + bytes([g])`. Nếu byte đoán đúng → `memcmp` pass → chương trình in **"Ok... Now Where's the Flag?"**; sai → in "***** Stack Smashing Detected *****". Mỗi guess là **một kết nối mới**.
2. Khi đủ 4 byte canary: payload = `"A"*64 + canary + "B"*16 + p32(win)`; `count = 88` → `ret` = `win`.
- Tối ưu tốc độ: chỉ đọc **dòng đầu** (`recvuntil(b'\n', timeout=3)`) thay vì `recvrepeat(1.5)` — vì tối đa ~1024 kết nối. DNS chập chờn → resolve IP trước (`socket.gethostbyname`) rồi `remote(IP, port)`.

## Exploit script
Xem file [exploit.py](exploit.py).

## Flag
`academy{redacted}`

## Bài học / pattern để tái sử dụng
- **Canary đọc từ file / biến toàn cục tĩnh** (thay vì `%gs:0x14`) ⇒ KHÔNG ngẫu nhiên theo tiến trình ⇒ brute-force từng byte qua nhiều kết nối. Dấu hiệu nhận biết: `checksec` báo "No canary" nhưng source có `memcpy(local, global_canary, N)` + `memcmp` thủ công.
- Brute-force cần **nhanh**: đọc đúng 1 dòng kết quả, timeout nhỏ; tránh `recvrepeat` dài ×1000.
- 32-bit: offset return address tính theo `ebp` (`buf`@`ebp-0x50` ⇒ ret cách 0x54), nhớ canary 4 byte + các slot đệm/saved reg ở giữa.
