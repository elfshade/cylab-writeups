# Rolling My Own (CyLab Academy / picoCTF 2021 — Pwn/RE, difficulty 3)

## Đề bài / file đính kèm
- File `remote` (ELF x86-64 PIE, stripped) + service `nc chatelaine.cylabacademy.net 42233`.
- Mô tả: *"I don't trust password checkers made by other people, so I wrote my own. It doesn't even need to store the password! If you can crack it I'll give you a flag."*
- Hints: dựa trên paper (JIT-CC, 2006) và password bắt đầu bằng `D1v1`.

## Recon
- `file remote` → ELF 64-bit PIE, stripped.
- IDA: `main` đọc password 16 ký tự, `v13 = "GpLaMjEWpVOjnnmkRGiledp6Mvcezxls"`, `v11 = {8,2,7,1}`.
- Với mỗi nhóm 4 ký tự password: `dest = pw[4i:4i+4] + v13[8i:8i+8]` rồi `ptr[16i:16i+16] = MD5(dest)`.
- `code[4k+j] = ptr[16k + j + v11[k]]` → 16 byte shellcode; `mmap` RWX; gọi `shellcode(rdi = sub_180F)`.
- `sub_180F`: nếu `a1 == 0x7B3DC26F1` thì mở `flag` và in; ngược lại in "Hmmmmmm... not quite".
- Mô hình MD5 + suffix + offset được kiểm chứng bằng gdb (khớp chính xác `pw="AAAAAAAAAAAAAAAA"` → `44299c04746859aef350804ce5f28685`).

## Lỗ hổng phát hiện
Password không được lưu; việc kiểm tra là **sinh code (JIT)** rồi chạy code đó. Vậy ta chỉ cần chọn 16 byte shellcode gọi `sub_180F(magic)`; mỗi nhóm 4 byte của shellcode là **ảnh của một hàm MD5** theo nhóm password tương ứng ⇒ cần tìm **preimage** cho từng chunk.

## Kỹ thuật khai thác
1. Shellcode tối thiểu (12 byte): `push rdi` (`57`) lưu con trỏ `sub_180F` → `mov rdi, 0x7B3DC26F1` (`48 bf f1 26 dc b3 07 00 00 00`) → `ret` (`c3`). Khi chạy, `ret` nhảy vào `sub_180F` với `rdi = magic`.
2. Sinh **nhiều** biến thể shellcode hợp lệ (nhiều cách mã hoá hằng số 35-bit: imm64; `mov edi,V>>s; shl rdi,s; add rdi,r`; dựng trong `rax` rồi `push rax; pop rdi`; nhiều cách save/call: `push rdi`+`ret`/`jmp [rsp]`, `mov rbx/rax/rcx/rdx/rsi,rdi`+`call/jmp reg`; chèn NOP đa byte để dịch chunk).
3. Thu tất cả **chunk 4 byte** của các shellcode làm target; brute-force `254^4` (loại byte `0x00`, `0x0a`) cho mỗi nhóm bằng MD5 tự viết + OpenMP (unrolled), dùng hash table cho target 4-byte đầy đủ. 4 nhóm mất ~4 phút trên 12 luồng.
4. Ghép: chọn shellcode mà **mọi chunk đều có preimage**; password = nối các preimage 4 byte (chunk all-wildcard thì tuỳ ý) → 38 shellcode khả thi.
5. Gửi password (16 byte thô + newline) tới service.

Lưu ý: hằng số phải đúng `0x7B3DC26F1`; chú ý `mov rdi, imm64` cần byte `f1 26 dc b3 07` (dễ nhầm `dc`↔`c2`).

## Exploit script
Xem file [exploit.py](exploit.py) (kèm [gen.py](gen.py) sinh shellcode, [bfall.c](bfall.c) brute-force, [final.py](final.py) ghép).

## Flag
`academy{redacted}`

## Bài học / pattern để tái sử dụng
- **JIT password checker**: khi chương trình *sinh code từ input rồi chạy code đó*, input chỉ cần là **preimage** của một shellcode hợp lệ — không cần đúng password gốc.
- Hash dùng để "nhúng" dữ liệu vào code: mỗi vùng độc lập ⇒ tìm preimage riêng từng vùng, ghép lại. Vùng wildcard (byte không thực thi) miễn ràng buộc.
- Brute-force MD5: tự viết MD5 unrolled + OpenMP (`-O3 -march=native -fopenmp`), scan `254^4` ~4.16e9 chỉ ~50 giây/nhóm; dùng hash table khi nhiều target.
- Luôn kiểm chứng mô hình (offset/hằng số) bằng gdb trước khi brute-force.
