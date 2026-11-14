# MATRIX (Reverse Engineering — difficulty 3, picoMini by redpwn)

## Đề bài / file đính kèm
- Handout: binary `matrix` (stripped ELF x86-64), chạy được; service `nc mars.cylabacademy.net 31259`.
- Đề: "Enter the M A T R I X". Chương trình in banner rồi đọc các ký tự điều hướng; đích là tìm chuỗi `u/d/l/r` đưa nhân vật ra khỏi mê cung (nếu sai → "You were eaten by a grue.").
- Flag format: `picoCTF{...}`.

## Recon
- `file matrix`: ELF 64-bit, **stripped**, non-PIE.
- Decompile main (IDA MCP): cấp phát hai stack `malloc(0x800)`, struct VM `v9` gồm `code=0x20F0`, `IP` (16-bit), data-stack, return-stack, con trỏ `getc`/`putc`. Vòng `while(sub_1350(&v9,v7))`. Điều kiện thắng: `v7[0]==0` (không lỗi) và kết quả pop ra `v8==0` → in "Have a flag!" rồi `fopen("flag.txt")`.
- Nhận ra đây là **một máy ảo bytecode (Forth-like)** — không phải mê cung native. Code VM nằm ở file offset `0x20F0`, dài 1490 byte (`0x20F0`..`0x26C2`, hết `.rodata`).

## Lỗ hổng / cơ chế phát hiện
Reverse bằng cách **tự viết interpreter cho VM** thay vì đọc assembly:
- Opcode giải mã được: `0x00` nop, `0x01` halt(pop → result), `0x10` dup, `0x11` drop, `0x12` add, `0x13` sub(a-b), `0x14` swap, `0x20` >R, `0x21` R>, `0x30` jmp(pop target), `0x31` jz, `0x32` jnz, `0x33` jl, `0x34` jle, `0x80` push imm8(signed), `0x81` push imm16, `0xC0` getc→push, `0xC1` putc(pop).
- Chương trình in banner, vào loop `0x75`: `getc` rồi so từng ký tự với `u(0x75)/d(0x64)/l(0x6c)/r(0x72)`. Bất kỳ ký tự khác → nhảy tới cell "thua".
- Handler `u/d/l/r` cập nhật một tọa độ trên data-stack, rồi tại `0xef`:
  `push 123; swap; push 372; add; jmp` ⇒ nhảy tới `0x174 + position`.
- Vùng `0x174..` là **bảng ô mê cung 4 byte/ô**: `81 XX XX 30` = `push16 target; jmp` (target `0xfb`=grue/thua, hoặc `0x57f`/`0x574`…), một số ô `30 00 00 00` = `jmp` lấy target từ stack (đệ quy). Thắng khi tới `ip=0xf8`: `push 0; halt` (result=0).

## Kỹ thuật khai thác
Không cần map tay toàn bộ mê cung (~hàng nghìn ô). Dùng chính VM làm **oracle** và BFS trên không gian trạng thái:
- Trạng thái = `(ip, data_stack, return_stack)` tại thời điểm VM gọi `getc` (chưa đọc ký tự).
- Từ mỗi trạng thái, thử 4 ký tự `u/d/l/r`, chạy tới `getc` kế tiếp (trạng thái mới) hoặc tới `halt`. Nếu `halt` với `error==0 && result==0` → thắng; nếu halt với result khác (grue) → nhánh chết.
- BFS ghi lại đường đi. Depth limit ~200, dedupe theo key trạng thái.
- Kết quả: đường đi dài 63 ký tự:
  `rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd`
- Verify local: tạo `flag.txt` giả rồi `printf ... | ./matrix` → "Congratulations, you made it! / Have a flag!".
- Gửi lên remote `nc mars.cylabacademy.net 31259` → nhận flag.

## Exploit script
Xem file [exploit.py](exploit.py) — interpreter VM + BFS tìm đường, in path để pipe vào service.

## Flag
`picoCTF{redacted}`

## Bài học / pattern để tái sử dụng
- Gặp **custom VM / bytecode** trong RE: viết nhanh interpreter (kể cả đọc opcode từ disasm tay) rồi dùng nó làm oracle. Không cần hiểu 100% logic mê cung.
- **BFS trên trạng thái VM** (ip + data/return stack) là cách tổng quát để "giải" chương trình kiểu game/maze mà không cần reverse từng ô: treat mỗi lần `getc` như một node, mỗi ký tự là cạnh.
- Banner/điều kiện thắng nằm ngay trong decompile main (`patch`/`puts`/`fopen("flag.txt")`) — đọc main để biết chính xác trạng thái "thắng" cần đạt (`error==0 && result==0`).
