# breadth (Reverse Engineering — difficulty 3)

## Đề bài / file đính kèm
- Challenge CyLab id 220, event `picoMini by redpwn`.
- Đề: "Surely this is what people mean when they say 'horizontal scaling,' right?"
  Kèm gợi ý: "Our operatives managed to exfiltrate an in-development version of this challenge, where the function with the real flag had a mistake in it. Can you help us get the flag?"
- Hai binary tải về:
  - `breadth.v1` — bản in-development (có "mistake").
  - `breadth.v2` — bản phát hành (đã sửa).
  - Cả hai ELF 64-bit PIE, **not stripped**, ~2.6 MB, 16384 hàm `fcn*`.

## Recon
- `file`: ELF 64-bit PIE, not stripped.
- `strings | grep picoCTF{ | wc -l` → **16384** flag (toàn `picoCTF{...}` 32 ký tự) ⇒ mỗi hàm có 1 flag decoy.
- `main` (0x1040) chỉ in `"Dead code? What's that?"` rồi `"Goodbye!"` — **không gọi hàm nào**.
- Toàn bộ 16384 hàm `fcnXXXXX` là dead code, mỗi hàm theo mẫu:
  ```text
  mov <reg>, <CONST_A>      ; "giá trị tính được"
  ...
  cmp <reg>, <CONST_B>      ; hằng số "kỳ vọng"
  jz  print_flag
  retn
  print_flag:
    lea rdi, "picoCTF{...}"
    jmp puts
  ```
  Nếu `<CONST_A> == <CONST_B>` thì hàm mới in flag; mặc định **không bằng** ⇒ không hàm nào in được.
- Không có xref/constructor nào gọi các hàm này (0 hàm `fcn*` có `call`).

## Lỗ hổng phát hiện
Ý tưởng chính là **so sánh hai phiên bản binary**. `breadth.v1` và `breadth.v2` chỉ khác nhau **36 byte**:
- 20 byte: `.note.gnu.build-id` (nhiễu, luôn khác).
- 15 byte tại file offset `0x9504B..0x9505B` (trong `.text`, vaddr == file offset): **code thật khác**.
- 1 byte trong `.strtab` tại `0x253753` (`'1'→'2'`).

Hàm tại `0x95040` là `fcnkKTQpF`.

## Kỹ thuật khai thác
So sánh disassembly của hai phiên bản:

`breadth.v1` (bản có lỗi — 2 hằng số khác nhau nên không bao giờ in):
```text
95040: mov [rsp+var_10], 41BC73Eh
95049: mov rdx, [rsp+var_10]
9504e: mov eax, 0D037803Ah
95053: cmp rdx, rax            ; 0x41BC73E != 0xD037803A  -> nhảy 95060 KHÔNG xảy ra
95056: jz  loc_95060
95058: retn
95060: lea rdi, "picoCTF{...}"
95067: jmp puts
```

`breadth.v2` (bản đã sửa — hằng số khớp):
```text
95040: mov [rsp+var_10], 41BC73Eh
95049: mov rax, [rsp+var_10]
9504e: cmp rax, 41BC73Eh        ; bằng nhau -> in flag
95054: jz  loc_95060
95056: retn
95060: lea rdi, "picoCTF{...}"
95067: jmp puts
```

⇒ Hàm "có lỗi" trong bản in-development chính là `fcnkKTQpF`, và flag gắn với nó là flag thật. Chỉ cần diff hai binary để khoanh vùng hàm, rồi đọc flag string của nó.

## Exploit script
Xem file [exploit.py](exploit.py) — diff v1/v2, tìm vùng code khác nhau, đọc flag string.

## Flag
`picoCTF{redacted}`
(raw, KHÔNG bọc `academy{}` — nộp nguyên chuỗi `picoCTF{...}` mới đúng.)

## Bài học / pattern để tái sử dụng
- Challenge có 2 phiên bản binary ("in-development" vs "released") ⇒ **`cmp -l v1 v2`** (hoặc `python3` so từng byte) lọc nhiễu build-id rồi tìm vùng `.text` khác nhau; đó chính là chỗ chứa "mistake" ⇒ hàm/flag thật.
- Binary khổng lồ nhiều hàm dead-code giống hệt nhau: đừng decompile từng hàm; tìm điểm khác biệt theo **diff byte** hoặc tìm hàm thỏa điều kiện tự-nhất-quán (`CONST_A == CONST_B` trong mẫu `mov constA; cmp constB; jz print`).
- Flag CyLab: **một số bài nộp RAW `picoCTF{...}`, không bọc `academy{}`** — thử cả hai dạng khi bị `correct:false`.
