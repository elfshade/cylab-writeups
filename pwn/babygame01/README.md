# babygame01 (Pwn — difficulty 2, CyLab id 345)

## Đề bài / file đính kèm
- Game di chuyển trên bản đồ ASCII 2D (picoCTF "babygame01" ported to CyLab).
- Remote: `nc -v xebec.cylabacademy.net 36644`.
- Binary: 32-bit ELF (`game`).

## Recon
- Binary 32-bit, người dùng điều khiển nhân vật bằng các phím `w/a/s/d`.
- Cấu trúc dữ liệu: `map` là mảng 2D; player bắt đầu tại `(4,4)`; có biến `has_flag` nằm **ngay trước** `map` trong bộ nhớ (`map[-4]` theo chỉ số byte thực tế của game).
- Nếu `has_flag != 0` khi người chơi bấm `p` (gọi `solve_round`) → in flag.

## Lỗ hổng phát hiện
Di chuyển **không kiểm tra biên**. Đi lên (`w`) làm giảm chỉ số hàng; đi sang trái (`a`) làm giảm chỉ số cột. Kết hợp lại có thể ghi ra ngoài mảng `map`, cụ thể chạm tới `has_flag` nằm ở `map-4`.

## Kỹ thuật khai thác
Di chuyển nhân vật tới toạ độ `(0, -4)` — tức đi lên 4 bước và sang trái 8 bước — sao cho ghi đè `has_flag` thành giá trị khác 0. Sau đó bấm `p` để chương trình kiểm tra `has_flag` và in flag.

Thứ tự gửi chuỗi trong 1 dòng (remote dùng tty canonical nên phải gửi kèm newline/là một dòng):
`"a"*8 + "w"*4 + "p"`.

## Exploit script
Xem file [exploit.py](exploit.py).

```python
io.sendline(b"a" * 8 + b"w" * 4 + b"p")   # (0,-4) => set has_flag, rồi solve_round
```

## Flag
`academy{redacted}`

## Bài học / pattern để tái sử dụng
- Game "di chuyển không kiểm tra biên" ⇒ OOB read/write trên mảng `map`; nhắm vào biến lân cận (ở đây `has_flag` nằm trước `map`).
- Remote CyLab đôi khi đứng sau tty canonical → gửi input thành **một dòng** (kèm newline), đừng `recvuntil` chờ từng ký tự.
