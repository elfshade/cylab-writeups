# CyLab Security Academy & picoCTF Writeups

Tổng hợp writeup cá nhân, phân tích root cause và mã khai thác (exploit script) các challenge từ **CyLab Security Academy** và **picoCTF**.

Tập trung vào 2 mảng chính:
- **Binary Exploitation (Pwn)**: Stack overflow, Format String, Heap Use-After-Free (UAF), glibc tcache internals, Ret2libc, 16-byte stack alignment.
- **Reverse Engineering (Rev)**: Custom VM bytecode emulation, Graph BFS search, Rust binary reversing, SPN S-Box inversion, JIT shellcode synthesis, Binary diffing.

> **Lưu ý:** Toàn bộ flag trên các bài viết công khai đều được ẩn theo định dạng `academy{redacted}` / `picoCTF{redacted}`.

---

## Cấu trúc thư mục

```text
cylab-writeups/
├── pwn/                              # Binary Exploitation
│   ├── babygame01/                   # 2D Array OOB write, ghi đè biến lân cận trên stack
│   ├── buffer-overflow-3/            # Brute-force static stack canary từng byte (linear search)
│   ├── heres-a-libc/                 # 64-bit Ret2libc, leak GOT qua puts, 16-byte stack alignment
│   ├── stonks/                       # Format string leak bộ nhớ stack qua %p, unpack little-endian
│   └── unsubscriptions-are-free/     # Heap Use-After-Free (UAF) & tái sử dụng chunk qua glibc tcache
├── rev/                              # Reverse Engineering
│   ├── breadth/                      # Binary diffing (cmp -l) & khoanh vùng 16K hàm dead-code
│   ├── checkpass/                    # Reverse stripped Rust binary, giải mã ngược 4 vòng SPN S-Box
│   ├── matrix/                       # Forth-like VM bytecode emulation, giải mê cung bằng BFS
│   ├── pico-bank/                    # Reverse Android APK (Smali), Dalvik register reuse & stego
│   └── rolling-my-own/               # JIT shellcode synthesis, brute-force MD5 preimage với OpenMP
└── README.md
```

---

## Danh sách Writeup

### 1. Binary Exploitation (Pwn)

| # | Bài toán | Nền tảng | Độ khó | Kỹ thuật / Lỗ hổng chính | Writeup |
|---|---|---|---|---|---|
| 1 | [Unsubscriptions Are Free](https://play.picoctf.org/) | CyLab / picoCTF | Medium | Heap Use-After-Free (UAF), glibc tcache LIFO reuse, stdio buffering trap | [Đọc writeup](pwn/unsubscriptions-are-free/README.md) |
| 2 | [Here's a LIBC](https://play.picoctf.org/) | CyLab / picoCTF | Medium | 64-bit Ret2libc, leak GOT qua `puts`, x86-64 stack alignment (16-byte RSP) | [Đọc writeup](pwn/heres-a-libc/README.md) |
| 3 | [buffer overflow 3](https://play.picoctf.org/) | CyLab / picoCTF | Medium | Brute-force static canary từng byte ($O(256 \times N)$ thay vì $O(256^N)$) | [Đọc writeup](pwn/buffer-overflow-3/README.md) |
| 4 | [Stonks](https://play.picoctf.org/) | CyLab / picoCTF | Easy | Format string (`%p`) leak stack memory, giải mã Little-Endian word | [Đọc writeup](pwn/stonks/README.md) |
| 5 | [babygame01](https://play.picoctf.org/) | CyLab / picoCTF | Easy | 2D Array Out-Of-Bounds (OOB) write, di chuyển toạ độ âm ghi đè `has_flag` | [Đọc writeup](pwn/babygame01/README.md) |

---

### 2. Reverse Engineering (Rev)

| # | Bài toán | Nền tảng | Độ khó | Kỹ thuật / Lỗ hổng chính | Writeup |
|---|---|---|---|---|---|
| 1 | [MATRIX](https://play.picoctf.org/) | CyLab / picoCTF | Hard | Viết interpreter cho Forth-like VM, BFS trên không gian trạng thái tìm đường | [Đọc writeup](rev/matrix/README.md) |
| 2 | [Checkpass](https://learn.cylabacademy.org/) | CyLab / picoCTF | Hard | Reverse stripped Rust binary, giải mã ngược 4 vòng SPN (S-Box + Permutation) | [Đọc writeup](rev/checkpass/README.md) |
| 3 | [Rolling My Own](https://learn.cylabacademy.org/) | CyLab / picoCTF | Hard | JIT shellcode synthesis, brute-force MD5 preimage song song bằng C + OpenMP | [Đọc writeup](rev/rolling-my-own/README.md) |
| 4 | [Pico Bank](https://learn.cylabacademy.org/) | CyLab / picoCTF | Medium | Reverse Android APK Smali, xử lý bẫy Dalvik register reuse, decode stego nhị phân | [Đọc writeup](rev/pico-bank/README.md) |
| 5 | [Breadth](https://play.picoctf.org/) | CyLab / picoCTF | Hard | Differential binary analysis (patch diffing v1/v2), lọc nhiễu 16K hàm dead-code | [Đọc writeup](rev/breadth/README.md) |

---

## Môi trường & Công cụ

* **Hệ điều hành:** Linux x86_64
* **Disassembly & Decompilation:** IDA Pro, Ghidra, `objdump`
* **Dynamic Debugging:** GDB với plugin `pwndbg`
* **Exploitation / Scripting:** Python 3, `pwntools`
* **Reconnaissance & Static Analysis:** `file`, `checksec`, `strings`, `nm`, `readelf`, `cmp`
