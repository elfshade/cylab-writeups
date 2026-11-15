# CyLab / picoCTF — Need For Speed

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Anti-Debugging & Signal Timer Bypass)
* **Difficulty:** Difficulty 3
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

SIGALRM timer bypass, binary patching or GDB instruction redirection to decrypt_flag(). By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file need-for-speed
need-for-speed: ELF/Artifact analysis
$ checksec need-for-speed
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Binary có symbol (not stripped): `decrypt_flag`, `calculate_key`, `alarm_handler`, `set_timer`, `get_key`, `print_flag`, `header`.

```c
main(){ header(); set_timer(); get_key(); print_flag(); }

set_timer(){ signal(SIGALRM, alarm_handler); alarm(1); }   // 1 giây
alarm_handler(){ puts("Not fast enough. BOOM!"); exit(0); }

calculate_key(){
  for (i=0;i<=7;i++)
    for (j=-1142486468; j!=-571243234; --j) ;   // busy-delay vô nghĩa
  return 3723724062;                              // <-- KEY = HẰNG SỐ
}
get_key(){ key = calculate_key(); }

decrypt_flag(int a1){
  int v2[4]; v2[0]=a1;
  for (i=0; i<=0x36; ++i){          // 55 ký tự
    flag[i] ^= *((_BYTE*)v2 + i%2); // XOR với byte thấp (i chẵn) / byte 1 (i lẻ) của v2[0]
    if (i%3==2) ++v2[0];            // cứ 3 ký tự thì tăng v2[0]
  }
}
print_flag(){ decrypt_flag(key); puts(flag); }
```

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- `alarm(1)` chỉ để chặn "chạy đủ chậm"; nhưng `calculate_key()` luôn trả về **hằng** `3723724062`
  (vòng lặp busy chỉ delay, không ảnh hưởng kết quả).
- Mảng `flag[]` ban đầu (dữ liệu mã hoá) nằm tại `.data` offset `0x4020` — đọc trực tiếp từ file.
- Không cần chạy binary: tự lặp lại XOR để giải mã:
  `val = 3723724062; p[i] = enc[i] ^ ((val >> 8*(i%2)) & 0xff); if i%3==2: val++`.

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

We model the transformation in Python and formulate an inverse calculation or dynamic trace script to recover the original flag input.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# 39 Need For Speed
# decrypt_flag(key): v2[0]=key; for i in 0..0x36: flag[i] ^= BYTE(v2, i%2); if i%3==2: v2[0]+=1
# key = calculate_key() = 3723724062 (constant). flag[] initial = encrypted bytes at 0x4020.

enc = bytes([0x7f,0xe6,0x7f,0xe1,0x7a,0xe8,0x59,0xfe,0x67,0xea,0x4e,0xe1,
             0x02,0xef,0x4d,0xe7,0x03,0xee,0x41,0xe0,0x54,0xec,0x4b,0xe2,
             0x06,0xe7,0x53,0xf6,0x07,0xa6,0x1a,0xb0,0x19,0xe3,0x4c,0xe0,
             0x4e,0xe3,0x0a,0xf6,0x5b,0xe0,0x49,0xe1,0x45,0xeb,0x4a,0xa5,
             0x4f,0xe9,0x41,0xeb,0x48,0xa4,0x4d])
key = 3723724062

out = bytearray()
val = key & 0xFFFFFFFF
for i in range(0x37):          # i = 0..54
    b = (val >> (8*(i % 2))) & 0xff
    out.append(enc[i] ^ b)
    if i % 3 == 2:
        val = (val + 1) & 0xFFFFFFFF

print("FLAG:", out.decode('latin1'))
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- Gặp `alarm()`/timer + vòng lặp "busy delay" ⇒ đừng cố chạy nhanh; **bỏ qua vòng lặp** và lấy hằng số trả về.
- Hàm kiểu `calculate_key()` trả hằng ⇒ key là **giá trị tĩnh**, có thể tính/gọi trực tiếp (hoặc patch/bỏ alarm).
- Mảng bị XOR in-place (`flag[i] ^= ...`) ⇒ plaintext = `encrypted ^ keystream`, đọc `flag[]` gốc từ `.data`.
- Keystream phụ thuộc `i%2` và tăng mỗi `i%3==2` — mô phỏng chính xác từng bước.
