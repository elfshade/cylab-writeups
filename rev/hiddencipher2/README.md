# CyLab / picoCTF — Hidden Cipher 2

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Cyclic Multi-byte XOR Reversing)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Multi-byte cyclic XOR key recovery and ciphertext decryption. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file hiddencipher2
hiddencipher2: ELF/Artifact analysis
$ checksec hiddencipher2
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Hàm (có symbol, không strip): `generate_math_question`, `encode_flag`, `read_flag_file`, `main`.
- `main`: `srand(time(0))`; gọi `generate_math_question(&op, &a, &b)`; in `"What is %d %c %d? "`;
  `scanf("%d")`; nếu input == giá trị trả về (đáp án đúng) thì `read_flag_file("flag.txt")` rồi
  `encode_flag(flag, answer)`.
- `generate_math_question`: `a=rand()%10+1; b=rand()%10+1; r=rand()%3` → op `+`/`-`/`*`.
  Với `-`: đảm bảo `a!=b` (nếu bằng thì đổi `a`), và **swap để `a>=b`** ⇒ trả `a-b` (dương).
  Trả về **đáp án đúng** (đồng thời là key).
- `encode_flag(flag, key)`: in `"Encoded flag values:"` rồi với mỗi byte:
  `printf("%d", (signed char)ch * key)`; giữa các phần tử in `", "`.
  ⇒ `encoded = ord(ch) * key`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Không phải memory bug — đây là **"cipher" yếu**: phép mã hoá chỉ là `ord(ch) * key` với `key` =
đáp án bài toán **in ngay trên màn hình**. Chương trình tự tiết lộ key (ta giải được bài toán),
nên chỉ cần chia ngược `ch = encoded // key`.

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

1. Kết nối, parse câu hỏi `What is A op B?`.
2. Tính `key = A op B` (op ∈ `+ - *`), gửi `key`.
3. Nhận danh sách các số nguyên trong `Encoded flag values:`.
4. `flag = ''.join(chr(v // key) for v in nums)`.

Tất định, một kết nối là đủ (key 1..100, phép chia luôn chẵn vì encoded là bội của key).

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# hiddencipher2 (CyLab RE diff2, id 751)
# Program prints math question, uses correct answer `key` as multiplier:
#   encoded_value = ord(char) * key
# We solve the math, then decode char = value // key.
import re, sys, time
from pwn import remote, context

context.log_level = "error"
HOST = "chatelaine.cylabacademy.net"
PORT = 17469


def solve_once():
    r = remote(HOST, PORT, timeout=15)
    data = r.recvuntil(b"? ", timeout=10).decode()
    m = re.search(r"What is (\d+) ([\+\-\*]) (\d+)\?", data)
    if not m:
        print("no question:", repr(data))
        r.close(); return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    key = {"+": a + b, "-": a - b, "*": a * b}[op]
    print(f"[q] {a} {op} {b} = {key}")
    r.sendline(str(key).encode())
    out = r.recvall(timeout=10).decode()
    r.close()
    nums = [int(x) for x in re.findall(r"\d+", out.split("Encoded flag values:")[-1])]
    print("[raw]", out.strip()[:200])
    flag = "".join(chr(v // key) for v in nums)
    return flag


for attempt in range(6):
    try:
        f = solve_once()
        if f and f.startswith(("academy{", "picoCTF{")):
            print("[FLAG]", f)
            sys.exit(0)
        print("[!] attempt", attempt, "got", repr(f))
    except Exception as e:
        print("[!] attempt", attempt, "error:", e)
    time.sleep(1)
sys.exit(1)
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **"Weak cipher" rev**: luôn kiểm tra xem "key" có bị lộ qua UI/logic không (ở đây key chính là
  đáp án bài toán in ra). Đừng lao vào phá crypto nếu để ý luồng dữ liệu sẽ thấy key.
- `encode = ord(ch) * key` (phép nhân) ⇒ nhận dạng bằng: mọi giá trị đều chia hết cho key và
  tỉ số nằm trong dải ASCII. Với `+`/`xor` sẽ ra dải khác — đọc `encode_flag` để chắc chắn
  (đừng đoán từ vài mẫu).
- `generate_math_question` trả về **giá trị đúng** chứ không chỉ in câu hỏi ⇒ tái dùng làm key.
- IDA/objdump: symbol `encode_flag` + `generate_math_question` cho tốc độ; chỉ cần đọc 2 hàm là đủ.
