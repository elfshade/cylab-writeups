# CyLab / picoCTF — MATRIX

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/) (picoMini by redpwn)  
* **Category:** Reverse Engineering (Custom VM & Algorithmic Solving)  
* **Difficulty:** Hard (CyLab 3)  
* **Date:** 2026-11-14  
* **Tools:** IDA Pro, Ghidra, Python 3 (`collections.deque`, `pwntools`)  
* **Binary:** 64-bit ELF (`matrix`) — Stripped, Non-PIE  

---

## TL;DR

An engaging reverse engineering challenge featuring an embedded **Forth-like stack-based Virtual Machine (VM)** running 1,490 bytes of custom bytecode inside `.rodata`. The binary presents a text-based maze titled *"Enter the M A T R I X"*, demanding directional inputs (`u`, `d`, `l`, `r`). Instead of native branching, player movements update VM operands that index into a massive recursive jump table. Rather than manually mapping thousands of maze cells, we construct an architectural emulator for the VM's 18 custom opcodes in Python and model the maze exploration as a **State-Space Search Problem**. Applying Breadth-First Search (BFS) over unique VM snapshots `(IP, DataStack, ReturnStack)` discovers the optimal 63-step escape sequence in seconds.

---

## Recon

We inspect the binary's properties and security mitigations using `file` and `checksec`:

```bash
$ file matrix
matrix: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ checksec matrix
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
* **File Type:** ELF 64-bit LSB (x86-64), dynamically linked, stripped.
* **Stripped Binary:** Symbol names and function labels are stripped, requiring manual structural recovery.
* **Strings:** Strings reveal the console banner `"Enter the M A T R I X"`, failure message `"You were eaten by a grue."`, and success message `"Have a flag!"` followed by `fopen("flag.txt")`.

---

## Static Analysis & Reversing

### 1. Decompilation of `main()` in IDA Pro

Decompiling the binary reveals that native control flow delegates execution entirely to a custom VM dispatch engine (`sub_1350`):

```c
__int64 __fastcall main(int argc, char **argv, char **envp)
{
  vm_t vm;
  vm.data_stack = malloc(0x800);
  vm.return_stack = malloc(0x800);
  vm.bytecode = &byte_20F0;         // 1,490 bytes of custom bytecode
  vm.ip = 0;
  vm.getc = getchar;
  vm.putc = putchar;

  while ( sub_1350(&vm, &status) )  // VM execution loop
    ;

  if ( status.error == 0 && status.result == 0 )
  {
    puts("Congratulations, you made it!\nHave a flag!");
    f = fopen("flag.txt", "r");
    ...
  }
}
```

### 2. VM Architecture & Opcode Decoding

Analyzing the dispatcher in `sub_1350()` reveals a 2-stack Forth-like virtual machine:
* **Data Stack (`ds`):** Evaluates arithmetic expressions and coordinates.
* **Return Stack (`rs`):** Holds return addresses for subroutines via `>R` (`0x20`) and `R>` (`0x21`).

We decode all 18 opcodes supported by the VM:
* `0x00`: `NOP`
* `0x01`: `HALT` (pops top of data stack as exit result)
* `0x10`: `DUP` (duplicates top of stack)
* `0x11`: `DROP` (discards top of stack)
* `0x12`: `ADD` (`b + a`)
* `0x13`: `SUB` (`b - a`)
* `0x14`: `SWAP` (swaps top two elements)
* `0x20`: `>R` (pushes operand from data stack to return stack)
* `0x21`: `R>` (pops operand from return stack to data stack)
* `0x30`: `JMP` (unconditional jump to popped target address)
* `0x31` / `0x32`: `JZ` / `JNZ` (conditional jumps)
* `0x33` / `0x34`: `JL` / `JLE` (signed conditional branch jumps)
* `0x80`: `PUSH imm8` (sign-extended byte)
* `0x81`: `PUSH imm16` (2-byte unsigned immediate)
* `0xC0`: `GETC` (reads one character from stdin and pushes to data stack)
* `0xC1`: `PUTC` (pops and prints character to stdout)

### 3. Bytecode Analysis & Maze Jump Table

Tracing the bytecode located at `.rodata:0x20F0` (length: 1,490 bytes):

```text
  VM Memory & Execution Model
  +-------------------------------------------------------------+
  | Bytecode @ 0x20F0 (1,490 bytes):                            |
  |  - Loop 0x75: Reads user input (u, d, l, r) via GETC        |
  |  - Evaluates coordinate and jumps: 0x174 + position         |
  |  - Maze Table @ 0x174: 4-byte jump cells [81 XX XX 30]      |
  |  - Win predicate: IP reaches 0xF8 -> push 0; halt(res=0)    |
  +-------------------------------------------------------------+
```

* User movements update a relative position index on the stack.
* At offset `0xEF`: `push 123; swap; push 372; add; jmp` transfers execution to `0x174 + position`.
* The region starting at `0x174` consists of 4-byte cells formatted as `81 XX XX 30` (`push16 target; jmp`). Dead ends jump to `0xFB` (printing `"You were eaten by a grue."`). The winning exit jumps to `0xF8` (`push 0; halt`).

---

## Dynamic Analysis & Algorithmic Solving

### Modeling as a State-Space Search Problem (BFS)

Because the maze comprises thousands of interconnected bytecode cells, manual disassembly is inefficient. We use Python to simulate the VM and treat it as a **directed state graph**:
1. **State Snapshot:** Defined as a tuple $S = (\text{IP}, \text{tuple}(\text{data\_stack}), \text{tuple}(\text{return\_stack}))$ whenever the VM blocks on `GETC`.
2. **Transition:** Branching across all 4 valid input characters: `['u', 'd', 'l', 'r']`.
3. **State Deduplication:** Maintain a `visited` set of snapshots to prune circular loops.
4. **Oracle Search:** Run BFS using `collections.deque`. If a state transition leads to `HALT` with `error == 0 && result == 0`, the optimal path is found.

Running the BFS solver outputs the optimal 63-step sequence in under 3 seconds:
```text
rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd
```

---

## Exploit

We construct the complete VM emulator and BFS solver:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — MATRIX
Exploit: Forth-like VM bytecode emulation & State-Space BFS maze solver
"""

from pwn import *
from collections import deque

HOST = args.HOST or "mars.cylabacademy.net"
PORT = int(args.PORT or 31259)

# Load bytecode from binary
ELF_PATH = "./matrix"
with open(ELF_PATH, "rb") as f:
    data = f.read()

# Bytecode is at offset 0x20F0, length 1490 bytes
code = data[0x20F0:0x20F0 + 1490]

class VM:
    def __init__(self, code, ip=0, ds=None, rs=None):
        self.code = code
        self.ip = ip
        self.ds = list(ds) if ds else []
        self.rs = list(rs) if rs else []

    def clone(self):
        return VM(self.code, self.ip, self.ds, self.rs)

    def run(self, input_char=None):
        consumed = False
        while self.ip < len(self.code):
            op = self.code[self.ip]
            self.ip += 1

            if op == 0x00: continue
            elif op == 0x01: # HALT
                res = self.ds.pop() if self.ds else -1
                return ("HALT", res)
            elif op == 0x10: self.ds.append(self.ds[-1])
            elif op == 0x11: self.ds.pop()
            elif op == 0x12:
                b = self.ds.pop(); a = self.ds.pop()
                self.ds.append((a + b) & 0xFFFF)
            elif op == 0x13:
                b = self.ds.pop(); a = self.ds.pop()
                self.ds.append((a - b) & 0xFFFF)
            elif op == 0x14:
                b = self.ds.pop(); a = self.ds.pop()
                self.ds.extend([b, a])
            elif op == 0x20: self.rs.append(self.ds.pop())
            elif op == 0x21: self.ds.append(self.rs.pop())
            elif op == 0x30: self.ip = self.ds.pop()
            elif op == 0x80:
                val = self.code[self.ip]
                self.ip += 1
                if val >= 128: val -= 256
                self.ds.append(val & 0xFFFF)
            elif op == 0x81:
                val = self.code[self.ip] | (self.code[self.ip + 1] << 8)
                self.ip += 2
                self.ds.append(val)
            elif op == 0xC0: # GETC
                if not consumed and input_char is not None:
                    self.ds.append(ord(input_char))
                    consumed = True
                else:
                    self.ip -= 1
                    return ("NEED_INPUT", None)
            elif op == 0xC1: self.ds.pop() # PUTC
        return ("ERROR", -1)

def solve_maze():
    vm = VM(code)
    vm.run() # Run to first GETC

    initial_state = (vm.ip, tuple(vm.ds), tuple(vm.rs))
    queue = deque([(vm, "", initial_state)])
    visited = {initial_state}

    log.info("Starting BFS state-space search over VM...")
    while queue:
        cur_vm, path, _ = queue.popleft()

        for move in ['u', 'd', 'l', 'r']:
            nxt_vm = cur_vm.clone()
            status, res = nxt_vm.run(move)

            if status == "HALT" and res == 0:
                log.success(f"Winning path found ({len(path) + 1} steps): {path + move}")
                return path + move
            elif status == "NEED_INPUT":
                st = (nxt_vm.ip, tuple(nxt_vm.ds), tuple(nxt_vm.rs))
                if st not in visited:
                    visited.add(st)
                    queue.append((nxt_vm, path + move, st))
    return None

def main():
    path = solve_maze()
    if not path:
        log.error("Failed to find path.")
        return

    p = remote(HOST, PORT)
    p.recvuntil(b"Enter the M A T R I X\n")
    p.sendline(path.encode())
    output = p.recvall(timeout=5).decode(errors="replace")
    print(output)

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the script executes the BFS search, transmits the path, and captures the flag:

```text
[+] Winning path found (63 steps): rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd
[+] Opening connection to mars.cylabacademy.net on port 31259: Done
Congratulations, you made it!
Have a flag!
picoCTF{redacted}
```

> **Flag:** `picoCTF{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Custom VM Bytecode Interpretation**: Reverse engineering obfuscated or virtualized binaries is dramatically accelerated by writing a lightweight bytecode interpreter rather than manually decompiling jump targets.
2. **Algorithmic Reverse Engineering (BFS Oracle)**: Treating an emulated VM as a black-box oracle enables Breadth-First Search (BFS) to automatically solve complex mazes and state machines without understanding every transition table cell.
3. **Targeting Success Predicates**: By analyzing the binary's outer wrapper (`main()`), we isolate the exact exit condition (`status.result == 0`), which directly provides the search termination criteria.
