# MATRIX — Forth-like Custom Virtual Machine & BFS State-Space Search

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/) (picoMini by redpwn)  
**Category:** Reverse Engineering (Custom VM & Algorithmic Solving)  
**Difficulty:** Hard (CyLab Difficulty 3)  
**Tools:** IDA Pro, Ghidra, Python 3 (`collections.deque`, `pwntools`)  
**Binary:** 64-bit ELF (`matrix`) — Stripped, Non-PIE  

---

## TL;DR

The target binary presents a text-based maze titled *"Enter the M A T R I X"*, demanding directional inputs (`u`, `d`, `l`, `r`). Instead of native control flow, reverse engineering `main()` reveals an embedded, stack-based **Forth-like Virtual Machine (VM)** running 1,490 bytes of custom bytecode stored in `.rodata`. Rather than manually deciphering thousands of maze table jump cells, I built an architectural emulator for the VM's 18 custom opcodes in Python and modeled the maze exploration as a **State-Space Search Problem**. Applying Breadth-First Search (BFS) over unique VM snapshots `(IP, DataStack, ReturnStack)` at each input gate discovered the optimal 63-step escape sequence in under 3 seconds.

---

## Student's Learning Note: Core Concepts

As a 2nd-year Computer Science student, this challenge was an incredible intersection of **Computer Systems Architecture** and **Data Structures & Algorithms (DSA)**:

1. **Stack-Based Virtual Machines (Forth Model):** Unlike register-based architectures (x86/ARM), a stack machine performs all arithmetic, logic, and branch evaluations on a Last-In, First-Out (LIFO) operand stack. Forth-like systems introduce two distinct stacks:
   * **Data Stack (`ds`):** Evaluates arithmetic expressions and holds active local variables.
   * **Return Stack (`rs`):** Stores return addresses for subroutines or temporarily stashes data via transfer opcodes (`>R` and `R>`).
2. **State-Space Representation:** A running computer program can be formalized as a directed graph. A single node represents a discrete system state $S = (IP, \text{Stack}_{\text{data}}, \text{Stack}_{\text{return}})$, and an edge represents a deterministic state transition triggered by external user input.
3. **Graph Search (BFS as an Oracle):** Because all transitions are deterministic, we can treat the emulated VM as a black-box oracle. BFS guarantees the shortest path to a terminal node meeting the success predicate (`error == 0 && result == 0`) while eliminating cyclical paths via state deduplication.

---

## Reconnaissance & Binary Analysis

Inspecting the binary with `file` and `checksec`:

```bash
$ file matrix
matrix: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ checksec matrix
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

Running the executable outputs:
```text
WELCOME to the M A T R I X
Can you make it out alive?
```
Entering arbitrary keystrokes terminates with:
```text
You were eaten by a grue.
```

### Decompiling `main()`

Opening the binary in IDA Pro reveals a surprisingly compact driver routine. Two 2,048-byte memory regions are allocated via `malloc(0x800)` to serve as execution stacks, followed by the initialization of a VM structure:

```c
struct VM {
    uint8_t  *code;         // Points to .rodata at 0x20F0 (Length: 1490 bytes)
    uint16_t  ip;           // 16-bit Instruction Pointer
    int16_t  *data_stack;   // LIFO Data Stack pointer
    int16_t  *return_stack; // LIFO Return Stack pointer
    int     (*getc_fn)();   // Input callback (wraps getchar)
    void    (*putc_fn)();   // Output callback (wraps putchar)
};
```

The execution loop delegates execution to an interpreter dispatch function:

```c
while (vm_step(&vm, &status)) {
    // Stepping cycle continues until vm_step returns 0
}

if (status.error == 0 && status.result == 0) {
    puts("Congratulations, you made it!\nHave a flag!");
    FILE *f = fopen("flag.txt", "r");
    // Prints the flag content
} else {
    puts("You were eaten by a grue.");
}
```

**Key Discovery:** The winning state is purely mathematical: the VM must halt with **`error == 0`** and the popped result code must be **`0`**.

---

## Instruction Set Architecture (ISA) Reverse Engineering

Analyzing the bytecode dispatcher (`vm_step`) revealed a custom 16-bit stack-machine ISA. Below is the decoded specification reconstructed from disassembly:

| Opcode | Mnemonic | Operands | Operation / Semantics |
| :---: | :--- | :--- | :--- |
| `0x00` | `NOP` | None | No operation. |
| `0x01` | `HALT` | None | Pops top of Data Stack into `result`; terminates VM execution. |
| `0x10` | `DUP` | None | Duplicates the top value on the Data Stack: `[a] -> [a, a]`. |
| `0x11` | `DROP` | None | Discards the top value from the Data Stack: `[a] -> []`. |
| `0x12` | `ADD` | None | Pops `b`, pops `a`, pushes signed 16-bit sum: `(a + b) & 0xFFFF`. |
| `0x13` | `SUB` | None | Pops `b`, pops `a`, pushes signed 16-bit difference: `(a - b) & 0xFFFF`. |
| `0x14` | `SWAP` | None | Swaps the top two values on the Data Stack: `[a, b] -> [b, a]`. |
| `0x20` | `>R` | None | Moves top of Data Stack to Return Stack: `ds.pop() -> rs.push()`. |
| `0x21` | `R>` | None | Moves top of Return Stack to Data Stack: `rs.pop() -> ds.push()`. |
| `0x30` | `JMP` | None | Pops target address from Data Stack: `IP = ds.pop()`. |
| `0x31` | `JZ` | None | Pops `target`, pops `cond`; jumps to `target` if `cond == 0`. |
| `0x32` | `JNZ` | None | Pops `target`, pops `cond`; jumps to `target` if `cond != 0`. |
| `0x33` | `JL` | None | Pops `target`, pops `cond`; jumps to `target` if `cond < 0` (signed). |
| `0x34` | `JLE` | None | Pops `target`, pops `cond`; jumps to `target` if `cond <= 0` (signed). |
| `0x80` | `PUSH8` | `imm8` | Fetches signed 8-bit immediate byte, pushes to Data Stack. |
| `0x81` | `PUSH16`| `imm16`| Fetches unsigned 16-bit little-endian word, pushes to Data Stack. |
| `0xC0` | `GETC` | None | Reads a character from user input and pushes its ASCII value. |
| `0xC1` | `PUTC` | None | Pops character code from Data Stack and outputs to stdout. |

---

## Bytecode Logic & The Maze Structure

Tracing the bytecode flow from `IP = 0x0000`:
1. The VM executes initialization routines, prints the banner via `PUTC` loops, and halts at instruction `0x0075`: a `GETC` (`0xC0`) operation.
2. The input character is verified against the four ASCII directions: `'u'` (`0x75`), `'d'` (`0x64`), `'l'` (`0x6C`), `'r'` (`0x72`). Any other key routes immediately to a failure handler.
3. Depending on the movement, the VM updates coordinate registers on the stack.
4. At offset `0x00EF`, the bytecode calculates the maze table index:
   ```text
   push 123
   swap
   push 372
   add
   jmp         ; Dynamically jumps to table address: 0x0174 + position
   ```
5. **The Maze Lookup Table (`0x0174` onwards):**  
   The maze consists of 4-byte cell structures:
   * `81 XX XX 30`: `PUSH16 <target>; JMP` $\rightarrow$ Redirects the player to another maze cell or the death handler (`0x00FB`: "grue").
   * Some cells invoke subroutine calls using the Return Stack (`>R`).
   * The sole winning cell resides at **`IP = 0x00F8`**, which executes:
     ```text
     0x80 0x00   ; push 0
     0x01        ; halt -> sets result = 0, error = 0!
     ```

---

## Why Manual Reversing is a Trap

Attempting to statically map the maze cell-by-cell is error-prone:
* The maze contains over 300 interlinked jump nodes with bidirectional wraps and dead ends.
* Manually calculating dynamic arithmetic coordinate offsets (`123`, `372`, `swap`) consumes hours.
* **The Engineering Alternative:** We already possess the exact semantics of the execution engine. By writing an emulator in Python, we can let graph theory solve the problem automatically.

---

## Algorithmic Solution: BFS on VM State Space

We model the puzzle as a classic graph traversal:
* **Node:** State tuple $K = (IP, \text{tuple}(ds), \text{tuple}(rs))$ captured precisely when the VM is paused awaiting input at opcode `0xC0`.
* **Edge:** An input character $\in \{\text{'u'}, \text{'d'}, \text{'l'}, \text{'r'}\}$.
* **Transition Function:** Feed character $\rightarrow$ Step VM forward until either:
  1. The VM encounters another `0xC0` (`GETC`) $\rightarrow$ Valid neighboring state.
  2. The VM terminates via `0x01` (`HALT`) $\rightarrow$ Evaluate win condition.
* **Visited Set:** Storing hashed state keys prevents infinite loops caused by backtracking or cyclic maze loops.

```text
[ Start State @ GETC ]
        |
        +---- 'u' ----> [ Intermediate VM Execution ] ----> [ Grue Death / Pruned ]
        +---- 'd' ----> [ Intermediate VM Execution ] ----> [ Next GETC State ] (Enqueued)
        +---- 'l' ----> [ Intermediate VM Execution ] ----> [ Cyclic State ] (Ignored)
        +---- 'r' ----> ...
```

---

## Exploit Script

Below is the core emulator and BFS solver (see [`exploit.py`](exploit.py) for the complete implementation):

```python
#!/usr/bin/env python3
# MATRIX VM Solver — Automated BFS State Space Exploration
import sys, os, time
from collections import deque

CODE_OFFSET = 0x20F0
CODE_LENGTH = 1490

# [ ... VMState and VMEmulator implementations ... ]

def solve_maze_bfs(vm: VMEmulator) -> bytes:
    initial_state = vm.find_initial_input_state()
    queue = deque([(initial_state.state_key(), b"", initial_state)])
    visited = {initial_state.state_key()}
    
    valid_moves = b"udlr"
    
    while queue:
        state_key, path, state = queue.popleft()
        
        for move in valid_moves:
            status, next_state = vm.run_until_input_or_halt(state, move)
            new_path = path + bytes([move])
            
            if status == "halt":
                if next_state.error == 0 and next_state.result == 0:
                    return new_path  # Found winning path!
            elif status == "input":
                key = next_state.state_key()
                if key not in visited:
                    visited.add(key)
                    queue.append((key, new_path, next_state))
    return b""
```

### Execution Output

Running the solver against the challenge binary:

```text
$ python3 exploit.py matrix
[*] Loading binary: matrix
[*] Extracted 1490 bytes of Forth bytecode at offset 0x20F0.
[*] Starting BFS State-Space Search for winning maze path...
[*] Explored 1000 states | Depth: 24 | Time: 0.81s
[*] Explored 2000 states | Depth: 45 | Time: 1.63s
[+] WINNING PATH FOUND in 2.34s!
[+] Total States Explored: 2841
[+] Solution Length: 63 steps

[+] Winning Sequence (63 steps):
    rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd

[*] Connecting to challenge service: mars.cylabacademy.net:31259...
[+] Service Response:
    WELCOME to the M A T R I X
    Can you make it out alive?
    Congratulations, you made it!
    Have a flag!
    picoCTF{REDACTED}
```

---

## Flag & Key Takeaways

```text
picoCTF{REDACTED}
```

1. **Virtual Machine Obfuscation vs. Emulation:** When analyzing custom bytecode architectures, reversing the dispatcher and building an execution simulator is far more scalable than statically decompiling thousands of complex transitions.
2. **Treat Binaries as State Machines:** Binary execution is fundamentally deterministic. When control flow branches depend on a small set of inputs (e.g. keyboard characters), state-space search algorithms (BFS, DFS, $A^*$) provide automated solutions without human guesswork.
3. **Double-Stack Forth Architecture:** Recognizing the interaction between the Data Stack and Return Stack (`>R`, `R>`) was critical for accurate operand tracking and state deduplication.
