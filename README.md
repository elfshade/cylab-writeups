# CyLab Security Academy & picoCTF Writeups

My personal notes, vulnerability analysis, and exploit scripts from **CyLab Security Academy** (including ported picoCTF challenges).  
Focus: **Binary Exploitation (Pwn)**, **Low-Level Linux Internals**, and **Reverse Engineering**.

As a 2nd-year computer science student exploring system security, these writeups document my hands-on learning journey—focusing on root cause analysis, stack/heap memory layouts, real debugging hurdles, and reproducible exploit scripts.

Flags and platform tokens are redacted on purpose.

---

## Repository Structure

```text
cylab-writeups/
├── pwn/                       # Binary Exploitation Challenges
│   ├── babygame01/            # 2D array OOB write
│   ├── buffer-overflow-3/     # Static canary byte-by-byte brute-force
│   ├── heres-a-libc/          # 64-bit Ret2libc & 16-byte stack alignment
│   ├── stonks/                # Format string leak & Little-Endian unpacking
│   └── unsubscriptions-are-free/ # Heap UAF & tcache LIFO reuse
├── rev/                       # Reverse Engineering Challenges
│   ├── breadth/               # Binary diffing & dead-code elimination
│   ├── checkpass/             # Stripped Rust reversing & SPN S-Box inversion
│   ├── matrix/                # Forth custom VM emulation & BFS maze search
│   ├── pico-bank/             # Android Smali reversing & Dalvik register reuse
│   └── rolling-my-own/        # JIT shellcode synthesis & OpenMP MD5 mining
└── README.md
```

---

## Challenge Index

### 🛡️ Binary Exploitation (`pwn/`)

| # | Challenge | Difficulty | Core Concept & Technique | Writeup |
|---|---|---|---|---|
| 1 | [Unsubscriptions Are Free](https://play.picoctf.org/) | Medium | Heap Use-After-Free (UAF), glibc tcache LIFO reuse, stdio buffering synchronization | [Writeup](pwn/unsubscriptions-are-free/README.md) |
| 2 | [Here's a LIBC](https://play.picoctf.org/) | Medium | 64-bit Ret2libc, GOT address leak, x86-64 stack alignment (16-byte RSP fix) | [Writeup](pwn/heres-a-libc/README.md) |
| 3 | [buffer overflow 3](https://play.picoctf.org/) | Medium | Custom static stack canary byte-by-byte linear brute-force ($O(256 \times 4)$), ret2win | [Writeup](pwn/buffer-overflow-3/README.md) |
| 4 | [Stonks](https://play.picoctf.org/) | Easy | Format string (`%p`) stack memory disclosure, Little-Endian word unpacking | [Writeup](pwn/stonks/README.md) |
| 5 | [babygame01](https://play.picoctf.org/) | Easy | 2D array Out-Of-Bounds (OOB) write, modifying game state via negative indexing | [Writeup](pwn/babygame01/README.md) |

### 🔍 Reverse Engineering (`rev/`)

| # | Challenge | Difficulty | Core Concept & Technique | Writeup |
|---|---|---|---|---|
| 6 | [MATRIX](https://play.picoctf.org/) | Hard | Forth-like custom VM bytecode emulation, BFS state-space graph search | [Writeup](rev/matrix/README.md) |
| 7 | [Checkpass](https://learn.cylabacademy.org/) | Hard | Stripped Rust reversing, 4-round SPN S-Box & Permutation inversion | [Writeup](rev/checkpass/README.md) |
| 8 | [Rolling My Own](https://learn.cylabacademy.org/) | Hard | JIT shellcode synthesis (`mmap` RWX), multithreaded OpenMP MD5 preimage mining | [Writeup](rev/rolling-my-own/README.md) |
| 9 | [Pico Bank](https://learn.cylabacademy.org/) | Medium | Android Smali reversing, Dalvik virtual register reuse emulation, binary stego | [Writeup](rev/pico-bank/README.md) |
| 10 | [Breadth](https://play.picoctf.org/) | Hard | Differential binary analysis (patch diffing), 16K dead-code deobfuscation | [Writeup](rev/breadth/README.md) |

---

## Toolchain & Environment

* **OS:** Arch Linux (x86_64)
* **Decompilation & Disassembly:** IDA Pro, Ghidra, `objdump`
* **Dynamic Debugging:** GDB with `pwndbg` plugin
* **Exploitation:** Python 3, `pwntools`
* **Static Analysis:** `file`, `checksec`, `strings`, `readelf`
