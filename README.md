# CyLab Security Academy & picoCTF Writeups

My personal notes, vulnerability analysis, and exploit scripts from **CyLab Security Academy** (including ported picoCTF challenges).  
Focus: **Binary Exploitation (Pwn)**, **Low-Level Linux Internals**, and **Reverse Engineering**.

As a 2nd-year computer science student exploring system security, these writeups document my hands-on learning journey—focusing on root cause analysis, stack/heap memory layouts, real debugging hurdles, and reproducible exploit scripts.

Flags and platform tokens are redacted on purpose.

---

## Challenge Index

| # | Challenge | Category | Difficulty | Technique / Concept | Writeup |
|---|---|---|---|---|---|
| 1 | [Unsubscriptions Are Free](https://play.picoctf.org/) | Binary Exploitation | Medium | Heap Use-After-Free (UAF), glibc tcache LIFO reuse, stdio buffering synchronization | [Writeup](unsubscriptions-are-free/README.md) |
| 2 | [Here's a LIBC](https://play.picoctf.org/) | Binary Exploitation | Medium | 64-bit Ret2libc, GOT address leak, x86-64 stack alignment (16-byte RSP) | [Writeup](heres-a-libc/README.md) |
| 3 | [buffer overflow 3](https://play.picoctf.org/) | Binary Exploitation | Medium | Custom static stack canary byte-by-byte brute-force, ret2win | [Writeup](buffer-overflow-3/README.md) |
| 4 | [Stonks](https://play.picoctf.org/) | Binary Exploitation | Easy | Format string (`%p`) stack memory disclosure, little-endian unpacking | [Writeup](stonks/README.md) |
| 5 | [babygame01](https://play.picoctf.org/) | Binary Exploitation | Easy | 2D array Out-Of-Bounds (OOB) write, modifying game state via negative indexing | [Writeup](babygame01/README.md) |
| 6 | [MATRIX](https://play.picoctf.org/) | Reverse Engineering | Hard | Forth-like custom VM bytecode emulation, BFS state-space graph search | [Writeup](matrix/README.md) |
| 7 | [Checkpass](https://learn.cylabacademy.org/) | Reverse Engineering | Hard | Stripped Rust reversing, 4-round SPN S-Box & Permutation inversion | [Writeup](checkpass/README.md) |
| 8 | [Rolling My Own](https://learn.cylabacademy.org/) | Reverse Engineering | Hard | JIT shellcode synthesis, multithreaded OpenMP MD5 preimage mining | [Writeup](rolling-my-own/README.md) |
| 9 | [Pico Bank](https://learn.cylabacademy.org/) | Reverse Engineering | Medium | Android Smali reversing, Dalvik virtual register reuse emulation, binary stego | [Writeup](pico-bank/README.md) |
| 10 | [Breadth](https://play.picoctf.org/) | Reverse Engineering | Hard | Differential binary analysis (patch diffing), 16K dead-code deobfuscation | [Writeup](breadth/README.md) |

---

## Toolchain & Environment

* **OS:** Arch Linux (x86_64)
* **Decompilation & Disassembly:** IDA Pro, Ghidra, `objdump`
* **Dynamic Debugging:** GDB with `pwndbg` plugin
* **Exploitation:** Python 3, `pwntools`
* **Static Analysis:** `file`, `checksec`, `strings`, `readelf`
