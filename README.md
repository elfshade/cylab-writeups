# CyLab Security Academy & picoCTF Writeups

A curated collection of vulnerability analyses, reverse engineering notes, and reproducible exploit scripts from **CyLab Security Academy** (including ported picoCTF challenges).

All writeups strictly adhere to the standardized **TryHackMe `pwn101` architectural motif**:
* **`## TL;DR`**: Concise executive summary of vulnerability root causes, exploit vectors, and hurdles.
* **`## Recon`**: Comprehensive metadata analysis with `file` and `checksec`.
* **`## Static Analysis & Reversing`**: Decompilation walkthroughs, disassembly tracings, and ASCII memory/stack diagrams.
* **`## Dynamic Analysis & Exploitation Strategy`**: In-depth analysis of runtime traps (alignment, buffering, register reuse, state space).
* **`## Exploit`**: Robust, standalone Python / `pwntools` exploit scripts.
* **`## Flag`**: Verified output proof with redacted flag tokens.
* **`## Key Takeaways & Lessons`**: Concrete technical lessons and defensive principles.

> [!NOTE]
> All flag tokens and confidential infrastructure credentials have been redacted (`academy{redacted}` / `picoCTF{redacted}`) in compliance with competition disclosure guidelines.

---

## Repository Structure

```text
cylab-writeups/
├── pwn/                              # Binary Exploitation Challenges
│   ├── babygame01/                   # 2D array OOB negative indexing into stack variable
│   ├── buffer-overflow-3/            # Byte-by-byte static canary brute force (O(256 * N)) + ret2win
│   ├── heres-a-libc/                 # 64-bit Ret2libc, GOT puts leak, 16-byte stack alignment
│   ├── stonks/                       # Format string stack disclosure (%p chain) & Little-Endian unpacking
│   └── unsubscriptions-are-free/     # 32-bit Heap UAF, glibc tcache recycling & stdio buffering fix
├── rev/                              # Reverse Engineering Challenges
│   ├── breadth/                      # Binary diffing (cmp -l) & isolating 16K dead-code functions
│   ├── checkpass/                    # Stripped Rust reversing & 4-round SPN S-Box/Permutation inversion
│   ├── matrix/                       # Forth-like VM bytecode emulation & state-space BFS maze solver
│   ├── pico-bank/                    # Android Smali reversing, Dalvik register tracking & binary stego
│   └── rolling-my-own/               # JIT shellcode synthesis & OpenMP multithreaded MD5 preimage mining
└── README.md
```

---

## Challenge Index

### 1. Binary Exploitation (Pwn)

| # | Challenge | Platform | Difficulty | Core Vulnerability / Technique | Writeup |
|---|---|---|---|---|---|
| 1 | [Unsubscriptions Are Free](https://play.picoctf.org/) | CyLab / picoCTF | Medium | 32-bit Heap Use-After-Free (UAF), glibc tcache recycling, stdio buffering synchronization | [Writeup](pwn/unsubscriptions-are-free/README.md) |
| 2 | [Here's a LIBC](https://play.picoctf.org/) | CyLab / picoCTF | Medium | 64-bit Ret2libc, GOT `puts` leak, AMD64 ABI 16-byte stack alignment (`movaps` crash fix) | [Writeup](pwn/heres-a-libc/README.md) |
| 3 | [buffer overflow 3](https://play.picoctf.org/) | CyLab / picoCTF | Medium | Static stack canary byte-by-byte brute force ($O(256 \times N)$ linear search) + ret2win | [Writeup](pwn/buffer-overflow-3/README.md) |
| 4 | [Stonks](https://play.picoctf.org/) | CyLab / picoCTF | Easy | Format string (`%p`) stack memory disclosure, little-endian word reconstruction | [Writeup](pwn/stonks/README.md) |
| 5 | [babygame01](https://play.picoctf.org/) | CyLab / picoCTF | Easy | 2D Array Out-Of-Bounds (OOB) write, negative indexing overwriting `has_flag` | [Writeup](pwn/babygame01/README.md) |

---

### 2. Reverse Engineering (Rev)

| # | Challenge | Platform | Difficulty | Core Concept / Reversing Technique | Writeup |
|---|---|---|---|---|---|
| 1 | [MATRIX](https://play.picoctf.org/) | CyLab / picoCTF | Hard | Forth-like custom VM bytecode emulation, BFS state-space graph search | [Writeup](rev/matrix/README.md) |
| 2 | [Checkpass](https://learn.cylabacademy.org/) | CyLab / picoCTF | Hard | Stripped Rust reversing, 4-round SPN (Substitution-Permutation Network) mathematical inversion | [Writeup](rev/checkpass/README.md) |
| 3 | [Rolling My Own](https://learn.cylabacademy.org/) | CyLab / picoCTF | Hard | JIT shellcode synthesis, multithreaded OpenMP MD5 partial preimage mining in native C | [Writeup](rev/rolling-my-own/README.md) |
| 4 | [Pico Bank](https://learn.cylabacademy.org/) | CyLab / picoCTF | Medium | Android APK Smali analysis, Dalvik virtual register reuse emulation, binary UI steganography | [Writeup](rev/pico-bank/README.md) |
| 5 | [Breadth](https://play.picoctf.org/) | CyLab / picoCTF | Hard | Differential binary analysis (patch diffing v1 vs v2), filtering 16K dead-code decoy functions | [Writeup](rev/breadth/README.md) |

---

## Toolchain & Environment

* **Operating System:** Linux x86_64 (Arch Linux)
* **Static Analysis & Decompilation:** IDA Pro, Ghidra, `readelf`, `nm`, `strings`
* **Dynamic Analysis & Debugging:** GDB with `pwndbg` plugin
* **Exploitation & Scripting:** Python 3, `pwntools`, `requests`
* **Binary Diffing & Compilation:** `cmp`, `objdump`, `gcc` with `-fopenmp`
