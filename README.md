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
├── pwn/                              # Binary Exploitation Challenges (23 total)
│   ├── babygame01/                   # 2D array OOB negative indexing into stack variable
│   ├── basic-file-exploit/           # Logic flaw: entry 0 array bypass disclosing flag buffer
│   ├── binary-gauntlet-0/            # Unbounded gets() stack smashing triggering crash handler win
│   ├── binary-gauntlet-1/            # Buffer leak + RWX stack shellcode injection
│   ├── binary-gauntlet-2/            # Format string stack address leak + stack shellcode execution
│   ├── binary-gauntlet-3/            # Format string %n arbitrary write redirecting GOT to shellcode
│   ├── buffer-overflow-3/            # Byte-by-byte static canary brute force (O(256 * N)) + ret2win
│   ├── cve-xxxx-xxxx/                # Threat intelligence: Windows PrintNightmare CVE-2021-34527
│   ├── guessing-game-1/              # Predictable rand() seed bypass + 64-bit ROP syscall execve
│   ├── heres-a-libc/                 # 64-bit Ret2libc, GOT puts leak, 16-byte stack alignment
│   ├── hijacking/                    # SUID Python privilege escalation via library hijacking
│   ├── input-injection-1/            # Stack buffer overflow into adjacent system() command buffer
│   ├── input-injection-2/            # Contiguous heap chunk overflow into system() command buffer
│   ├── local-target/                 # Stack buffer overflow partial overwrite of local variable (num=65)
│   ├── picker-iv/                    # Unconstrained function pointer dereference (ret2win win())
│   ├── rps/                          # Logic flaw: composite substring matching strstr() auto-win
│   ├── stonks/                       # Format string stack disclosure (%p chain) & Little-Endian unpacking
│   ├── tea-cash/                     # glibc 2.27 tcache LIFO free-list traversal & contiguous chunk delta
│   ├── two-sum/                      # Signed 32-bit integer overflow wrapping to negative arithmetic
│   ├── unsubscriptions-are-free/     # 32-bit Heap UAF, glibc tcache recycling & stdio buffering fix
│   ├── vne/                          # SUID root command injection via SECRET_DIR environment variable
│   ├── whats-your-input/             # Python 2 input() insecure eval and global namespace reflection
│   └── x-sixty-what/                 # 64-bit stack buffer overflow (offset 72) ret2win into flag()
├── rev/                              # Reverse Engineering Challenges (5 total)
│   ├── breadth/                      # Binary diffing (cmp -l) & isolating 16K dead-code functions
│   ├── checkpass/                    # Stripped Rust reversing & 4-round SPN S-Box/Permutation inversion
│   ├── matrix/                       # Forth-like VM bytecode emulation & state-space BFS maze solver
│   ├── pico-bank/                    # Android Smali reversing, Dalvik register tracking & binary stego
│   └── rolling-my-own/               # JIT shellcode synthesis & OpenMP multithreaded MD5 preimage mining
└── README.md
```

---

## Challenge Index

### 1. Binary Exploitation (Pwn) — Difficulty 2 (Complete Collection)

| # | Challenge | Platform / ID | Core Vulnerability / Technique | Writeup | Exploit |
|---|---|---|---|---|---|
| 1 | [babygame01](https://play.picoctf.org/) | CyLab / picoCTF | 2D Array Out-Of-Bounds (OOB) write, negative indexing overwriting `has_flag` | [Writeup](pwn/babygame01/README.md) | [exploit.py](pwn/babygame01/exploit.py) |
| 2 | [Basic File Exploit](https://play.picoctf.org/) | CyLab #292 | Logic Flaw: `strtol("0") == 0` bypasses upper bound check and dumps flag buffer | [Writeup](pwn/basic-file-exploit/README.md) | [exploit.py](pwn/basic-file-exploit/exploit.py) |
| 3 | [Binary Gauntlet 0](https://play.picoctf.org/) | CyLab #294 | Unbounded `gets()` stack overflow triggering crash signal handler win routine | [Writeup](pwn/binary-gauntlet-0/README.md) | [exploit.py](pwn/binary-gauntlet-0/exploit.py) |
| 4 | [Binary Gauntlet 1](https://play.picoctf.org/) | CyLab #295 | Stack buffer leak + execution of 27-byte execve shellcode on RWX stack | [Writeup](pwn/binary-gauntlet-1/README.md) | [exploit.py](pwn/binary-gauntlet-1/exploit.py) |
| 5 | [Binary Gauntlet 2](https://play.picoctf.org/) | CyLab #296 | Format string `%p` stack leak + return address hijack into injected shellcode | [Writeup](pwn/binary-gauntlet-2/README.md) | [exploit.py](pwn/binary-gauntlet-2/exploit.py) |
| 6 | [Binary Gauntlet 3](https://play.picoctf.org/) | CyLab #297 | Format string `%n` arbitrary write, overwriting `exit@GOT` with stack shellcode | [Writeup](pwn/binary-gauntlet-3/README.md) | [exploit.py](pwn/binary-gauntlet-3/exploit.py) |
| 7 | [CVE-XXXX-XXXX](https://learn.cylabacademy.org/) | CyLab #383 | Threat Intelligence: Disambiguating Windows PrintNightmare (CVE-2021-34527 vs 1675) | [Writeup](pwn/cve-xxxx-xxxx/README.md) | N/A |
| 8 | [guessing-game-1](https://play.picoctf.org/) | CyLab #310 | Deterministic `rand()` seed + Static 64-bit ROP syscall chain (`execve("/bin/sh")`) | [Writeup](pwn/guessing-game-1/README.md) | [exploit.py](pwn/guessing-game-1/exploit.py) |
| 9 | [Hijacking](https://learn.cylabacademy.org/) | CyLab #385 | SUID / Sudo Python privilege escalation via writable standard library hijacking | [Writeup](pwn/hijacking/README.md) | [exploit.py](pwn/hijacking/exploit.py) |
| 10 | [Input Injection 1](https://learn.cylabacademy.org/) | CyLab #525 | Stack buffer overflow (`strcpy`) into adjacent command argument buffer `system("sh")` | [Writeup](pwn/input-injection-1/README.md) | [exploit.py](pwn/input-injection-1/exploit.py) |
| 11 | [Input Injection 2](https://learn.cylabacademy.org/) | CyLab #526 | Contiguous heap chunk overflow (`scanf("%s")`) into `system()` command buffer | [Writeup](pwn/input-injection-2/README.md) | [exploit.py](pwn/input-injection-2/exploit.py) |
| 12 | [Local Target](https://play.picoctf.org/) | CyLab #399 | Stack buffer overflow partial overwrite of local variable (`num = 64 -> 65`) | [Writeup](pwn/local-target/README.md) | [exploit.py](pwn/local-target/exploit.py) |
| 13 | [Picker IV](https://play.picoctf.org/) | CyLab #403 | Unconstrained function pointer dereference, jumping to non-PIE `win()` function | [Writeup](pwn/picker-iv/README.md) | [exploit.py](pwn/picker-iv/exploit.py) |
| 14 | [RPS](https://play.picoctf.org/) | CyLab #293 | Logic Flaw: `strstr()` substring matching bypass using composite input string | [Writeup](pwn/rps/README.md) | [exploit.py](pwn/rps/exploit.py) |
| 15 | [Stonks](https://play.picoctf.org/) | CyLab / picoCTF | Format string (`%p`) stack memory disclosure, little-endian word reconstruction | [Writeup](pwn/stonks/README.md) | [exploit.py](pwn/stonks/exploit.py) |
| 16 | [tea-cash](https://learn.cylabacademy.org/) | CyLab #746 | glibc 2.27 tcache LIFO free-list traversal, computing contiguous chunk spacing | [Writeup](pwn/tea-cash/README.md) | [exploit.py](pwn/tea-cash/exploit.py) |
| 17 | [two-sum](https://play.picoctf.org/) | CyLab #382 | Signed 32-bit integer overflow wrapping to negative values ($n_1 > n_1 + n_2$) | [Writeup](pwn/two-sum/README.md) | [exploit.py](pwn/two-sum/exploit.py) |
| 18 | [VNE](https://play.picoctf.org/) | CyLab #387 | SUID root command injection via unsanitized `SECRET_DIR` environment variable | [Writeup](pwn/vne/README.md) | [exploit.py](pwn/vne/exploit.py) |
| 19 | [What's Your Input?](https://learn.cylabacademy.org/) | CyLab #138 | Python 2 `input()` insecure evaluation and global namespace variable reflection | [Writeup](pwn/whats-your-input/README.md) | [exploit.py](pwn/whats-your-input/exploit.py) |
| 20 | [x-sixty-what](https://play.picoctf.org/) | CyLab #319 | 64-bit stack buffer overflow (offset 72 = 64B buffer + 8B RBP) into `flag()` | [Writeup](pwn/x-sixty-what/README.md) | [exploit.py](pwn/x-sixty-what/exploit.py) |

### 2. Binary Exploitation (Pwn) — Difficulty 3 (Advanced)

| # | Challenge | Platform | Core Vulnerability / Technique | Writeup | Exploit |
|---|---|---|---|---|---|
| 1 | [Unsubscriptions Are Free](https://play.picoctf.org/) | CyLab / picoCTF | 32-bit Heap Use-After-Free (UAF), glibc tcache recycling, stdio buffering synchronization | [Writeup](pwn/unsubscriptions-are-free/README.md) | [exploit.py](pwn/unsubscriptions-are-free/exploit.py) |
| 2 | [Here's a LIBC](https://play.picoctf.org/) | CyLab / picoCTF | 64-bit Ret2libc, GOT `puts` leak, AMD64 ABI 16-byte stack alignment (`movaps` crash fix) | [Writeup](pwn/heres-a-libc/README.md) | [exploit.py](pwn/heres-a-libc/exploit.py) |
| 3 | [buffer overflow 3](https://play.picoctf.org/) | CyLab / picoCTF | Static stack canary byte-by-byte brute force ($O(256 \times N)$ linear search) + ret2win | [Writeup](pwn/buffer-overflow-3/README.md) | [exploit.py](pwn/buffer-overflow-3/exploit.py) |

---

### 3. Reverse Engineering (Rev)

| # | Challenge | Platform | Difficulty | Core Concept / Reversing Technique | Writeup | Exploit |
|---|---|---|---|---|---|---|
| 1 | [MATRIX](https://play.picoctf.org/) | CyLab / picoCTF | Hard | Forth-like custom VM bytecode emulation, BFS state-space graph search | [Writeup](rev/matrix/README.md) | [exploit.py](rev/matrix/exploit.py) |
| 2 | [Checkpass](https://learn.cylabacademy.org/) | CyLab / picoCTF | Hard | Stripped Rust reversing, 4-round SPN (Substitution-Permutation Network) mathematical inversion | [Writeup](rev/checkpass/README.md) | [exploit.py](rev/checkpass/exploit.py) |
| 3 | [Rolling My Own](https://learn.cylabacademy.org/) | CyLab / picoCTF | Hard | JIT shellcode synthesis, multithreaded OpenMP MD5 partial preimage mining in native C | [Writeup](rev/rolling-my-own/README.md) | [exploit.py](rev/rolling-my-own/exploit.py) |
| 4 | [Pico Bank](https://learn.cylabacademy.org/) | CyLab / picoCTF | Medium | Android APK Smali analysis, Dalvik virtual register reuse emulation, binary UI steganography | [Writeup](rev/pico-bank/README.md) | [exploit.py](rev/pico-bank/exploit.py) |
| 5 | [Breadth](https://play.picoctf.org/) | CyLab / picoCTF | Hard | Differential binary analysis (patch diffing v1 vs v2), filtering 16K dead-code decoy functions | [Writeup](rev/breadth/README.md) | [exploit.py](rev/breadth/exploit.py) |

---

## Toolchain & Environment

* **Operating System:** Linux x86_64 (Arch Linux)
* **Static Analysis & Decompilation:** IDA Pro, Ghidra, `readelf`, `nm`, `strings`
* **Dynamic Analysis & Debugging:** GDB with `pwndbg` plugin, QEMU user-mode emulation
* **Exploitation & Scripting:** Python 3, `pwntools`, `paramiko`, `requests`
* **Binary Diffing & Compilation:** `cmp`, `objdump`, `gcc` with `-fopenmp`
