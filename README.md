# CyLab Security Academy & picoCTF Writeups

A comprehensive, curated repository of binary exploitation analyses, reverse engineering writeups, and reproducible exploit scripts from **CyLab Security Academy** and **picoCTF**.

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
├── pwn/                              # Binary Exploitation Challenges (53 total)
│   ├── babygame01/                   # 2D array OOB negative indexing into stack variable
│   ├── babygame02/                   # 2D map OOB write into move_player retaddr NOP slide
│   ├── babygame03/                   # 2D map OOB write, infinite moves & level-up block hijack
│   ├── basic-file-exploit/           # Logic flaw: entry 0 array bypass disclosing flag buffer
│   ├── binary-gauntlet-0/            # Unbounded gets() stack smashing triggering crash handler win
│   ├── binary-gauntlet-1/            # Buffer leak + RWX stack shellcode injection
│   ├── binary-gauntlet-2/            # Format string %p stack address leak + stack shellcode execution
│   ├── binary-gauntlet-3/            # Format string %n arbitrary write redirecting GOT to shellcode
│   ├── bizz-fuzz/                    # BFS call-graph maze navigation & fgets stack smash
│   ├── buffer-overflow-3/            # Byte-by-byte static canary brute force (O(256 * N)) + ret2win
│   ├── cache-me-outside/             # 1-byte tcache head corruption & chunk offset shift
│   ├── cve-xxxx-xxxx/                # Threat intelligence: Windows PrintNightmare CVE-2021-34527
│   ├── download-horsepower/          # V8 JIT array length expansion OOB & WASM RWX shellcode
│   ├── fermat-strings/               # Multi-stage format string splitting, pow@GOT loop & system
│   ├── filtered-shellcode/           # 2-byte slip shellcode across periodic NOP injection
│   ├── function-overwrite/           # OOB negative index on .bss function pointer
│   ├── guessing-game-1/              # Deterministic rand() seed bypass + 64-bit ROP syscall execve
│   ├── guessing-game-2/              # Unintended function pointer leak + ret2libc
│   ├── handoff/                      # NX-off stack overflow with relative trampoline stager
│   ├── heap-havoc/                   # Heap overflow across adjacent struct function pointer
│   ├── heres-a-libc/                 # 64-bit Ret2libc, GOT puts leak, 16-byte stack alignment
│   ├── hft/                          # glibc 2.35 House of Orange top chunk shrink & TLS tcache hijack
│   ├── hijacking/                    # SUID Python privilege escalation via library hijacking
│   ├── homework/                     # Befunge-93 2D VM interpreter off-by-one boundary escape
│   ├── horsetrack/                   # glibc 2.33 Safe-Linking key leak & UAF GOT hijack
│   ├── input-injection-1/            # Stack buffer overflow into adjacent system() command buffer
│   ├── input-injection-2/            # Contiguous heap chunk overflow into system() command buffer
│   ├── kit-engine/                   # V8 custom AssembleEngine double array RWX shellcode
│   ├── local-target/                 # Stack buffer overflow partial overwrite of local variable (num=65)
│   ├── lockdown-horses/              # Seccomp ROP stager pivot & getdents64/mmap flag extraction
│   ├── offset-cycleV2/               # Dynamic ephemeral SUID binary canary oracle & ret2win
│   ├── picker-iv/                    # Unconstrained function pointer dereference (ret2win win())
│   ├── pizza-router/                 # Heap OOB 8-byte write & drone finish callback hijack
│   ├── ropfu/                        # 32-bit static NX-off jmp esp shellcode execution
│   ├── rps/                          # Logic flaw: composite substring matching strstr() auto-win
│   ├── saas/                         # Seccomp write-only bypass via RIP-relative dynamic linker leak
│   ├── seed-spring/                  # PRNG time(0) prediction via libc ctypes
│   ├── sice-cream/                   # glibc 2.23 fastbin double-free & chunk overlap
│   ├── stack-cache/                  # Uninitialized stack frame overlapping & dword reconstruction
│   ├── stonk-market/                 # Heap format string pointer-to-pointer chain & GOT hijack
│   ├── stonks/                       # Format string stack disclosure (%p chain) & Little-Endian unpacking
│   ├── tea-cash/                     # glibc 2.27 tcache LIFO free-list traversal & contiguous chunk delta
│   ├── the-office/                   # Custom heap allocator canary leak & scanf overflow
│   ├── tic-tac/                      # TOCTOU filesystem race condition via parallel symlink flippers
│   ├── turboflan/                    # V8 TurboFan JIT type confusion addrof/fakeobj & WASM RWX
│   ├── two-sum/                      # Signed 32-bit integer overflow wrapping to negative arithmetic
│   ├── unsubscriptions-are-free/     # 32-bit Heap UAF, glibc tcache recycling & stdio buffering fix
│   ├── vne/                          # SUID root command injection via SECRET_DIR environment variable
│   ├── vr-school/                    # C++ UAF vtable hijacking & Seccomp ORW chain
│   ├── whats-your-input/             # Python 2 input() insecure eval and global namespace reflection
│   ├── wine/                         # PE32 stack buffer overflow on Wine emulation
│   ├── x-sixty-what/                 # 64-bit stack buffer overflow (offset 72) ret2win into flag()
│   └── zero-to-hero/                 # glibc 2.29 tcache double-free bypass via off-by-null
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

### 1. Binary Exploitation (Pwn) — Difficulty 2 (Foundation & Intermediate, 20 Challenges)

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

---

### 2. Binary Exploitation (Pwn) — Difficulty 3 (Advanced Exploitation, 33 Challenges)

| # | Challenge | Platform / ID | Core Vulnerability / Technique | Writeup | Exploit |
|---|---|---|---|---|---|
| 1 | [babygame02](https://play.picoctf.org/) | CyLab #346 | 2D map OOB write, LSB return address overwrite to NOP slide of `win` | [Writeup](pwn/babygame02/README.md) | [exploit.py](pwn/babygame02/exploit.py) |
| 2 | [babygame03](https://play.picoctf.org/) | CyLab #446 | 2D map OOB write, infinite moves reset & level-up block hijack | [Writeup](pwn/babygame03/README.md) | [exploit.py](pwn/babygame03/exploit.py) |
| 3 | [Bizz Fuzz](https://play.picoctf.org/) | CyLab #181 | BFS call-graph traversal (627 lines) & stack overflow `fgets` into `win()` | [Writeup](pwn/bizz-fuzz/README.md) | [exploit.py](pwn/bizz-fuzz/exploit.py) |
| 4 | [buffer overflow 3](https://play.picoctf.org/) | CyLab / picoCTF | Static stack canary byte-by-byte brute force ($O(256 \times N)$ linear search) + ret2win | [Writeup](pwn/buffer-overflow-3/README.md) | [exploit.py](pwn/buffer-overflow-3/exploit.py) |
| 5 | [Cache Me Outside](https://play.picoctf.org/) | CyLab #146 | 1-byte arbitrary heap write modifying tcache head to misaligned chunk (`chunk+8`) | [Writeup](pwn/cache-me-outside/README.md) | [exploit.py](pwn/cache-me-outside/exploit.py) |
| 6 | [Download Horsepower](https://play.picoctf.org/) | CyLab #135 | V8 Torque patch array length expansion OOB, `addrof`/`fakeobj` & WASM RWX shellcode | [Writeup](pwn/download-horsepower/README.md) | [send.py](pwn/download-horsepower/send.py) |
| 7 | [fermat-strings](https://play.picoctf.org/) | CyLab #215 | Multi-stage format string splitting, `pow@GOT` infinite loop & `atoi@GOT` hijack | [Writeup](pwn/fermat-strings/README.md) | [solve.py](pwn/fermat-strings/solve.py) |
| 8 | [filtered-shellcode](https://play.picoctf.org/) | CyLab #184 | "2-byte slip" shellcode executing across periodic 2-NOP injection filter | [Writeup](pwn/filtered-shellcode/README.md) | [exploit.py](pwn/filtered-shellcode/exploit.py) |
| 9 | [function overwrite](https://play.picoctf.org/) | CyLab #272 | OOB negative array indexing on `.bss` function pointer (`fun[-11] += -310`) | [Writeup](pwn/function-overwrite/README.md) | [exploit.py](pwn/function-overwrite/exploit.py) |
| 10 | [Guessing Game 2](https://play.picoctf.org/) | CyLab #89 | Function pointer return PRNG leak, format string canary leak & ret2libc | [Writeup](pwn/guessing-game-2/README.md) | [exploit.py](pwn/guessing-game-2/exploit.py) |
| 11 | [handoff](https://play.picoctf.org/) | CyLab #486 | RWX executable stack, relative trampoline stager (`sub rsp, 0x2e8; jmp rsp`) via `jmp rax` | [Writeup](pwn/handoff/README.md) | [exploit.py](pwn/handoff/exploit.py) |
| 12 | [Heap Havoc](https://play.picoctf.org/) | CyLab #763 | Heap buffer overflow across adjacent struct, preserving intermediate pointer & hijack | [Writeup](pwn/heap-havoc/README.md) | [exploit.py](pwn/heap-havoc/exploit.py) |
| 13 | [Here's a LIBC](https://play.picoctf.org/) | CyLab / picoCTF | 64-bit Ret2libc, GOT `puts` leak, AMD64 ABI 16-byte stack alignment (`movaps` crash fix) | [Writeup](pwn/heres-a-libc/README.md) | [exploit.py](pwn/heres-a-libc/exploit.py) |
| 14 | [high frequency troubles](https://play.picoctf.org/) | CyLab #441 | glibc 2.35 House of Orange top chunk shrink, TLS tcache hijack & `setcontext` RCE | [Writeup](pwn/hft/README.md) | [exploit.py](pwn/hft/exploit.py) |
| 15 | [homework](https://play.picoctf.org/) | CyLab #217 | Befunge-93 2D VM off-by-one boundary escape (`p` at 50,4 setting `cols=200`) | [Writeup](pwn/homework/README.md) | [solve.py](pwn/homework/solve.py) |
| 16 | [Horsetrack](https://play.picoctf.org/) | CyLab #353 | glibc 2.33 Safe-Linking key leak ($L \gg 12$) & UAF write hijacking `free@GOT` | [Writeup](pwn/horsetrack/README.md) | [exploit.py](pwn/horsetrack/exploit.py) |
| 17 | [Kit Engine](https://play.picoctf.org/) | CyLab #168 | V8 custom `AssembleEngine` double array packing & direct RWX page execution | [Writeup](pwn/kit-engine/README.md) | [send.py](pwn/kit-engine/send.py) |
| 18 | [lockdown-horses](https://play.picoctf.org/) | CyLab #214 | Seccomp ROP stager pivot to `.bss`, directory dump via `getdents64` & `mmap` read | [Writeup](pwn/lockdown-horses/README.md) | [exploit.py](pwn/lockdown-horses/exploit.py) |
| 19 | [offset-cycleV2](https://learn.cylabacademy.org/) | CyLab #738 | Dynamic ephemeral SUID binary reversing, flag-derived canary oracle & ret2win | [Writeup](pwn/offset-cycleV2/README.md) | [exploit.py](pwn/offset-cycleV2/exploit.py) |
| 20 | [Pizza Router](https://play.picoctf.org/) | CyLab #758 | Heap OOB 8-byte write via unvalidated `heap_idx`, hijacking drone finish callback | [Writeup](pwn/pizza-router/README.md) | [solve.py](pwn/pizza-router/solve.py) |
| 21 | [ropfu](https://play.picoctf.org/) | CyLab #292 | 32-bit static binary with missing `GNU_STACK` (NX-off), trampoline `jmp esp` shellcode | [Writeup](pwn/ropfu/README.md) | [exploit.py](pwn/ropfu/exploit.py) |
| 22 | [SaaS](https://play.picoctf.org/) | CyLab #213 | Seccomp write-only bypass via RIP-relative dynamic linker (`ld.so`) link_map leak | [Writeup](pwn/saas/README.md) | [exploit.py](pwn/saas/exploit.py) |
| 23 | [seed-sPRiNG](https://play.picoctf.org/) | CyLab #50 | Deterministic `time(0)` PRNG prediction across 30 rounds via Python `ctypes` | [Writeup](pwn/seed-spring/README.md) | [exploit.py](pwn/seed-spring/exploit.py) |
| 24 | [sice_cream](https://play.picoctf.org/) | CyLab #55 | glibc 2.23 fastbin double-free, fake chunk in global memory & `globals[]` overwrite | [Writeup](pwn/sice-cream/README.md) | [exploit.py](pwn/sice-cream/exploit.py) |
| 25 | [stack cache](https://play.picoctf.org/) | CyLab #306 | Uninitialized stack frame overlapping (`win` into `UnderConstruction`) & `%x` leak | [Writeup](pwn/stack-cache/README.md) | [exploit.py](pwn/stack-cache/exploit.py) |
| 26 | [Stonk Market](https://play.picoctf.org/) | CyLab #164 | Heap format string stack pointer-to-pointer chain, modifying `free@GOT` to `system` | [Writeup](pwn/stonk-market/README.md) | [solve.py](pwn/stonk-market/solve.py) |
| 27 | [The Office](https://play.picoctf.org/) | CyLab #172 | Custom heap allocator canary leak via building-# overlap & `scanf` buffer overflow | [Writeup](pwn/the-office/README.md) | [solve.py](pwn/the-office/solve.py) |
| 28 | [tic-tac](https://play.picoctf.org/) | CyLab #380 | TOCTOU filesystem race condition: parallel symlink flipper vs SUID root `txtreader` | [Writeup](pwn/tic-tac/README.md) | [race.sh](pwn/tic-tac/race.sh) |
| 29 | [Turboflan](https://play.picoctf.org/) | CyLab #178 | V8 TurboFan map check bypass type confusion, fake `ArrayBuffer` & WASM RWX shellcode | [Writeup](pwn/turboflan/README.md) | [send.py](pwn/turboflan/send.py) |
| 30 | [Unsubscriptions Are Free](https://play.picoctf.org/) | CyLab / picoCTF | 32-bit Heap Use-After-Free (UAF), glibc tcache recycling, stdio buffering synchronization | [Writeup](pwn/unsubscriptions-are-free/README.md) | [exploit.py](pwn/unsubscriptions-are-free/exploit.py) |
| 31 | [vr-school](https://play.picoctf.org/) | CyLab #218 | C++ UAF object type confusion, virtual table dispatch hijack & Seccomp ORW chain | [Writeup](pwn/vr-school/README.md) | [solve.py](pwn/vr-school/solve.py) |
| 32 | [wine](https://play.picoctf.org/) | CyLab #317 | Windows PE32 stack buffer overflow on Wine, fixed image base ret2win (`0x0040151c`) | [Writeup](pwn/wine/README.md) | [exploit.py](pwn/wine/exploit.py) |
| 33 | [zero_to_hero](https://play.picoctf.org/) | CyLab #75 | glibc 2.29 tcache double-free bypass via off-by-null size mutation, `__free_hook` overwrite | [Writeup](pwn/zero-to-hero/README.md) | [exploit.py](pwn/zero-to-hero/exploit.py) |

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
* **Dynamic Analysis & Debugging:** GDB with `pwndbg` plugin, QEMU user-mode emulation, Wine
* **Browser & VM Exploitation:** Google V8 (`d8`), WebAssembly JIT, NetworkX Call-Graph Navigation
* **Exploitation & Scripting:** Python 3, `pwntools`, `paramiko`, `requests`
* **Binary Diffing & Compilation:** `cmp`, `objdump`, `gcc` with `-fopenmp`
