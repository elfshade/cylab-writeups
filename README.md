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

### 3. Reverse Engineering (Rev) — 58 Challenges

#### 3.1 Reverse Engineering — Difficulty 2 (Foundation & Intermediate, 44 Challenges)

| # | Challenge | Platform / ID | Core Concept / Reversing Technique | Writeup | Exploit |
|---|---|---|---|---|---|
| 1 | [The Add/On Trap](https://play.picoctf.org/) | CyLab RE #527 | Browser add-on native component reversing & XOR key schedule | [Writeup](rev/addon-trap/README.md) | [exploit.py](rev/addon-trap/exploit.py) |
| 2 | [ASCII FTW](https://play.picoctf.org/) | CyLab #389 | Disassembly analysis of sequential `movb` immediate stack writes | [Writeup](rev/ascii-ftw/README.md) | [exploit.py](rev/ascii-ftw/exploit.py) |
| 3 | [asm1](https://play.picoctf.org/) | CyLab #20 / picoCTF | x86 32-bit assembly conditional branch tracing (`cmp`, `jg`, `sub`) | [Writeup](rev/asm1/README.md) | [exploit.py](rev/asm1/exploit.py) |
| 4 | [Autorev 1](https://play.picoctf.org/) | CyLab RE (Diff 2) | Linear equation system recovery from stripped ELF binary | [Writeup](rev/autorev1/README.md) | [exploit.py](rev/autorev1/exploit.py) |
| 5 | [Bbbbloat](https://play.picoctf.org/) | CyLab #255 | Stripped x86_64 ELF decompilation, integer branch (`549255`) & rotation cipher | [Writeup](rev/bbbbloat/README.md) | [exploit.py](rev/bbbbloat/exploit.py) |
| 6 | [Bit-O-Asm-1](https://play.picoctf.org/) | CyLab #391 | Static disassembly analysis of single register assignment (`mov eax, 0x30`) | [Writeup](rev/bit-o-asm-1/README.md) | [exploit.py](rev/bit-o-asm-1/exploit.py) |
| 7 | [Bit-O-Asm-2](https://play.picoctf.org/) | CyLab #392 | Stack local variable tracking (`mov [rbp-4], 0x471; mov eax, [rbp-4]`) | [Writeup](rev/bit-o-asm-2/README.md) | [exploit.py](rev/bit-o-asm-2/exploit.py) |
| 8 | [Bit-O-Asm-3](https://play.picoctf.org/) | CyLab #393 | Arithmetic pipeline tracing (`imul eax, [rbp-8]; add eax, [rbp-4]`) | [Writeup](rev/bit-o-asm-3/README.md) | [exploit.py](rev/bit-o-asm-3/exploit.py) |
| 9 | [bloat.py](https://play.picoctf.org/) | CyLab #256 | Deobfuscating obfuscated Python script, extracting hidden password checks | [Writeup](rev/bloat-py/README.md) | [exploit.py](rev/bloat-py/exploit.py) |
| 10 | [Bypass Me](https://play.picoctf.org/) | CyLab RE (Diff 2) | Authentication branch bypass in native binary, patch analysis | [Writeup](rev/bypass-me/README.md) | [exploit.py](rev/bypass-me/exploit.py) |
| 11 | [Chronohack](https://play.picoctf.org/) | CyLab RE (Diff 2) | Time-based PRNG state reconstruction, backward seed synchronization | [Writeup](rev/chronohack/README.md) | [exploit.py](rev/chronohack/exploit.py) |
| 12 | [crackme-py](https://play.picoctf.org/) | CyLab #175 | Python ROT47 cipher analysis and invocation of hidden `decode_secret` | [Writeup](rev/crackme-py/README.md) | [exploit.py](rev/crackme-py/exploit.py) |
| 13 | [file-run1](https://play.picoctf.org/) | CyLab #266 | Executable permission analysis and terminal execution parameter inspection | [Writeup](rev/file-run1/README.md) | [exploit.py](rev/file-run1/exploit.py) |
| 14 | [file-run2](https://play.picoctf.org/) | CyLab #267 | CLI argument passing inspection (`./run Hello!`) through string analysis | [Writeup](rev/file-run2/README.md) | [exploit.py](rev/file-run2/exploit.py) |
| 15 | [Flag Hunters](https://play.picoctf.org/) | CyLab RE (Diff 2) | Custom bytecode virtual machine interpreter analysis and opcode tracing | [Writeup](rev/flag-hunters/README.md) | [exploit.py](rev/flag-hunters/exploit.py) |
| 16 | [Fresh Java](https://play.picoctf.org/) | CyLab #271 | Java class bytecode decompilation (`javap`/`jadx`), ordered character comparison table | [Writeup](rev/fresh-java/README.md) | [exploit.py](rev/fresh-java/exploit.py) |
| 17 | [Gatekeeper](https://play.picoctf.org/) | CyLab RE (Diff 2) | Multi-stage password checking function analysis and static constraint solving | [Writeup](rev/gatekeeper/README.md) | [exploit.py](rev/gatekeeper/exploit.py) |
| 18 | [GDB Test Drive](https://play.picoctf.org/) | CyLab #273 | GDB debugging, breakpoint placement and skipping `sleep()` delay loop | [Writeup](rev/gdb-test-drive/README.md) | [exploit.py](rev/gdb-test-drive/exploit.py) |
| 19 | [Hidden Cipher 1](https://play.picoctf.org/) | CyLab RE (Diff 2) | XOR keystream recovery from embedded cipher routine | [Writeup](rev/hiddencipher/README.md) | [exploit.py](rev/hiddencipher/exploit.py) |
| 20 | [Hidden Cipher 2](https://play.picoctf.org/) | CyLab RE (Diff 2) | Multi-byte cyclic XOR key recovery and ciphertext decryption | [Writeup](rev/hiddencipher2/README.md) | [exploit.py](rev/hiddencipher2/exploit.py) |
| 21 | [keygenme-py](https://play.picoctf.org/) | CyLab #121 | Python license validator reversing: selective SHA-256 digest character extraction | [Writeup](rev/keygenme-py/README.md) | [exploit.py](rev/keygenme-py/exploit.py) |
| 22 | [M1n10n'5_53cr37](https://play.picoctf.org/) | CyLab RE (Diff 2) | Android APK decompilation (`jadx`), native asset decryption and intent analysis | [Writeup](rev/minions-apk/README.md) | [exploit.py](rev/minions-apk/exploit.py) |
| 23 | [patchme.py](https://play.picoctf.org/) | CyLab #287 | Python conditional bypass, extracting encrypted payload and hardcoded key | [Writeup](rev/patchme/README.md) | [exploit.py](rev/patchme/exploit.py) |
| 24 | [perplexed](https://play.picoctf.org/) | CyLab RE (Diff 2) | Obfuscated control flow graph untangling, recovering character transformation matrix | [Writeup](rev/perplexed/README.md) | [exploit.py](rev/perplexed/exploit.py) |
| 25 | [Picker I](https://play.picoctf.org/) | CyLab #400 | Python `eval()` arbitrary function dispatch, calling hidden `win()` routine | [Writeup](rev/picker-i/README.md) | [exploit.py](rev/picker-i/exploit.py) |
| 26 | [Picker III](https://play.picoctf.org/) | CyLab #402 | Function table index manipulation, overwriting function pointer variable with `win` | [Writeup](rev/picker-iii/README.md) | [exploit.py](rev/picker-iii/exploit.py) |
| 27 | [Pico Bank](https://play.picoctf.org/) | CyLab #529 | Android APK Smali analysis, Dalvik virtual register reuse emulation | [Writeup](rev/pico-bank/README.md) | [exploit.py](rev/pico-bank/exploit.py) |
| 28 | [Quantum Scrambler](https://play.picoctf.org/) | CyLab RE (Diff 2) | Inverting multi-round bitwise permutation, shift, and XOR diffusion network | [Writeup](rev/quantum-scrambler/README.md) | [exploit.py](rev/quantum-scrambler/exploit.py) |
| 29 | [Reverse](https://play.picoctf.org/) | CyLab #372 | Disassembly of string reversal algorithm, static extraction of flag buffer | [Writeup](rev/reverse-372/README.md) | [exploit.py](rev/reverse-372/exploit.py) |
| 30 | [Safe Opener](https://play.picoctf.org/) | CyLab #294 | Java class reversing, base64 encoded password string decoding | [Writeup](rev/safe-opener/README.md) | [exploit.py](rev/safe-opener/exploit.py) |
| 31 | [Safe Opener 2](https://play.picoctf.org/) | CyLab #375 | Stripped Java `.class` string table recovery, Base64 decoded flag extraction | [Writeup](rev/safe-opener-2/README.md) | [exploit.py](rev/safe-opener-2/exploit.py) |
| 32 | [Secure Password Database](https://play.picoctf.org/) | CyLab RE (Diff 2) | SQLite schema and embedded hashing algorithm analysis in stripped native binary | [Writeup](rev/secure-password-database/README.md) | [exploit.py](rev/secure-password-database/exploit.py) |
| 33 | [Silent Stream](https://play.picoctf.org/) | CyLab RE (Diff 2) | Audio/data stream parsing, recovering hidden binary payload from carrier | [Writeup](rev/silent-stream/README.md) | [exploit.py](rev/silent-stream/exploit.py) |
| 34 | [Tap into Hash](https://play.picoctf.org/) | CyLab RE (Diff 2) | Hash lookup table inversion and dictionary matching | [Writeup](rev/tap-into-hash/README.md) | [exploit.py](rev/tap-into-hash/exploit.py) |
| 35 | [Transformation](https://play.picoctf.org/) | CyLab #104 | UTF-16 16-bit packed char unpacking: extracting high byte (`>>8`) and low byte (`&0xFF`) | [Writeup](rev/transformation/README.md) | [exploit.py](rev/transformation/exploit.py) |
| 36 | [unpackme.py](https://play.picoctf.org/) | CyLab #314 | De-obfuscating Python payload, extracting base64 encoded Fernet decryption key | [Writeup](rev/unpackme-py/README.md) | [exploit.py](rev/unpackme-py/exploit.py) |
| 37 | [vault-door-training](https://play.picoctf.org/) | CyLab / picoCTF 2019 | Java source code inspection, extracting hardcoded plaintext string parameter | [Writeup](rev/vault-door-training/README.md) | [exploit.py](rev/vault-door-training/exploit.py) |
| 38 | [vault-door-1](https://play.picoctf.org/) | CyLab / picoCTF 2019 | Java source code analysis, reconstructing 32-character string from sparse index checks | [Writeup](rev/vault-door-1/README.md) | [exploit.py](rev/vault-door-1/exploit.py) |
| 39 | [vault-door-3](https://play.picoctf.org/) | CyLab / picoCTF 2019 | Inverting character array shuffling algorithm across four distinct loop stages | [Writeup](rev/vault-door-3/README.md) | [exploit.py](rev/vault-door-3/exploit.py) |
| 40 | [vault-door-4](https://play.picoctf.org/) | CyLab / picoCTF 2019 | Decoding composite byte representation array: decimal, hex (`0x`), octal (`0`), and raw chars | [Writeup](rev/vault-door-4/README.md) | [exploit.py](rev/vault-door-4/exploit.py) |
| 41 | [vault-door-5](https://play.picoctf.org/) | CyLab / picoCTF 2019 | Two-stage encoding inversion: URL decoding followed by standard Base64 decoding | [Writeup](rev/vault-door-5/README.md) | [exploit.py](rev/vault-door-5/exploit.py) |
| 42 | [vault-door-6](https://play.picoctf.org/) | CyLab / picoCTF 2019 | Inverting byte-wise XOR masking (`c ^ 0x55 == expected`) across 32 password bytes | [Writeup](rev/vault-door-6/README.md) | [exploit.py](rev/vault-door-6/exploit.py) |
| 43 | [weirdSnake](https://play.picoctf.org/) | CyLab RE (Diff 2) | Python bytecode disassembly analysis, reconstructing snake game state and flag array | [Writeup](rev/weirdsnake/README.md) | [exploit.py](rev/weirdsnake/exploit.py) |
| 44 | [WinAntiDbg0x300](https://play.picoctf.org/) | CyLab RE (Diff 2) | Windows PE32 anti-debugging bypass: patching `IsDebuggerPresent` and PEB | [Writeup](rev/winantidbg0x300/README.md) | [exploit.py](rev/winantidbg0x300/exploit.py) |

---

#### 3.2 Reverse Engineering — Difficulty 3 (Advanced Reversing, 14 Challenges)

| # | Challenge | Platform / ID | Core Concept / Reversing Technique | Writeup | Exploit |
|---|---|---|---|---|---|
| 1 | [B1ll_Gat35](https://play.picoctf.org/) | CyLab #57 | 32-bit ELF reversing, key validation algorithm and linear constraint solver | [Writeup](rev/b1ll-gat35/README.md) | [exploit.py](rev/b1ll-gat35/exploit.py) |
| 2 | [Breadth](https://play.picoctf.org/) | CyLab / picoCTF | Differential binary analysis (patch diffing v1 vs v2), filtering 16K dead-code decoy functions | [Writeup](rev/breadth/README.md) | [exploit.py](rev/breadth/exploit.py) |
| 3 | [Checkpass](https://play.picoctf.org/) | CyLab #149 | Stripped Rust reversing, 4-round SPN (Substitution-Permutation Network) mathematical inversion | [Writeup](rev/checkpass/README.md) | [exploit.py](rev/checkpass/exploit.py) |
| 4 | [Easy as GDB](https://play.picoctf.org/) | CyLab #122 | Automated GDB byte-by-byte flag oracle, hardware watchpoints & breakpoint scripting | [Writeup](rev/easy-as-gdb/README.md) | [exploit.py](rev/easy-as-gdb/exploit.py) |
| 5 | [Forky](https://play.picoctf.org/) | CyLab #24 | Multi-process fork tree analysis, IPC shared memory increment simulation ($4 \times 10^9$) | [Writeup](rev/forky/README.md) | [exploit.py](rev/forky/exploit.py) |
| 6 | [Keygenme](https://play.picoctf.org/) | CyLab RE (Diff 3) | Reverse engineering license validation algorithm, dynamic key generator creation | [Writeup](rev/keygenme/README.md) | [exploit.py](rev/keygenme/exploit.py) |
| 7 | [MATRIX](https://play.picoctf.org/) | CyLab #222 / picoMini | Forth-like custom VM bytecode emulation, BFS state-space graph search | [Writeup](rev/matrix/README.md) | [exploit.py](rev/matrix/exploit.py) |
| 8 | [Need For Speed](https://play.picoctf.org/) | CyLab #39 | SIGALRM timer bypass, binary patching or GDB instruction redirection to `decrypt_flag()` | [Writeup](rev/need-for-speed/README.md) | [exploit.py](rev/need-for-speed/exploit.py) |
| 9 | [not crypto](https://play.picoctf.org/) | CyLab #222 / picoMini | Obfuscated AES keystream decoupling: input-independent state recovery via LD_PRELOAD hook | [Writeup](rev/not-crypto/README.md) | [run.sh](rev/not-crypto/run.sh) |
| 10 | [OTP Implementation](https://play.picoctf.org/) | CyLab #92 | Custom finite alphabet `jumble()` permutation bijection inversion and XOR decryption | [Writeup](rev/otp-implementation/README.md) | [exploit.py](rev/otp-implementation/exploit.py) |
| 11 | [Picker II](https://play.picoctf.org/) | CyLab #401 | Python `eval()` filter bypass: calling `print(open('flag.txt').read())` without forbidden `win` | [Writeup](rev/picker-ii/README.md) | [exploit.py](rev/picker-ii/exploit.py) |
| 12 | [Powershelly](https://play.picoctf.org/) | CyLab #119 | PowerShell 5x264 bit-matrix unscrambler, inverting cumulative XOR and linear probing | [Writeup](rev/powershelly/README.md) | [exploit.py](rev/powershelly/exploit.py) |
| 13 | [reverse_cipher](https://play.picoctf.org/) | CyLab #79 | Parity-dependent byte transformation inversion: even index `-5`, odd index `+2` | [Writeup](rev/reverse-cipher/README.md) | [exploit.py](rev/reverse-cipher/exploit.py) |
| 14 | [Rolling My Own](https://play.picoctf.org/) | CyLab #151 | JIT shellcode synthesis, multithreaded OpenMP MD5 partial preimage mining in native C | [Writeup](rev/rolling-my-own/README.md) | [exploit.py](rev/rolling-my-own/exploit.py) |

---

## Toolchain & Environment

* **Operating System:** Linux x86_64 (Arch Linux)
* **Static Analysis & Decompilation:** IDA Pro, Ghidra, `readelf`, `nm`, `strings`
* **Dynamic Analysis & Debugging:** GDB with `pwndbg` plugin, QEMU user-mode emulation, Wine
* **Browser & VM Exploitation:** Google V8 (`d8`), WebAssembly JIT, NetworkX Call-Graph Navigation
* **Exploitation & Scripting:** Python 3, `pwntools`, `paramiko`, `requests`
* **Binary Diffing & Compilation:** `cmp`, `objdump`, `gcc` with `-fopenmp`
