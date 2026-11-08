# Rolling My Own — JIT Shellcode Synthesis & Multithreaded MD5 Preimage Mining

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
**Category:** Reverse Engineering (JIT Compilers & Cryptographic Preimage Mining)  
**Difficulty:** Hard (CyLab Difficulty 3)  
**Tools:** IDA Pro, GCC (OpenMP), Python 3 (`pwntools`, `hashlib`), GDB  
**Binary:** 64-bit ELF (`remote`) — Stripped, PIE  

---

## TL;DR

The challenge author implements a custom password validator claiming: *"I don't trust password checkers made by other people... It doesn't even need to store the password!"* Instead of comparing passwords, the binary segments a 16-byte user input into four 4-byte blocks, appends unique static salt suffixes, computes MD5 hashes, and extracts 4-byte slices to construct a 16-byte buffer in an executable memory page (`mmap` with `PROT_READ | PROT_WRITE | PROT_EXEC`). It then branches directly into this memory as native x86-64 code. The target function `sub_180F` prints the flag only when passed a specific 35-bit constant: `0x7B3DC26F1`. Rather than finding the original author's password, we synthesize multiple valid 16-byte x86-64 shellcodes, collect candidate 4-byte slices, and run an optimized multi-threaded C/OpenMP MD5 brute-forcer across the $254^4$ search space to mine preimages that compile into valid win-code.

---

## Student's Learning Note: Core Concepts

As a 2nd-year CS student, this challenge bridged **Low-Level Assembly**, **Operating Systems Memory Management**, and **Parallel Computing**:

1. **JIT (Just-In-Time) Execution Paradigm:** When an application dynamically maps memory with `PROT_EXEC` and executes synthesized instructions, the original input is irrelevant. Any input that causes the synthesis engine to assemble valid, compliant machine code will succeed.
2. **Partial Hash Preimage Complexity:** While full 128-bit MD5 preimage mining is computationally infeasible ($2^{128}$), attacking 4-byte (32-bit) hash slices requires searching a space of at most $254^4 \approx 4.16 \times 10^9$ iterations (excluding NUL and newline bytes).
3. **Multi-Candidate Parallel Optimization:** If you search for a single hardcoded 16-byte shellcode, hitting all four preimages simultaneously has a low probability. By generating **hundreds of equivalent assembly variants** (using different register assignments, NOP padding, and instruction encodings), we create a large target dictionary for each block, guaranteeing that a solution emerges within minutes.

---

## Reconnaissance & Reverse Engineering

Checking binary protections with `checksec`:

```bash
$ file remote
remote: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ checksec remote
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled (Binary), but uses mmap RWX at runtime!
    PIE:        PIE enabled
```

### Decompiling the Validator Logic

Reversing `main` in IDA Pro reveals:
1. The program reads a 16-byte password string into `pw[16]`.
2. Static salt suffixes and slice offsets are initialized:
   ```c
   const char *suffixes[4] = { "GpLaMjEW", "pVOjnnmk", "RGiledp6", "Mvcezxls" };
   const int   offsets[4]  = { 8, 2, 7, 1 };
   ```
3. For each 4-byte block $i \in \{0, 1, 2, 3\}$:
   * Concatenates: $\text{buffer} = \text{pw}[4i : 4i+4] \parallel \text{suffixes}[i]$.
   * Computes: $\text{digest} = \text{MD5}(\text{buffer})$.
   * Slices 4 bytes: $\text{code}[4i : 4i+4] = \text{digest}[\text{offsets}[i] : \text{offsets}[i]+4]$.
4. Allocates executable memory and invokes the JIT code:
   ```c
   void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   memcpy(page, code, 16);
   ((void (*)(void *))page)(&sub_180F); // Passes sub_180F pointer in RDI!
   ```
5. `sub_180F(uint64_t magic)`:
   ```c
   if (magic == 0x7B3DC26F1) {
       print_flag();
   } else {
       puts("Hmmmmmm... not quite");
   }
   ```

---

## Exploitation Strategy

```text
[ Password Chunk 0 ] + "GpLaMjEW" --> MD5 --> [Offset 8..12]  \
[ Password Chunk 1 ] + "pVOjnnmk" --> MD5 --> [Offset 2..6]   |--> 16-byte Executable Shellcode
[ Password Chunk 2 ] + "RGiledp6" --> MD5 --> [Offset 7..11]  |    in mmap(RWX) page
[ Password Chunk 3 ] + "Mvcezxls" --> MD5 --> [Offset 1..5]   /
```

### 1. Minimal Calling Shellcode
When the JIT code is invoked:
* `RDI` holds the address of `sub_180F`.
* We need to call `sub_180F(0x7B3DC26F1)`.

Minimal instruction sequence (12 bytes):
```asm
push rdi                   ; 57                      - Save sub_180F address
mov  rdi, 0x7B3DC26F1      ; 48 bf f1 26 dc b3 07 00 ; Set target argument in RDI
                           ; 00 00
ret                        ; c3                      - Jump to sub_180F
```

### 2. Generating Shellcode Encodings (`gen.py`)
Because 16 bytes allows 4 padding bytes, we generate dozens of permutations:
* Alternative ways to load `0x7B3DC26F1` (e.g. `mov edi, imm32; shl rdi, 32`, building in `RAX` then moving to `RDI`).
* Alternative dispatch gadgets (`call rdi`, `jmp [rsp]`, `push rdi; ret`).
* Inserting multi-byte NOPs (`0x66 0x90`, `0x0F 0x1F 0x00`) to shift instruction alignment across chunk boundaries.

### 3. OpenMP MD5 Brute-Forcer (`bfall.c`)
To search $254^4 \approx 4.16 \times 10^9$ candidate passwords per group without OpenSSL overhead, I wrote a custom, unrolled C implementation with OpenMP pragmas (`#pragma omp parallel for`):
* Filters out byte `0x00` (NUL) and `0x0A` (`\n`).
* Maintains an integer lookup table for candidate 4-byte chunk hashes.
* Executes in **~50 seconds per group** on a modern 12-thread CPU (~4 minutes total).

### 4. Matching & Solution Synthesis (`final.py`)
Intersecting the mined preimage dictionary against the valid shellcode library identified **38 fully solvable shellcodes**. One chosen valid password:

```text
Hex Password: c6 70 47 49 64 33 41 6e 65 82 01 21 39 ...
Corresponding Shellcode:
57 66 90 48 bf f1 26 dc b3 07 00 00 00 c3 b0 b5
(push rdi; nop; mov rdi, 0x7b3dc26f1; ret; mov al, 0xb5)
```

---

## Exploit Execution

Running the pipeline locally and against the CyLab challenge instance:

```text
$ cd rolling-my-own
$ python3 gen.py
[*] Generated 42 valid shellcode variants.
[*] Extracted unique target chunks per group: G0: 38, G1: 42, G2: 40, G3: 35.

$ gcc -O3 -march=native -fopenmp -o bfall bfall.c
$ ./bfall > solvable.txt
[+] Thread pool initialized (12 workers).
[+] Group 0 solved in 48.2s.
[+] Group 1 solved in 51.4s.
[+] Group 2 solved in 49.1s.
[+] Group 3 solved in 47.9s.

$ python3 exploit.py remote chatelaine.cylabacademy.net 42233
[+] Selected Solvable Password: c67047496433416e6443306e82012139
[+] Connecting to remote target...
[+] Flag received:
    academy{REDACTED}
```

---

## Flag & Key Takeaways

```text
academy{REDACTED}
```

1. **JIT Code Generation is Inherent Code Execution:** If user input is transformed into executable memory through any deterministic pipeline (even cryptographically hashed), the author must ensure that the output machine instructions cannot be coerced into unauthorized control transfer.
2. **Hash Preimage Slicing:** A 128-bit hash function loses its collision and preimage resistance properties when truncated to small slices (32 bits).
3. **High-Performance Parallel Programming:** Utilizing OpenMP and unrolled cryptographic primitives in C allowed a multi-billion hash search space to complete in under 4 minutes.
