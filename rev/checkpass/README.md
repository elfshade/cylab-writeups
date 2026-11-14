# CyLab / picoCTF — Checkpass

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Reverse Engineering (Stripped Rust & SPN Inversion)  
* **Difficulty:** Hard (CyLab 3)  
* **Date:** 2026-11-14  
* **Tools:** IDA Pro, Ghidra, Python 3 (`pwntools`)  
* **Binary:** 64-bit ELF (`checkpass`) — Stripped Rust binary, PIE  

---

## TL;DR

A reverse engineering challenge analyzing a stripped **Rust** binary. Despite compiler bloat and absent symbol tables, we locate the primary validation routine (`sub_15CA0`) passed as a closure to the Rust runtime harness. The binary verifies that the input password is 41 characters long, enclosed in `academy{...}`, and subjects the middle 32 bytes to a 4-round **Substitution-Permutation Network (SPN)**. Because every round consists strictly of bijective S-box substitutions and position permutations using static tables embedded in the binary, the transformation is **completely invertible**. We extract the tables directly from the ELF using `pwntools` and compute the inverse rounds backwards from 3 to 0 to decrypt the password.

---

## Recon

We inspect the binary's properties and security mitigations using `file` and `checksec`:

```bash
$ file checkpass
checkpass: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ checksec checkpass
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
* **File Type:** ELF 64-bit LSB, stripped, PIE enabled.
* **Rust Binary:** String references include `std::panicking`, `alloc::raw_vec`, and core Rust runtime primitives.
* **Size:** $\approx 358 \text{ KB}$ — relatively small for Rust, indicating minimal third-party dependencies.

---

## Static Analysis & Reversing

### 1. Navigating Stripped Rust Runtime

In stripped Rust executables, `main()` typically initializes runtime allocators and exception handlers, passing the application logic as a closure:
* `main` calls `sub_3BFF0(&closure, ..., argv, 0)`.
* Tracing the closure pointer identifies **`sub_15CA0`** as the actual password verification routine.

### 2. Password Constraints & Validation Checks

Analyzing `sub_15CA0`:
1. **Length Check:** Asserts `len == 41`.
2. **Wrapper Verification:** Checks that the first 8 bytes match `0x7B796D6564616361` (`"academy{"` in little-endian) and `pw[40] == '}'`.
3. **Core Transformation:** Isolates the middle 32 bytes (`pw[8..40]`) and passes them to `sub_168C0(ptr, pw + 8)`.
4. **Final Comparison:** `sub_16360(ptr)` compares the 32-byte transformed output against a static target array located at `byte_9F70`. If identical, `sub_16920()` prints `"Success"`.

### 3. The 4-Round SPN Cipher Architecture

Examining `sub_168C0`:
The algorithm iterates a round transformation `sub_16940(a1, a2, r)` across 4 rounds ($r \in [0, 1, 2, 3]$):

```text
  Forward Encryption (Rounds 0 -> 3):
  [ 32-byte Input State ]
          |
  +-------v---------------------------------------------------+
  | Round r (0..3):                                           |
  |  1. S-Box Substitution:                                   |
  |     state[i] = sbox_r[state[i]]   (byte_8470[r*256 + i])  |
  |  2. Position Permutation:                                 |
  |     out[k]   = state[perm_r[k]]   (asc_9FB0[r*256 + 8*k]) |
  +-------+---------------------------------------------------+
          |
  [ Target Ciphertext @ byte_9F70 (32 bytes) ]
```

Because both the S-box substitution and the position permutation are 1-to-1 bijective mappings without external secret keys, the entire cryptographic pipeline can be mathematically inverted.

---

## Inversion & Decryption Strategy

To recover the plaintext, we run the cryptographic process in reverse order:
1. **Invert Rounds:** Loop backwards through rounds: $r = 3, 2, 1, 0$.
2. **Invert Permutation:** For each round, reverse the bitwise position mapping:
   $$\text{sub}[\text{perm\_r}[k]] = \text{state}[k]$$
3. **Invert S-Box:** Compute the inverse lookup table for each round's S-box:
   $$\text{inv\_sbox}[ \text{sbox}[x] ] = x$$
   $$\text{prev}[i] = \text{inv\_sbox}[ \text{sub}[i] ]$$
4. **Extract Tables Automatically:** Rather than manually transcribing 1,024 S-box entries and 1,024 permutation bytes, we read them programmatically from the ELF binary using `pwntools`:
   * S-boxes: `ELF("checkpass").read(0x8470, 1024)`
   * Permutations: `ELF("checkpass").read(0x9FB0, 1024)`
   * Target Ciphertext: `ELF("checkpass").read(0x9F70, 32)`

---

## Exploit

We construct the automated decryption script:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Checkpass
Reverse Engineering: Inversion of 4-round SPN (Substitution-Permutation Network)
"""

from pwn import *

EXE = "./checkpass"
elf = ELF(EXE, checksec=False)

# Read static cipher tables from ELF
SBOX_DATA = elf.read(0x8470, 1024)       # 4 rounds * 256 bytes
PERM_DATA = elf.read(0x9FB0, 1024)       # 4 rounds * 32 qwords (8 bytes each)
TARGET_DATA = elf.read(0x9F70, 32)       # 32-byte final target ciphertext

def invert_round(state, round_idx):
    # 1. Invert Permutation
    perm_offset = round_idx * 256
    perm = [u64(PERM_DATA[perm_offset + i * 8 : perm_offset + (i + 1) * 8]) for i in range(32)]

    inv_perm_state = [0] * 32
    for out_idx in range(32):
        inv_perm_state[perm[out_idx]] = state[out_idx]

    # 2. Invert S-Box
    sbox = list(SBOX_DATA[round_idx * 256 : (round_idx + 1) * 256])
    inv_sbox = [0] * 256
    for original, substituted in enumerate(sbox):
        inv_sbox[substituted] = original

    prev_state = [inv_sbox[b] for b in inv_perm_state]
    return bytes(prev_state)

def main():
    current_state = TARGET_DATA

    log.info("Decrypting 4-round SPN cipher...")
    for r in reversed(range(4)):
        current_state = invert_round(current_state, r)
        log.info(f"Round {r} inverted.")

    flag = b"academy{" + current_state + b"}"
    log.success(f"Recovered Password: {flag.decode()}")

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Executing the inversion script immediately reveals the flag:

```text
[*] Decrypting 4-round SPN cipher...
[*] Round 3 inverted.
[*] Round 2 inverted.
[*] Round 1 inverted.
[*] Round 0 inverted.
[+] Recovered Password: academy{redacted}
```

Testing the recovered password against the binary confirms the solution:
```bash
$ ./checkpass 'academy{redacted}'
Success
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Analyzing Stripped Rust Binaries**: Look for argument pointers passed into runtime wrappers (`main` calls `sub_3BFF0`). The core application logic resides in closure callbacks.
2. **Invertibility of SPN Cryptography**: When an application implements custom encryption without key-dependent branches or one-way trapdoor functions, the entire cipher is reversible by running inverse operations in reverse round sequence.
3. **Automating Binary Table Extraction**: Using `pwntools` `ELF.read(offset, size)` eliminates human error when extracting multi-kilobyte lookup tables and permutation matrices.
