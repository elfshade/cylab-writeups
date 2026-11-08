# Checkpass — Stripped Rust Binary & Substitution-Permutation Network (SPN) Inversion

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
**Category:** Reverse Engineering (Rust Internals & Cryptographic S-Box Inversion)  
**Difficulty:** Hard (CyLab Difficulty 3)  
**Tools:** IDA Pro, Ghidra, Python 3 (`pwntools`)  
**Binary:** 64-bit ELF (`checkpass`) — Rust, Stripped, PIE  

---

## TL;DR

The binary is a stripped 64-bit ELF executable compiled from **Rust**. Although the prompt and naming hint at a *"timing side channel"*, reversing the underlying binary control flow reveals that this is a deliberate red herring. The validation engine is a deterministic, 4-round **Substitution-Permutation Network (SPN)** operating on a 32-byte secret enclosed within `academy{...}`. Because both the substitution layer (S-Box) and the permutation layer are strictly bijective (invertible 1-to-1 mappings) without external key whitening, the cipher can be completely inverted mathematically. Extracting the round tables directly from `.rodata` and reversing each round in backward order ($R_3 \to R_0$) recovers the exact password in milliseconds.

---

## Student's Learning Note: Core Concepts

As a 2nd-year CS student studying compilers and introductory cryptography, this challenge presented two foundational concepts:

1. **Rust Runtime Initialization (`std::rt::lang_start`):** Rust binaries contain substantial runtime boilerplate (panic handlers, unwinding tables, stack guards). In a stripped Rust binary, `main` does not contain application logic; it simply invokes `std::rt::lang_start`, passing a function pointer to the actual user entry point.
2. **Substitution-Permutation Networks (SPN):** The architecture behind modern block ciphers (e.g. AES):
   * **Confusion Layer (S-Box):** A non-linear byte-level substitution. In an invertible cipher, every input byte maps to a unique output byte ($\text{S-Box}$ is a permutation of $0..255$).
   * **Diffusion Layer (P-Box / Permutation):** Transposes byte positions across the block so that local modifications disperse across the entire state.
   * **Invertibility Property:** Since both layers are bijective, the decryption function is simply the reverse sequence: $\text{Round}^{-1} = \text{S-Box}^{-1} \circ \text{P-Box}^{-1}$.

---

## Reconnaissance & Disassembly

Checking binary protections with `checksec`:

```bash
$ file checkpass
checkpass: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ checksec checkpass
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

Running the executable:
```bash
$ ./checkpass test
Wrong!
```

### Locating the Real Logic in Stripped Rust

In IDA Pro, `main` simply prepares runtime arguments for `sub_3BFF0`, which acts as the Rust entry stub:

```c
int __fastcall main(int argc, const char **argv, const char **envp) {
    return sub_3BFF0(&sub_15CA0, argc, argv, 0); // sub_15CA0 is the real main!
}
```

Analyzing `sub_15CA0`:
1. **Length Check:** The input argument must be exactly 41 bytes long:
   ```c
   if (input_len != 41) return FAIL;
   ```
2. **Format Check:** Verifies header and trailer:
   ```c
   if (*(uint64_t*)input != 0x7B796D6564616361) return FAIL; // "academy{"
   if (input[40] != '}') return FAIL;
   ```
3. **Core Processing:** The 32 bytes between index `[8..40]` are extracted and passed to `sub_168C0(output_buf, input + 8)`.
4. **Validation:** The resulting 32-byte block is compared against a fixed target buffer at `byte_9F70` via `sub_16360`. If identical, it displays `"Success"`.

---

## Cryptographic Structure: 4-Round SPN

Examining `sub_168C0`, the function executes a 4-round loop (`r = 0, 1, 2, 3`) calling `sub_16940(state, r)`:

```text
[ 32-byte Input: pw[8..40] ]
          |
     +----+----+
     | Round 0 |  --> S-Box Substitution (byte_8470[0..255])
     |         |  --> Byte Permutation    (asc_9FB0[0..31])
     +----+----+
          |
     +----+----+
     | Round 1 |  --> S-Box Substitution (byte_8470[256..511])
     |         |  --> Byte Permutation    (asc_9FB0[32..63])
     +----+----+
          |
     +----+----+
     | Round 2 |  --> S-Box Substitution (byte_8470[512..767])
     |         |  --> Byte Permutation    (asc_9FB0[64..95])
     +----+----+
          |
     +----+----+
     | Round 3 |  --> S-Box Substitution (byte_8470[768..1023])
     |         |  --> Byte Permutation    (asc_9FB0[96..127])
     +----+----+
          |
[ Compare against 32-byte Target Array @ byte_9F70 ]
```

### Table Layout in Binary Memory

* **S-Box Table (`0x8470`):** 1,024 bytes ($4 \times 256$ bytes). Each 256-byte slice represents a round-specific substitution lookup.
* **Permutation Table (`0x9FB0`):** 1,024 bytes ($4 \times 32$ 64-bit integers). Each qword denotes the destination index: `state[out] = temp[P[out]]`.
* **Target Ciphertext (`byte_9F70`):** 32 target bytes.

---

## Reversing Strategy: Backward Round Inversion

Because forward encryption performs:
1. $T[i] = S_r[A[i]]$
2. $B[i] = T[P_r[i]]$

The exact mathematical inverse for round $r$ is:
1. **Invert Permutation:**  
   $$T[P_r[i]] = B[i]$$
2. **Invert S-Box:**  
   Construct an inverted mapping table: $\text{InvS}[S_r[x]] = x$.  
   $$A[i] = \text{InvS}[T[i]]$$

By stepping rounds backward ($r = 3 \to 2 \to 1 \to 0$), the original 32 plaintext bytes are cleanly recovered without any brute force.

---

## Exploit Script

```python
#!/usr/bin/env python3
# Checkpass SPN Inverter — Python 3
from pwn import ELF

TARGET = bytes([
    0x1F, 0x99, 0x50, 0xD7, 0xB8, 0x22, 0x3A, 0xCB,
    0xCF, 0x12, 0xAE, 0xCB, 0xD9, 0x20, 0x99, 0x48,
    0x05, 0x7B, 0x7B, 0x22, 0xCD, 0x0D, 0x46, 0xF9,
    0xCF, 0xE6, 0x12, 0x01, 0x05, 0xCB, 0xF9, 0x7B
])

def solve():
    elf = ELF("./checkpass", checksec=False)
    sbox_data = elf.read(0x8470, 1024)
    perm_data = elf.read(0x9FB0, 1024)

    state = bytearray(TARGET)

    # Invert rounds 3 down to 0
    for r in reversed(range(4)):
        round_sbox = sbox_data[r*256 : (r+1)*256]
        inv_sbox = [0] * 256
        for orig, sub in enumerate(round_sbox):
            inv_sbox[sub] = orig

        round_perm = [
            int.from_bytes(perm_data[r*256 + 8*k : r*256 + 8*k + 8], "little")
            for k in range(32)
        ]

        unpermuted = bytearray(32)
        for out_idx in range(32):
            unpermuted[round_perm[out_idx]] = state[out_idx]

        state = bytearray(inv_sbox[b] for b in unpermuted)

    password = b"academy{" + bytes(state) + b"}"
    print("[+] Recovered Password:", password.decode())

if __name__ == "__main__":
    solve()
```

*(See [`exploit.py`](exploit.py) for the full standalone script with fallback reading).*

### Execution Output

```text
$ python3 exploit.py checkpass
[*] Reversing 4-Round Substitution-Permutation Network (SPN)...
    [+] Round 3 inverted successfully.
    [+] Round 2 inverted successfully.
    [+] Round 1 inverted successfully.
    [+] Round 0 inverted successfully.

[+] Verification & Decryption Complete:
    Raw Middle: t1mingS1deChann3l_c55b1a90e29d2f
    Full Flag : academy{t1mingS1deChann3l_c55b1a90e29d2f}

[+] Forward roundtrip check passed: Decrypted plaintext reproduces ciphertext exactly!
```

Testing locally:
```bash
$ ./checkpass 'academy{t1mingS1deChann3l_c55b1a90e29d2f}'
Success
```

---

## Flag & Key Takeaways

```text
academy{REDACTED}
```

1. **Beware of CTF Red Herrings:** The challenge title and string references to *"timing side channel"* were decoys designed to prompt time-measurement experiments. Always confirm hypotheses through static assembly review first.
2. **Locating User Logic in Rust:** In stripped Rust binaries, bypass runtime initialization by following `std::rt::lang_start` to find the actual `main` logic.
3. **Symmetric Layer Inversion:** Cryptographic verification logic constructed from pure permutations and substitutions without a dynamic secret key is trivial to reverse through inverse mapping tables.
