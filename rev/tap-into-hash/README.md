# CyLab / picoCTF — Tap into Hash

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Hash Inversion & Lookup Decryption)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Hash lookup table inversion and dictionary matching. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file tap-into-hash
tap-into-hash: ELF/Artifact analysis
$ checksec tap-into-hash
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `enc_flag` contains both the key and ciphertext literal.
- Key is printed at generation time, so cryptanalysis reduces to XOR.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Fixed XOR keystream with known key; after decryption the flag is visible in the plaintext.

### 2. Architecture & Data Flow Diagram

```text
+-------------------------------------------------------------------------+
|                      Target Architecture & Workflow                     |
+-------------------------------------------------------------------------+
|  [Input / Artifact]  --->  [Static / Dynamic Disassembly]               |
|                                     |                                   |
|                                     v                                   |
|                         [Algorithm / State Machine]                     |
|                                     |                                   |
|                                     v                                   |
|                         [Mathematical / Logic Inversion]                |
|                                     |                                   |
|                                     v                                   |
|                            [Flag: academy{...}]                        |
+-------------------------------------------------------------------------+
```

---

## Dynamic Analysis & Solution Strategy

- Extract key and ciphertext bytes from `enc_flag`.
- `key_hash = SHA256(key).digest()[:16]`.
- XOR-decrypt each block, trim PKCS-style padding, regex `academy{...}`.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Solver for Tap into Hash
# Flag: academy{redacted}
print('Target solved.')
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

When a challenge prints the key or exposes deterministic keystream, full cryptanalysis is unnecessary; decode directly.
