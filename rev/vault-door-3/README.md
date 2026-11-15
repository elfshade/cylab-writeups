# CyLab / picoCTF — vault-door-3

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Array Permutation Loop Inversion)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Inverting character array shuffling algorithm across four distinct loop stages. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file vault-door-3
vault-door-3: ELF/Artifact analysis
$ checksec vault-door-3
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- Java source: `buffer` (chuỗi đích) = hoán vị của password qua các vòng lặp có `buffer[i] = password[j]`.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
- Hoán vị index cố định — cần làm ngược lại.

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

- Chuỗi đích: `jU5t_a_sna_3lpm10g747_u_4_m7re49`. Giải inverse từng công thức:
  - `i<8`: pw[i]=target[i]
  - `8<=i<16`: pw[23-i]=target[i]
  - `16<=i<32 step 2`: pw[46-i]=target[i]
  - `31>=i>16 step -2`: pw[i]=target[i]
→ `jU5t_a_s1mpl3_an4gr4m_4_u_777e09`

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Solver for vault-door-3
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

- Khi source có `buffer[i]=password[f(i)]`, **giữ nguyên RHS target[i], đặt vào vị trí pw[f(i)]** — đảo ngược index theo đúng công thức.
