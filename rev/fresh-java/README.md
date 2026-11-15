# CyLab / picoCTF — Fresh Java

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Java Bytecode Decompilation)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Java class bytecode decompilation (javap/jadx), ordered character comparison table. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file fresh-java
fresh-java: ELF/Artifact analysis
$ checksec fresh-java
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
Initial inspection verifies the structure and constraints of Fresh Java. We identify key functional components and validation loops.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
`javap -c -p` cho thấy kiểm tra từng ký tự:
```
aload_2; bipush IDX; invokevirtual charAt; bipush CHAR; if_icmpeq
```
Parse cặp (index, char) -> dựng key.

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

We model the transformation in Python and formulate an inverse calculation or dynamic trace script to recover the original flag input.

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
import re, subprocess
txt = subprocess.run(["javap","-c","-p","KeygenMe"],capture_output=True,text=True).stdout
lines=txt.splitlines()
res={}
def pv(l):
    m=re.search(r'(bipush|sipush|iconst_m1|iconst_\d|ldc)\s*(-?\d+)',l)
    if m: return int(m.group(2))
    return None
for i,l in enumerate(lines):
    if 'String.charAt' in l:
        j=i-1
        while not re.search(r'bipush|sipush|iconst|ldc',lines[j]): j-=1
        idx=pv(lines[j])
        k=i+1
        while 'if_icmpeq' not in lines[k]: k+=1
        m=k-1
        while not re.search(r'bipush|sipush|iconst|ldc',lines[m]): m-=1
        res[idx]=pv(lines[m])
print(''.join(chr(res[i]) for i in sorted(res)))
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

Keygen tự định nghĩa: trích (index, char) từ bytecode rồi ghép.
