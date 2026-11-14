# Breadth — Binary Diffing & Large-Scale Dead Code Deobfuscation

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/) (picoMini by redpwn)  
**Category:** Reverse Engineering (Binary Diffing & Patch Analysis)  
**Difficulty:** Hard (CyLab Difficulty 3)  
**Tools:** `cmp`, `readelf`, IDA Pro, Python 3 (`struct`)  
**Binaries:** 64-bit ELFs (`breadth.v1`, `breadth.v2`) — Non-Stripped, PIE  

---

## TL;DR

The challenge distributes a 2.6 MB binary containing **16,384 distinct dead-code functions** (`fcn*`), each embedding a plausible decoy flag. Statically analyzing or decompiling 16,384 routines is a textbook anti-analysis rabbit hole. However, the author provided two builds: an in-development build (`breadth.v1`) with a deliberate flaw and a patched production build (`breadth.v2`). By performing byte-level **Binary Diffing** (`cmp -l`) between the two binaries and filtering out build-id metadata, we isolate the single 15-byte modification in the `.text` section. This immediately pinpoints the exact function containing the real flag (`fcnkKTQpF` at address `0x95040`), resolving the challenge in under 1 second.

---

## Student's Learning Note: Core Concepts & The 16,000-Function Trap

When I first dropped `breadth.v1` into Ghidra and saw **16,384 distinct functions**, my laptop fans started screaming and the auto-analysis estimated 45 minutes! I immediately realized: *there's no way a human is expected to reverse 16,000 functions.* 

Then the lightbulb went off: why did the author give us **two binaries** (`breadth.v1` and `breadth.v2`)? In our software engineering coursework, we studied version control and differential analysis. This was a textbook patch diffing scenario!

1. **Dead-Code Bloating (Obfuscation by Volume):** Compilers and script generators can easily synthesize vast oceans of unreachable routines that look like real code. While individual functions appear valid, none are referenced in the program's actual call-graph from `main()`.
2. **Binary Diffing (Patch Analysis):** In real-world vulnerability research, analyzing security patches (1-day exploits) begins by diffing an unpatched binary against a patched release. The code modifications immediately isolate the fix—and in our case, the real flag!
3. **Filtering Diff Noise:** Not all binary discrepancies are meaningful. Compilers routinely introduce variations in:
   * Timestamps and GNU Build IDs (`.note.gnu.build-id`).
   * String table metadata (`.strtab`).  
   Focusing strictly on executable machine code (`.text`) eliminates false positives and pinpoints the actual logic change in seconds.

---

## Reconnaissance & Disassembly Analysis

Inspecting binary characteristics:

```bash
$ file breadth.v1 breadth.v2
breadth.v1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped
breadth.v2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped
```

Checking embedded strings:
```bash
$ strings breadth.v1 | grep "picoCTF{" | wc -l
16384
```

There are **16,384 distinct flags** inside `.rodata`!

### Decompiling `main()`

```c
int main() {
    puts("Dead code? What's that?");
    puts("Goodbye!");
    return 0;
}
```

The `main` function performs no operations, references zero external variables, and calls zero functions. 

### Structure of the 16,384 Dummy Functions

Every single `fcn*` function follows an identical assembly pattern:

```asm
fcnXXXXX:
    mov  [rsp-0x10], CONST_A
    mov  rdx, [rsp-0x10]
    mov  rax, CONST_B
    cmp  rdx, rax
    jz   print_flag
    ret
print_flag:
    lea  rdi, [rip + disp32]     ; Points to a unique decoy "picoCTF{...}"
    jmp  puts
```

In almost all 16,384 functions, `CONST_A != CONST_B`, meaning the jump `jz` never executes.

---

## Exploitation Strategy: Differential Analysis

Instead of reversing 16,384 functions, we compare `breadth.v1` against `breadth.v2` using byte comparison:

```bash
$ cmp -l breadth.v1 breadth.v2 | wc -l
36
```

Only **36 bytes** differ across the entire 2.6 MB binary!

Breaking down the 36 differing bytes:
1. **20 bytes** at offset `0x2C4 .. 0x2E8`: Belongs to `.note.gnu.build-id` (compiler metadata noise).
2. **1 byte** at offset `0x253753`: String table symbol name change (`'1'` $\to$ `'2'`).
3. **15 bytes** at offset **`0x9504B .. 0x9505B`**: Located inside the executable **`.text` section**!

### Disassembly Comparison of the Patched Function

Locating offset `0x95040` (aligned to 16 bytes):

#### `breadth.v1` (Defective In-Development Build):
```asm
0x95040: mov  [rsp-0x10], 0x41BC73E
0x95049: mov  rdx, [rsp-0x10]
0x9504e: mov  eax, 0xD037803A
0x95053: cmp  rdx, rax             ; 0x41BC73E != 0xD037803A -> NEVER JUMPS!
0x95056: jz   0x95060
0x95058: ret
0x95060: lea  rdi, "picoCTF{...}"
0x95067: jmp  puts
```

#### `breadth.v2` (Patched Production Build):
```asm
0x95040: mov  [rsp-0x10], 0x41BC73E
0x95049: mov  rax, [rsp-0x10]
0x9504e: cmp  rax, 0x41BC73E        ; EQUAL! Condition passes!
0x95054: jz   0x95060
0x95056: ret
0x95060: lea  rdi, "picoCTF{redacted}"
0x95067: jmp  puts
```

The function at `0x95040` (`fcnkKTQpF`) is the **only function in the binary** where the developer fixed the logic so that `jz` evaluates to true!

---

## Exploit Script

```python
#!/usr/bin/env python3
# Breadth Differential Solver — Python 3
import sys, os, struct, re

def solve():
    v1 = open("breadth.v1", "rb").read()
    v2 = open("breadth.v2", "rb").read()

    # Find differences restricted to .text section
    code_diffs = [i for i in range(len(v1)) if v1[i] != v2[i] and 0x1000 <= i <= 0xC11E5]
    patch_offset = min(code_diffs)
    
    # Align down to 16-byte function boundary
    func_start = patch_offset & ~0xF
    func_bytes = v1[func_start : func_start + 0x80]

    # Decode RIP-relative displacement: 48 8d 3d <disp32>
    match = re.search(rb"\x48\x8d\x3d(....)", func_bytes, re.DOTALL)
    disp32 = struct.unpack("<i", match.group(1))[0]
    next_ip = func_start + match.end()
    flag_va = next_ip + disp32

    flag = re.search(rb"picoCTF\{[^}]+\}", v1[flag_va : flag_va + 64]).group(0)
    print("[+] Legitimate Flag:", flag.decode())

if __name__ == "__main__":
    solve()
```

*(See [`exploit.py`](exploit.py) for the complete script).*

### Execution Output

```text
$ python3 exploit.py breadth.v1 breadth.v2
[*] Breadth (Binary Diffing Solver)
[*] Loading binaries: 'breadth.v1' and 'breadth.v2'...
[*] Total byte discrepancies detected: 36
[+] Identified critical patch at offset 0x09504B
[+] Containing target function start: 0x095040

[+] Successfully Extracted Legitimate Flag:
    picoCTF{redacted}
```

---

## Flag & Key Takeaways

```text
picoCTF{redacted}
```
*(Flag redacted in accordance with competition disclosure guidelines)*

1. **Volume Does Not Equal Complexity:** Obfuscation that relies on bloating binaries with thousands of duplicate dead functions collapses instantly when confronted with differential binary analysis.
2. **Filtering Metadata in Binary Diffing:** Always delineate section boundaries (e.g., `.text` vs `.rodata` vs metadata sections) to avoid wasting time analyzing irrelevant linker/build hashes.
3. **x86-64 RIP-Relative Addressing:** In 64-bit ELF binaries, string references frequently use `lea rdi, [rip + disp32]`. Calculating `target = next_instruction_address + disp32` allows direct programmatic string recovery.
