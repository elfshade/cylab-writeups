# Pico Bank — Android Reverse Engineering & Dalvik Register Reuse Emulation

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/) (picoMini by CMU-Africa)  
**Category:** Mobile Reverse Engineering (Android APK & Logic Steganography)  
**Difficulty:** Medium (CyLab Difficulty 2)  
**Tools:** `apktool`, Python 3, `urllib`  
**Artifact:** Android Package (`pico-bank.apk`)  

---

## TL;DR

The challenge presents an Android banking application (`pico-bank.apk`). The flag is divided into two separate halves requiring distinct reversing vectors:
1. **Part 1 (Static APK Steganography):** Hidden in the transaction history defined inside `MainActivity.smali`. The monetary amounts for transactions are encoded as 7-bit ASCII binary strings (`$ 1110000` = `'p'`). Importantly, compiler optimizations reuse virtual registers across transaction constructor calls, making simple regex extraction fail unless full Dalvik register assignments are sequentially emulated.
2. **Part 2 (Dynamic API Verification):** A hardcoded OTP value (`9673`) extracted from `res/values/strings.xml` is submitted to the remote endpoint `POST /verify-otp` to receive the second half of the flag.

---

## Student's Learning Note: Core Concepts

As a 2nd-year CS student interested in mobile application security, this challenge highlighted key aspects of the Android/Dalvik execution environment:

1. **Dalvik Bytecode & Register Architecture:** Unlike x86 stack-based or general-purpose hardware register models, the Dalvik Virtual Machine (DVM/ART) uses a frame-based virtual register architecture (`v0`, `v1`, ...). Variables and intermediate constants live in these virtual registers.
2. **Register Allocation & Liveness Optimization:** Compilers minimize register allocations by reusing dormant registers. If a register is set once and passed to multiple constructor calls across several basic blocks, a static parser must simulate register state rather than assuming each invocation contains its own literal declaration.
3. **Android Client-Side Trust Assumptions:** Developers often mistakenly trust client-side validation (such as hardcoding valid usernames/passwords in `Login$1.smali` or storing sensitive keys in XML resource bundles).

---

## Static Analysis & Decompilation

Decompiling the APK using `apktool`:

```bash
$ apktool d -f -o dec pico-bank.apk
I: Using Apktool 2.9.x on pico-bank.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Baksmaling classes.dex...
```

### 1. Client-Side Authentication Bypass
Inspecting `smali/com/example/picobank/Login$1.smali`:
```smali
const-string v0, "johnson"
const-string v1, "tricky1990"
```
The login mechanism is completely local. Credentials match user profile hints provided in the challenge prompt (`Alex Johnson`, pet `tricky`, born `1990`). No network requests are made during login.

### 2. Hardcoded OTP in Resources
Searching `res/values/strings.xml`:
```xml
<string name="otp_value">9673</string>
```
The OTP verification activity checks input against this static XML entry.

---

## Vulnerability & Recovery Strategy

### The Register Reuse Trap in `MainActivity.smali`

Inspecting `MainActivity.smali`, the app populates a `RecyclerView` with `Transaction` objects via:
`new Transaction(title, category, date, amount)`

In Dalvik assembly:
```smali
const-string v9, "$ 1110000"         ; Binary for 'p' (0x70)
...
invoke-direct {v5, v6, v7, v8, v9}, Lcom/example/picobank/Transaction;-><init>...
```

However, later in the method:
```smali
; "Water Bill" transaction creation:
; Notice that register v9 is NOT reassigned! It reuses the previously stored amount!
invoke-direct {v5, v11, v12, v10, v9}, Lcom/example/picobank/Transaction;-><init>...
```

**The Trap:** Running a naive regex search for `const-string vN, "\$ [01]+"` extracts only uniquely assigned strings, producing missing letters and corrupted words.

**The Solution:** Build a Python emulator that models Dalvik virtual registers sequentially:
* When `const-string vX, "..."` is seen $\to$ Update `reg_map[vX] = string`.
* When `invoke-direct {..., vAmount}, Transaction;-><init>` is seen $\to$ Read `reg_map[vAmount]`.
* Decode each 7-bit binary string into its corresponding ASCII character.

---

## Exploit Script

Below is the automated solver (see [`exploit.py`](exploit.py)):

```python
#!/usr/bin/env python3
# Pico Bank Solver — Python 3
import os, re, json, urllib.request

def recover_part1(smali_path):
    with open(smali_path, "r", encoding="utf-8") as f:
        src = f.read()

    registers = {}
    decoded = []
    
    re_const = re.compile(r'const-string (v\d+), "(.*?)"')
    re_invoke = re.compile(r'invoke-direct \{([^}]+)\},\s*Lcom/example/picobank/Transaction;-><init>')

    for line in src.splitlines():
        m_const = re_const.search(line)
        if m_const:
            registers[m_const.group(1)] = m_const.group(2)
            continue

        m_invoke = re_invoke.search(line)
        if m_invoke:
            args = [a.strip() for a in m_invoke.group(1).split(",")]
            amt = registers.get(args[3], "")
            if amt.startswith("$ "):
                b = amt[2:]
                decoded.append(chr(int(b, 2)))
                
    return "".join(decoded)

def main():
    part1_full = recover_part1("./dec/smali_classes3/com/example/picobank/MainActivity.smali")
    part1 = part1_full.split("{", 1)[1] if "{" in part1_full else part1_full
    print("[+] Part 1 (APK):", part1)

    # Submit OTP to obtain Part 2
    req = urllib.request.Request(
        "http://xebec.cylabacademy.net:39382/verify-otp",
        data=json.dumps({"otp": "9673"}).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        part2 = data["flag"]
        print("[+] Part 2 (API):", part2)
        print(f"[+] Full Flag: academy{{{part1}{part2}")

if __name__ == "__main__":
    main()
```

### Execution Output

```text
$ python3 exploit.py ./dec
[*] Emulating Dalvik register reuse in: ./dec/smali_classes3/com/example/picobank/MainActivity.smali
[+] Extracted sequence: picoCTF{1_l13d_4b0ut_b31ng_
[+] Extracted Hardcoded OTP: 9673
[*] Submitting OTP to challenge service: http://xebec.cylabacademy.net:39382/verify-otp...
[+] Full Flag Assembled: academy{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_13fbb223}
```

---

## Flag & Key Takeaways

```text
academy{REDACTED}
```

1. **Understand Compiler Optimizations in Bytecode:** In Dalvik/Smali reversing, literal strings are not necessarily declared adjacent to their consumer instructions. Tracking register state transitions ensures fidelity.
2. **Never Rely on Client-Side Security in Mobile Apps:** Sensitive data like OTPs, secret strings, or user credentials must never be hardcoded into APK bytecode or XML resources.
3. **Data Encoding in UI Layers:** Application UI elements (like financial amounts, timestamps, or coordinates) can frequently be leveraged for steganographic concealment.
