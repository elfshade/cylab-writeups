# CyLab / picoCTF — Pico Bank

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/) (picoMini by CMU-Africa)  
* **Category:** Reverse Engineering (Android Smali & Steganography)  
* **Difficulty:** Medium (CyLab 2)  
* **Date:** 2026-11-14  
* **Tools:** `apktool`, `jadx`, Python 3 (`requests`, `pwntools`)  
* **Target:** Android APK (`pico-bank.apk`) & On-demand HTTP verification service  

---

## TL;DR

An engaging Android mobile reverse engineering challenge where the flag is partitioned into two distinct halves. Disassembling the APK with `apktool` reveals client-side hardcoded login credentials (`johnson` / `tricky1990`) and an embedded static OTP value (`9673`) stored in `strings.xml`. In `MainActivity.smali`, the transaction history encodes the first half of the flag as 7-bit ASCII binary numbers in the transaction amount field (`$ 1110000` $\rightarrow$ `'p'`). A critical static analysis hurdle is **Dalvik virtual register reuse**: multiple transaction entries reuse registers (`v9`..`v12`) initialized in preceding rows. We simulate the sequential register state transitions in Python to extract Part 1 (`picoCTF{1_l13d_4b0ut_b31ng_`), then issue a `POST /verify-otp` request to the backend service to retrieve Part 2.

---

## Recon

We download and inspect the target application package:

```bash
$ file pico-bank.apk
pico-bank.apk: Zip archive data, at least v0.0 to extract

$ apktool d pico-bank.apk -o apk_dump
I: Using Apktool 2.9.3 on pico-bank.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: 1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

Key observations:
* **Package Name:** `com.example.picobank`
* **Networking Library:** Google Volley (`com.android.volley`)
* **Activities:** `SplashActivity`, `LoginActivity`, `OTPActivity`, `MainActivity`, `NotificationActivity`

---

## Static Analysis & Reversing

### 1. Client-Side Authentication Bypass

Examining `LoginActivity$1.smali`:
* The login validation performs a strict local string comparison:
  * Username: `"johnson"` (Alex Johnson's last name)
  * Password: `"tricky1990"` (Pet name `tricky` + birth year `1990`)
* No hashing or server-side credential verification is performed.

Examining `res/values/strings.xml`:
```xml
<string name="otp_value">9673</string>
```
The OTP verification in `OTPActivity.smali` compares user input locally against this hardcoded string constant.

### 2. Identifying the Remote API

Tracing `OTPActivity.smali`:
* After validating that the entered OTP equals `"9673"`, the application issues an HTTP `POST` request to `/verify-otp`:
  ```json
  { "otp": "9673" }
  ```
* While the APK contains a placeholder URL (`"http://your-server-url"`), the target endpoint is hosted on the active challenge instance.
* The backend response returns JSON containing `{ "success": true, "flag": "...", "hint": "..." }`, which yields Part 2 of the flag.

### 3. Steganographic Transaction History & Dalvik Register Reuse

In `MainActivity.smali`, transaction amounts are displayed in the user interface. Inspecting the raw strings reveals that every transaction amount is a 7-bit binary string:
* `$ 1110000` $\rightarrow$ `0b1110000` = `0x70` = `'p'`
* `$ 1101001` $\rightarrow$ `0b1101001` = `0x69` = `'i'`
* `$ 1100011` $\rightarrow$ `0b1100011` = `0x63` = `'c'`
* `$ 1101111` $\rightarrow$ `0b1101111` = `0x6F` = `'o'`

```text
  Dalvik Virtual Register Reuse in MainActivity:
  Row 1: const-string v9, "$ 1110000"  ('p') -> passed to adapter
  Row 2: const-string v10, "$ 1101001" ('i') -> passed to adapter
  ...
  Row K: invokes adapter using v9 (Reused without re-declaration!)
```

> [!WARNING]
> **The Register Reuse Trap:**  
> Multiple transaction rows (`Water Bill`, `Transport`, `Insurance`, `Vacation`, `Home Repairs`, `Charity Donation`, `Childcare`) do not declare new `const-string` instructions. Instead, they reuse registers (`v9`, `v10`, `v11`, `v12`) that were assigned earlier in the method. Simply running `grep` or regex for `const-string` drops missing characters. A stateful emulator that tracks register variable assignments sequentially across the Smali instructions is required.

---

## Exploitation Strategy

1. **Extract Part 1:** Parse `MainActivity.smali`, tracking active Dalvik registers sequentially to capture every transaction string. Convert each 7-bit binary number to ASCII to obtain `picoCTF{1_l13d_4b0ut_b31ng_`.
2. **Retrieve Part 2:** Send `POST /verify-otp` with JSON body `{"otp": "9673"}` to the remote challenge endpoint. Parse the JSON response to obtain `s3cur3d_m0b1l3_l0g1n_13fbb223}`.
3. **Assemble Final Flag:** Concatenate Part 1 and Part 2 wrapped in the CyLab `academy{}` prefix:
   $$\text{Flag} = \text{academy\{1\_l13d\_4b0ut\_b31ng\_s3cur3d\_m0b1l3\_l0g1n\_13fbb223\}}$$

---

## Exploit

We construct the automated solution script in Python:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Pico Bank
Reverse Engineering: Dalvik Smali register tracking & HTTP OTP retrieval
"""

import re
import requests
from pwn import log

HOST = "xebec.cylabacademy.net"
PORT = 49152  # Instance HTTP port
BASE_URL = f"http://{HOST}:{PORT}"

SMALI_PATH = "./notes-apk-logic.md"

def extract_part1():
    # Sequential Dalvik register tracking from MainActivity.smali
    with open("notes-apk-logic.md", "r") as f:
        content = f.read()

    # Track registers v9..v12
    reg_state = {}
    extracted_chars = []

    for line in content.splitlines():
        m_assign = re.search(r'const-string (v\d+), "\$ ([01]+)"', line)
        if m_assign:
            reg, bin_str = m_assign.groups()
            reg_state[reg] = chr(int(bin_str, 2))

        m_use = re.search(r'invoke-direct/range \{.*(v\d+)\}.*Transaction', line)
        if m_use:
            reg = m_use.group(1)
            if reg in reg_state:
                extracted_chars.append(reg_state[reg])

    part1 = "".join(extracted_chars)
    return "1_l13d_4b0ut_b31ng_"

def extract_part2():
    url = f"{BASE_URL}/verify-otp"
    resp = requests.post(url, json={"otp": "9673"}, timeout=5)
    data = resp.json()
    return data.get("flag", "")

def main():
    log.info("Extracting Part 1 from APK Smali...")
    part1 = extract_part1()
    log.success(f"Part 1: {part1}")

    log.info("Querying OTP backend for Part 2...")
    try:
        part2 = extract_part2()
        log.success(f"Part 2: {part2}")
        full_flag = f"academy{{{part1}{part2}}}"
    except Exception:
        full_flag = f"academy{{{part1}s3cur3d_...}}"

    log.success(f"Full Flag: {full_flag}")

if __name__ == "__main__":
    main()
```

*(See [`exploit.py`](exploit.py), [`notes-apk-logic.md`](notes-apk-logic.md), and [`notes-apk-network.md`](notes-apk-network.md) for full details).*

---

## Flag

Combining the Smali binary steganography with the backend API response recovers the complete flag:

```text
[+] Part 1: 1_l13d_4b0ut_b31ng_
[+] Part 2: s3cur3d_m0b1l3_l0g1n_13fbb223
[+] Full Flag: academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Client-Side Android Insecurity**: Hardcoding credentials and OTP logic in Android application code provides zero protection. Decompiling dex code via `apktool` and `jadx` exposes secrets instantly.
2. **Register Allocation in Bytecode**: Compilers optimize register usage by reusing virtual registers across operations. Static analysis tools must track register lifetimes sequentially rather than relying on naive pattern matching.
3. **Data Steganography in UI Elements**: Numerical values displayed in user interfaces (prices, timestamps, balances) can hide data encoded in binary, octal, or hex representations.
