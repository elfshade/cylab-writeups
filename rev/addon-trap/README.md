# CyLab / picoCTF — The Add/On Trap

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Add-on Reversing & XOR Decryption)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Disassembling browser add-on binary component, identifying XOR key schedule. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file addon-trap
addon-trap: ELF/Artifact analysis
$ checksec addon-trap
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `.xpi` = zip ⇒ `unzip -P academy`. Nội dung: `manifest.json`, `popup.html`, `assets/script.js`,
  **`background/main.js`** (thú vị nhất), `assets/styles.css`, icons, chữ ký.
- `background/main.js`:
```js
// Secret key must be 32 url-safe base64-encoded bytes!
const key="YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=";
const webhookUrl='gAAAAABqUwkJWn6EVtro8ovh-MzUjpxg4dolaPtGOvfvZJDoDpYXWCaV0TWf4VBBiBh2l0ega8nyZMoUrIoK38IDB2GnRtbkktQmBLlxKFPe_ZWThc72G6pwmUo5Gk8ZLGSWe_NVfyS4';
browser.webNavigation.onCompleted.addListener(logOnCompleted);
```
  ⇒ Add-on gửi URL người dùng truy cập tới một **webhook Fernet-encrypted**.

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of The Add/On Trap reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

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

1. Giải nén `.xpi` (zip, password `academy`); đọc `background/main.js`.
2. `key` base64 decode → **`academy{you're on the right tra}`** = **DECOY** (đúng chủ đề "The Add/On Trap":
   "right tra" chứ không phải "track"). Nhưng nó là **Fernet key hợp lệ** (32 byte).
3. `webhookUrl` là **Fernet token** (`gAAAAA...`) ⇒ decrypt bằng key trên:
```python
Fernet(key).decrypt(webhookUrl) -> b'academy{Us3_4dd/0ns_v3ry_c4r3fully1}'
```

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# The Add/On Trap (CyLab RE diff2, id 697) -- file-only: suspicious.zip (password: academy)
# Inside: a Firefox .xpi (also a zip). background/main.js holds:
#   key  = base64("academy{you're on the right tra}")   <-- DECOY (32-byte Fernet key)
#   webhookUrl = Fernet token (gAAAAA...)               <-- real flag encrypted
# Decrypt the Fernet token with that key.
import base64, subprocess, sys, os

ZIP = "/home/thang/cylab-re/dl/697-suspicious.zip"
D = "/home/thang/cylab-re/697/extract"


def extract():
    os.makedirs(D, exist_ok=True)
    subprocess.run(["unzip", "-o", "-P", "academy", ZIP, "-d", D], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    xpi = next(f for f in os.listdir(D) if f.endswith(".xpi"))
    subprocess.run(["unzip", "-o", "-P", "academy", os.path.join(D, xpi), "-d", os.path.join(D, "xpi")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return open(os.path.join(D, "xpi", "background", "main.js")).read()


def main():
    js = extract()
    import re
    key = re.search(r'key\s*=\s*"([^"]+)"', js).group(1)
    tok = re.search(r'webhookUrl\s*=\s*[\'"]([^\'"]+)[\'"]', js).group(1)
    print("[+] decoy key decodes to:", base64.b64decode(key).decode())
    from cryptography.fernet import Fernet
    flag = Fernet(key.encode()).decrypt(tok.encode()).decode()
    print("[+] FLAG:", flag)


if __name__ == "__main__":
    main()
```

---

## Flag

```text
academy{redacted}
```

---

## Key Takeaways & Lessons

- **`.xpi` = zip** (có thể đặt password) ⇒ `unzip -P`; add-on Firefox chứa `background/*.js` là nơi giấu
  logic/secret.
- **Fernet** = khuôn dạng token `gAAAAA...` + key url-safe base64 32 byte. Hint "url-safe Base64 32-byte key"
  là dấu hiệu nhận diện Fernet ngay; `cryptography.fernet.Fernet(key).decrypt(token)`.
- **Decoy flag**: một chuỗi base64 nhìn giống flag (`academy{...}`) nhưng chính là khoá ⇒ đừng nộp ngay;
  dùng nó để mở tầng mã hoá thật. (Tên bài "Trap" mách bảo điều này.)
- Manifest V2 `webNavigation` + `fetch` webhook = mẫu exfiltration; đọc `background` thay vì chỉ `popup`.
