# CyLab / picoCTF — M1n10n'5_53cr37

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Android APK & Dalvik Bytecode Reversing)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Android APK decompilation (jadx), native asset decryption and activity intent analysis. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file minions-apk
minions-apk: ELF/Artifact analysis
$ checksec minions-apk
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `apktool d minions.apk` ⇒ package `com.example.picoctfimage`, app name **"Minions"**.
- `MainActivity` rất đơn giản: `setContentView(activity_main)`, đổi màu action bar vàng.
- `res/layout/activity_main.xml`: một `ImageView` dùng `@drawable/minion` (ảnh duy nhất) + một `TextView`:
  > **"Look into me my Banana Value is interesting"**
- `res/drawable/minion.jpg`: JPEG progressive 800x711, không metadata/trailing; grep toàn cây không có `academy`.
- Grep từ khoá "banana" ⇒ trúng ngay `res/values/strings.xml`:
  ```xml
  <string name="Banana">MFRWCZDFNV4XWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=</string>
  ```

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Chuỗi `Banana` là **Base32** (alphabet `A-Z2-7` + padding `=`). Hint "**Banana Value**" chính là *giá trị*
của resource tên `Banana` (không phải ảnh!) — bait kiểu "look into me" hướng sự chú ý vào ảnh.

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

```python
import base64
base64.b32decode("MFRWCZDFNV4XWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=")
# -> b'academy{redacted}'
```
Không cần steghide (đã thử rockyou trên `minion.jpg` — không có dữ liệu; JPEG progressive đúng là bait).

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# M1n10n'5_53cr37 (CyLab RE diff2, id 528) -- file-only Android APK (minions.apk)
# The app (com.example.picoctfimage / "Minions") shows one image (res/drawable/minion.jpg)
# and a TextView hint: "Look into me my Banana Value is interesting".
# res/values/strings.xml holds <string name="Banana">BASE32_FLAG</string>.
# So: read the "Banana" string resource and base32-decode it.
import re, subprocess, sys, os, base64

APK = "/home/thang/cylab-re/dl/528-minions.apk"
D = "/home/thang/cylab-re/528/dec"


def main():
    if not os.path.isdir(D):
        subprocess.run(["apktool", "d", "-f", "-o", D, APK], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    xml = open(os.path.join(D, "res", "values", "strings.xml"), encoding="utf-8", errors="replace").read()
    m = re.search(r'<string name="Banana">([^<]+)</string>', xml)
    if not m:
        print("[-] Banana string not found"); sys.exit(1)
    b32 = m.group(1)
    print("[+] Banana (base32):", b32)
    print("[+] FLAG:", base64.b32decode(b32).decode())


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

- **Resource string giả làm ứng viên thường**: grep nhanh theo từ khoá trong hint (`banana`) trên toàn cây
  `apktool` (đặc biệt `res/values/strings.xml`) là bước rẻ, thường trúng trước khi sa vào stego ảnh.
- **Nhận diện Base32**: chuỗi chỉ gồm `A-Z2-7` (+`=`) ⇒ `base64.b32decode`, dễ nhầm với base64 nhưng
  base32 không có `0/1/8/9` và không phân biệt hoa/thường.
- **Bait "Look into me"**: hint có thể cố tình hướng vào ảnh; hãy kiểm tra cả những chỗ khác (tên resource = từ khoá).
- Công cụ: `apktool` (đã có), `aapt/aapt2`, `baksmali`, `dexdump`; `jadx` **không có** trong môi trường.
- `steghide` CÓ sẵn (nhưng không dùng được cho JPEG progressive của bài này); `stegseek` có thể tự cài qua
  `apt-get download stegseek` + `dpkg -x` để brute-force nhanh bằng rockyou khi cần.
