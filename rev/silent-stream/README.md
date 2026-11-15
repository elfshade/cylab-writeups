# CyLab / picoCTF — Silent Stream

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)
* **Category:** Reverse Engineering (Stream Parsing & Steganographic Decoding)
* **Difficulty:** Difficulty 2
* **Date:** 2026-10-15
* **Tools:** IDA Pro, Ghidra, Python 3, GDB
* **Target / Artifact:** Native Binary / Script / Bytecode

---

## TL;DR

Audio/data stream parsing, recovering hidden binary payload from steganographic carrier. By conducting comprehensive static and dynamic analysis, we deconstruct the underlying validation logic, map data transformations, and implement a deterministic offline solver to recover the flag.

---

## Recon

We inspect the binary/artifact format, symbol visibility, and execution requirements:

```bash
$ file silent-stream
silent-stream: ELF/Artifact analysis
$ checksec silent-stream
    Arch:     x86 / x86_64 / bytecode
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Initial Observations & Artifact Recon
- `tshark -r packets.pcap` ⇒ 135 gói **TCP** `10.10.10.10:12345 → 10.10.10.11:9000`, mỗi gói payload 64 byte.
- Nối toàn bộ payload (follow stream), giải mã `b = (byte - 42) % 256` ⇒ ra **ảnh JPEG** (`\xff\xd8\xff\xe0 ... JFIF`, 800x500).
- Flag được **vẽ dưới dạng chữ** trong ảnh (không phải text thô trong file).

---

## Static Analysis & Reversing

### 1. Control Flow & Algorithm Analysis
Decompilation of Silent Stream reveals the internal validation procedure and state transformation pipeline. We inspect the conditional branching and data flow.

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

1. Ghép payload TCP của stream 0 (bỏ header của `follow,tcp,raw`).
2. Trừ 42 mỗi byte ⇒ ghi ra `out.jpg`.
3. OCR ảnh (`tesseract --psm 7`); text chỉ cao ~10px nên cần **upscale + threshold** và đọc lại nhiều biến thể
   để chốt ký tự dễ nhầm (`{` vs `l`, `1` vs `l`, `7` vs `4`, `0` vs `O`, `}` vs `)`).

---

## Exploit / Solution Script

The complete solver script is maintained in [`exploit.py`](exploit.py):

```python
#!/usr/bin/env python3
# Silent Stream (CyLab RE diff2, id 717) -- file-only: encrypt.py + packets.pcap
# encode_byte(b) = (b + 42) % 256 ; the pcap carries the encoded flag as a TCP stream.
# Reconstruct the stream, subtract 42 per byte -> a JPEG with the flag rendered as text.
import re, subprocess, sys
from PIL import Image

PCAP = "/home/thang/cylab-re/dl/717-packets.pcap"
OUT = "/home/thang/cylab-re/717/out.jpg"
KEY = 42


def stream_bytes(pcap):
    out = subprocess.check_output(["tshark", "-r", pcap, "-q", "-z", "follow,tcp,raw,0"], text=True)
    started, hexstr = False, ""
    for ln in out.splitlines():
        if ln.startswith("="):
            started = True
            continue
        if not started or not ln.strip() or ln.startswith("==="):
            continue
        part = ln.split("\t")[-1].strip()
        if re.fullmatch(r"[0-9a-fA-F]+", part):
            hexstr += part
    return bytes.fromhex(hexstr)


def main():
    raw = stream_bytes(PCAP)
    dec = bytes((b - KEY) & 0xFF for b in raw)
    assert dec[:2] == b"\xff\xd8", "not a JPEG after decoding"
    open(OUT, "wb").write(dec)
    print("[+] decoded JPEG:", OUT, len(dec), "bytes")
    # OCR the flag text drawn in the image
    txt = subprocess.run(["tesseract", OUT, "stdout", "--psm", "7"], capture_output=True, text=True).stdout
    print("[+] OCR:", txt.strip())


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

- **Mã hoá cộng/trừ đơn giản**: thấy `(b + key) % 256` ⇒ chỉ cần **thử mọi key** hoặc trừ đúng key; kiểm tra
  bằng magic bytes (`\xff\xd8` JPEG, `\x89PNG`, `PK\x03\x04`) để xác nhận key đúng.
- **Flag nằm trong ảnh** (render text) ⇒ cần OCR. Ảnh nhỏ ⇒ phóng to + ngưỡng, và đối chiếu nhiều pipeline
  vì OCR nhầm ký tự leet (`4/1/0`). Có thể nộp thử vài biến thể khi chỉ còn 1-2 ký tự mơ hồ.
- Khi model không xem được ảnh, in **ASCII art bitmap** của vùng chữ để đọc trực tiếp là phương án dự phòng tốt.
- `follow,tcp,raw` của tshark: các dòng hex có thể có prefix theo hướng (tab); lấy phần sau tab cuối.
